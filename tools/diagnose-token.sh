#!/bin/bash
# Read-only smart card diagnostics for a machine where only "SSTP VPN.app"
# is installed: reader, middleware, PKCS#11 modules, bundled client.
#
# Needs nothing preinstalled — the Python inside the app bundle is used.
# Never logs in, so no PIN attempt is ever spent. Run as a normal user:
#
#   bash diagnose-token.sh > ~/Desktop/sstp-report.txt 2>&1

set -u

PROBE=$(mktemp -t sstp-probe)
trap 'rm -f "$PROBE"' EXIT

section() {
    printf '\n===== %s =====\n' "$1"
}

# macOS has no coreutils timeout; a stuck middleware must not hang the report.
limit() {
    local seconds=$1
    shift
    /usr/bin/perl -e 'alarm shift; exec @ARGV' "$seconds" "$@"
}

section "environment"
date
sw_vers
printf 'hardware arch: %s\n' "$(uname -m)"
sysctl -n machdep.cpu.brand_string 2>/dev/null
printf 'running under Rosetta: %s\n' "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo n/a)"

section "the app bundle"
APP=""
for candidate in \
    "/Applications/SSTP VPN.app" \
    "$HOME/Applications/SSTP VPN.app" \
    "$HOME/Downloads/SSTP VPN.app" \
    "$HOME/Desktop/SSTP VPN.app"
do
    [ -d "$candidate" ] && APP="$candidate" && break
done
if [ -z "$APP" ]; then
    printf 'not found in the usual places, searching...\n'
    APP=$(find /Applications "$HOME" -maxdepth 4 -name 'SSTP VPN.app' -type d 2>/dev/null | head -1)
fi

if [ -z "$APP" ]; then
    printf 'SSTP VPN.app NOT FOUND — is it in /Applications?\n'
else
    printf 'app: %s\n' "$APP"
    ls -ld "$APP"
    printf '\n$ bundle contents\n'
    ls -l "$APP/Contents/Resources" 2>&1
    printf '\n$ quarantine attributes (a quarantined bundle fails oddly)\n'
    xattr -l "$APP" 2>&1
    printf '\n$ architecture of the GUI binary\n'
    file "$APP/Contents/MacOS/SSTP" 2>&1
    printf '\n$ signature\n'
    codesign -dv "$APP" 2>&1 | head -5
fi

PY=""
LAUNCHER=""
if [ -n "$APP" ]; then
    [ -x "$APP/Contents/Resources/python/bin/python3" ] && PY="$APP/Contents/Resources/python/bin/python3"
    [ -x "$APP/Contents/Resources/sstp.sh" ] && LAUNCHER="$APP/Contents/Resources/sstp.sh"
fi
# Fall back to a system interpreter only if the bundle is broken; it will most
# likely lack PyKCS11, but its architecture is still worth reporting.
[ -z "$PY" ] && PY=$(command -v python3 || true)

printf '\npython: %s\n' "${PY:-NOT FOUND}"
if [ -n "$PY" ]; then
    printf '$ interpreter arch and version\n'
    limit 20 "$PY" -c 'import platform,sys; print(platform.machine(), sys.version.split()[0])' 2>&1
    printf '$ PyKCS11 availability\n'
    limit 20 "$PY" -c 'import PyKCS11; print("PyKCS11 ok:", PyKCS11.__file__)' 2>&1
    printf '$ file on the interpreter\n'
    file "$PY" 2>&1
fi

section "reader visible to macOS (PC/SC layer)"
printf '\n$ system_profiler SPSmartCardsDataType\n'
limit 60 system_profiler SPSmartCardsDataType 2>&1
printf '\n$ security list-smartcards\n'
limit 30 security list-smartcards 2>&1
printf '\n$ sc_auth identities\n'
limit 30 sc_auth identities 2>&1
printf '\n$ USB devices\n'
ioreg -p IOUSB -l -w 0 2>/dev/null | grep -i -e '"USB Product Name"' -e '"USB Vendor Name"' | sort -u
printf '\n$ USB smart card / CCID drivers loaded\n'
ls /usr/libexec/SmartCardServices/drivers 2>&1
ls "/usr/local/libexec/SmartCardServices/drivers" 2>/dev/null

section "middleware processes and services"
printf '\n$ running middleware processes\n'
pgrep -fl 'SACSrv|SACMonitor|SafeNet|jcTray|jcProxy|JaCarta|Aladdin|ifdok|pcscd' 2>/dev/null
printf '\n$ launchd jobs\n'
launchctl list 2>/dev/null | grep -i -e safenet -e jacarta -e aladdin -e pcsc -e ctk
printf '\n$ installed frameworks\n'
ls -d /Library/Frameworks/*.framework 2>/dev/null
printf '\n$ installed middleware apps\n'
ls -d /Applications/*.app 2>/dev/null | grep -i -e safenet -e jacarta -e etoken -e aladdin -e "единый"
printf '\n$ middleware receipts (what was actually installed)\n'
pkgutil --pkgs 2>/dev/null | grep -i -e safenet -e jacarta -e etoken -e aladdin -e rutoken

section "candidate PKCS#11 modules"
CANDIDATES=(
    /usr/local/lib/pkcs11/libeTPkcs11.dylib
    /usr/local/lib/pkcs11/libIDPrimePKCS11.dylib
    /usr/local/lib/pkcs11/libClassicClientPKCS11.dylib
    /Library/Frameworks/eToken.framework/Versions/Current/libeToken.dylib
    /Library/Frameworks/eToken.framework/Versions/A/libeToken.dylib
    /Library/Frameworks/jcPKCS11-2.framework/jcPKCS11-2
    /Library/Frameworks/jcPKCS11.framework/jcPKCS11
    /usr/local/lib/libjcPKCS11.dylib
    /usr/local/lib/librtpkcs11ecp.dylib
    /Library/Frameworks/rtpkcs11ecp.framework/rtpkcs11ecp
    /opt/homebrew/lib/pkcs11/opensc-pkcs11.so
    /usr/local/lib/pkcs11/opensc-pkcs11.so
)

printf '\n$ ls -l /usr/local/lib/pkcs11/\n'
ls -l /usr/local/lib/pkcs11/ 2>&1

printf '\n$ find for anything pkcs11-shaped\n'
FOUND=$(find /usr/local/lib /opt/homebrew/lib /Library/Frameworks -maxdepth 4 \
    \( -iname '*pkcs11*' -o -iname '*eToken*.dylib' \) -type f 2>/dev/null | sort)
printf '%s\n' "$FOUND"

MODULES=()
for path in "${CANDIDATES[@]}" $FOUND; do
    [ -e "$path" ] || continue
    for seen in ${MODULES[@]+"${MODULES[@]}"}; do
        [ "$seen" = "$path" ] && continue 2
    done
    MODULES+=("$path")
done

printf '\n$ architecture of each existing module\n'
for path in ${MODULES[@]+"${MODULES[@]}"}; do
    file "$path" 2>&1
done
[ ${#MODULES[@]} -eq 0 ] && printf 'NO PKCS#11 MODULE FOUND ON DISK — middleware is not installed\n'

cat >"$PROBE" <<'PYTHON'
"""Load one PKCS#11 module and report slots and certificates. No login."""
import sys

path = sys.argv[1]
try:
    import PyKCS11
except ImportError as exc:
    print(f"  cannot probe: {exc}")
    raise SystemExit(0)
try:
    from cryptography import x509
except ImportError:
    x509 = None

lib = PyKCS11.PyKCS11Lib()
try:
    lib.load(path)
except Exception as exc:
    print(f"  LOAD FAILED: {exc}")
    raise SystemExit(0)

try:
    info = lib.getInfo()
    print(f"  library: {info.manufacturerID.strip()} {info.libraryDescription.strip()}")
except Exception as exc:
    print(f"  getInfo failed: {exc}")

try:
    empty = lib.getSlotList(tokenPresent=False)
    present = lib.getSlotList(tokenPresent=True)
except Exception as exc:
    print(f"  getSlotList failed: {exc}")
    raise SystemExit(0)

print(f"  slots total={list(empty)} with_token={list(present)}")
if not present:
    print("  NO TOKEN PRESENT for this module")
    raise SystemExit(0)

for slot in present:
    try:
        token = lib.getTokenInfo(slot)
    except Exception as exc:
        print(f"  slot {slot}: getTokenInfo failed: {exc}")
        continue
    flags = token.flags
    warnings = [
        name
        for name, bit in (
            ("USER_PIN_COUNT_LOW", PyKCS11.CKF_USER_PIN_COUNT_LOW),
            ("USER_PIN_FINAL_TRY", PyKCS11.CKF_USER_PIN_FINAL_TRY),
            ("USER_PIN_LOCKED", PyKCS11.CKF_USER_PIN_LOCKED),
        )
        if flags & bit
    ]
    print(
        f"  slot {slot}: label={token.label.strip()!r} "
        f"model={token.model.strip()!r} serial={token.serialNumber.strip()!r}"
    )
    if warnings:
        print(f"    PIN FLAGS: {', '.join(warnings)}")

    try:
        session = lib.openSession(slot, PyKCS11.CKF_SERIAL_SESSION)
    except Exception as exc:
        print(f"    openSession failed: {exc}")
        continue
    try:
        handles = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
        print(f"    certificates: {len(handles)}")
        for handle in handles:
            try:
                value, label = session.getAttributeValue(
                    handle, [PyKCS11.CKA_VALUE, PyKCS11.CKA_LABEL]
                )
                if x509 is None:
                    print(f"      {label} | {len(bytes(value))} bytes (no x509 parser)")
                    continue
                cert = x509.load_der_x509_certificate(bytes(value))
                print(f"      {label} | {cert.subject.rfc4514_string()}")
                print(f"        valid until {cert.not_valid_after_utc:%Y-%m-%d}")
            except Exception as exc:
                print(f"      unreadable certificate: {exc}")
        keys = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])
        print(f"    private keys visible without login: {len(keys)}")
    except Exception as exc:
        print(f"    enumeration failed: {exc}")
    finally:
        try:
            session.closeSession()
        except Exception:
            pass
PYTHON

section "probing each module (no login, 25s limit each)"
if [ -z "$PY" ]; then
    printf 'no interpreter available, skipping\n'
elif [ ${#MODULES[@]} -eq 0 ]; then
    printf 'no modules to probe\n'
else
    for path in "${MODULES[@]}"; do
        printf '\n--- %s\n' "$path"
        limit 25 "$PY" "$PROBE" "$path"
        status=$?
        [ $status -ne 0 ] && printf '  PROBE CRASHED OR TIMED OUT (exit %d)\n' $status
    done
fi

section "the client itself"
if [ -z "$LAUNCHER" ]; then
    printf 'the bundled launcher sstp.sh was not found, skipping\n'
else
    printf '\n$ sstp modules\n'
    limit 30 "$LAUNCHER" modules 2>&1
    printf '\n$ sstp list --all -v\n'
    limit 90 "$LAUNCHER" list --all -v 2>&1
fi

section "daemon state"
printf '\n$ installed daemon\n'
ls -l /Library/LaunchDaemons/local.sstp.daemon.plist /var/run/sstp.sock /var/log/sstp.log 2>&1
printf '\n$ daemon registered with launchd\n'
launchctl print system/local.sstp.daemon 2>&1 | head -20
printf '\n$ tail of /var/log/sstp.log\n'
tail -n 60 /var/log/sstp.log 2>&1

printf '\n===== end of report =====\n'
