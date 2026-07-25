#!/bin/sh
# Build "SSTP VPN.app": the SwiftUI front end plus a Python runtime, the
# dependencies and the sstp package, so the recipient needs nothing installed.
#
# A bundle is also what gives the app a Dock and Launchpad icon; a bare
# executable gets neither.
set -eu

cd "$(dirname "$0")"

PYTHON_TAG=20260718
PYTHON_VERSION=3.12.13
PYTHON_ARCHIVE="cpython-$PYTHON_VERSION+$PYTHON_TAG-aarch64-apple-darwin-install_only_stripped.tar.gz"
PYTHON_URL="https://github.com/astral-sh/python-build-standalone/releases/download/$PYTHON_TAG/$PYTHON_ARCHIVE"

APP="${1:-build/SSTP VPN.app}"
RUNTIME=build/runtime
STAMP="$RUNTIME/.stamp"
WANTED="$PYTHON_TAG $(shasum ../requirements.txt | cut -d' ' -f1)"

# ------------------------------------------------------------------ runtime

# Downloading and pip-installing takes a minute, and neither changes between
# rebuilds of the Swift code, so the prepared runtime is kept around.
if [ "$(cat "$STAMP" 2>/dev/null || true)" != "$WANTED" ]; then
    echo "preparing the Python runtime..."
    mkdir -p build/cache
    [ -f "build/cache/$PYTHON_ARCHIVE" ] ||
        curl -fL --progress-bar -o "build/cache/$PYTHON_ARCHIVE" "$PYTHON_URL"

    rm -rf "$RUNTIME"
    mkdir -p "$RUNTIME"
    tar -xzf "build/cache/$PYTHON_ARCHIVE" -C "$RUNTIME" --strip-components=1

    "$RUNTIME/bin/python3" -m pip install --quiet --no-cache-dir \
        --disable-pip-version-check -r ../requirements.txt

    # None of this is reachable from the daemon, and it is over half the size.
    LIB="$RUNTIME/lib/python${PYTHON_VERSION%.*}"
    rm -rf "$LIB/test" "$LIB/idlelib" "$LIB/tkinter" "$LIB/lib2to3" \
           "$LIB/ensurepip" "$LIB/site-packages/pip" \
           "$LIB/site-packages/setuptools" "$LIB/site-packages/wheel" \
           "$RUNTIME/lib/tcl8"* "$RUNTIME/lib/tk8"* "$RUNTIME/share" \
           "$RUNTIME/include"
    find "$RUNTIME" -name '__pycache__' -type d -prune -exec rm -rf {} +
    find "$RUNTIME" -name '*.a' -delete

    echo "$WANTED" > "$STAMP"
fi

# --------------------------------------------------------------------- app

swift build -c release

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp .build/release/SSTPClient "$APP/Contents/MacOS/SSTP"

ditto "$RUNTIME" "$APP/Contents/Resources/python"
ditto ../sstp "$APP/Contents/Resources/sstp"
find "$APP/Contents/Resources/sstp" -name '__pycache__' -type d -prune -exec rm -rf {} +

# The GUI runs this to install the daemon, and it is also the way to reach the
# command line inside the bundle. $0 rather than a baked-in path, so the app
# keeps working wherever it is dragged.
cat > "$APP/Contents/Resources/sstp.sh" <<'LAUNCHER'
#!/bin/sh
set -eu
cd "$(dirname "$0")"
exec ./python/bin/python3 -m sstp "$@"
LAUNCHER
chmod +x "$APP/Contents/Resources/sstp.sh"

rm -rf build/SSTP.iconset
swiftc -O -o build/make-icon icon.swift
./build/make-icon build/SSTP.iconset
iconutil -c icns build/SSTP.iconset -o "$APP/Contents/Resources/SSTP.icns"

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>            <string>SSTP VPN</string>
    <key>CFBundleDisplayName</key>     <string>SSTP VPN</string>
    <key>CFBundleIdentifier</key>      <string>local.sstp.client</string>
    <key>CFBundleExecutable</key>      <string>SSTP</string>
    <key>CFBundleIconFile</key>        <string>SSTP</string>
    <key>CFBundlePackageType</key>     <string>APPL</string>
    <key>CFBundleShortVersionString</key> <string>0.1</string>
    <key>LSMinimumSystemVersion</key>  <string>14.0</string>
</dict>
</plist>
PLIST

codesign --force --sign - "$APP/Contents/MacOS/SSTP" >/dev/null 2>&1 ||
    echo "warning: ad-hoc signing failed; the app will still run" >&2

ZIP="build/SSTP-VPN.zip"
rm -f "$ZIP"
ditto -c -k --keepParent --sequesterRsrc "$APP" "$ZIP"

echo "built $APP ($(du -sh "$APP" | cut -f1))"
echo "shareable: $ZIP ($(du -h "$ZIP" | cut -f1))"
