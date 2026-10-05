#!/bin/sh
# Переносит SSTP VPN.app в /Программы, снимает карантин и собирает
# диагностику в отчёт на рабочем столе.
# Запуск:  sh установить-и-проверить.sh
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/SSTP VPN.app"
APP="/Applications/SSTP VPN.app"
LOG="$HOME/Desktop/sstp-диагностика.txt"

if [ ! -d "$SRC" ]; then
    echo "Рядом со скриптом нет 'SSTP VPN.app' — распакуйте архив целиком." >&2
    exit 1
fi

echo "Переношу приложение в Программы..."
rm -rf "$APP"
ditto "$SRC" "$APP"

echo "Снимаю карантин..."
xattr -cr "$APP" 2>/dev/null

{
    echo "=== Дата ==="
    date

    echo; echo "=== 1. Система ==="
    sw_vers
    uname -m

    echo; echo "=== 2. Содержимое MacOS/ ==="
    ls -la "$APP/Contents/MacOS/"

    echo; echo "=== 3. Архитектура бинарника ==="
    file "$APP/Contents/MacOS/SSTP"

    echo; echo "=== 4. Расширенные атрибуты ==="
    xattr -l "$APP" 2>&1
    echo "(пусто — значит карантин снят)"

    echo; echo "=== 5. Gatekeeper ==="
    spctl --assess --type execute -vv "$APP" 2>&1

    echo; echo "=== 6. Подпись ==="
    codesign --verify --deep -vv "$APP" 2>&1

    echo; echo "=== 7. Прямой запуск бинарника ==="
} > "$LOG" 2>&1

echo "Пробую запустить приложение (если откроется окно — всё работает, просто закройте его)..."
"$APP/Contents/MacOS/SSTP" >> "$LOG" 2>&1 &
PID=$!
sleep 10
if kill -0 "$PID" 2>/dev/null; then
    echo "процесс жив через 10 секунд — запуск успешен" >> "$LOG"
    kill "$PID" 2>/dev/null
else
    wait "$PID"
    RC=$?
    echo "процесс завершился с кодом $RC" >> "$LOG"
    echo; echo "=== 8. Свежие креш-репорты ===" >> "$LOG"
    for f in $(ls -t "$HOME/Library/Logs/DiagnosticReports" 2>/dev/null | grep -i sstp | head -2); do
        echo "--- $f ---" >> "$LOG"
        head -60 "$HOME/Library/Logs/DiagnosticReports/$f" >> "$LOG" 2>&1
    done
fi

echo
echo "Готово. Отчёт: $LOG"
echo "Отправьте этот файл обратно."
