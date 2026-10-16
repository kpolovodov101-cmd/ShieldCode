#!/bin/sh
set -eu
cd "$(dirname "$0")"
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 не найден. Установи Python 3.10+ и запусти скрипт ещё раз."
  exit 1
fi
# Keep existing accounts and scan history when installing this version beside an older one.
if [ -z "${SHIELDCODE_DATA_DIR:-${CODESHIELD_DATA_DIR:-}}" ] && [ ! -f "$PWD/data/codeshield.sqlite3" ]; then
  PARENT_DIR="$(dirname "$PWD")"
  GRANDPARENT_DIR="$(dirname "$PARENT_DIR")"
  MIGRATED=0
  for SEARCH_DIR in "$PARENT_DIR" "$GRANDPARENT_DIR"; do
    for CANDIDATE in \
      "$SEARCH_DIR/ShieldCode_v2.37/data/codeshield.sqlite3" \
      "$SEARCH_DIR/ShieldCode_v2.36/data/codeshield.sqlite3" \
      "$SEARCH_DIR/ShieldCode_v2.35/data/codeshield.sqlite3" \
      "$SEARCH_DIR/ShieldCode_v2.34/data/codeshield.sqlite3" \
      "$SEARCH_DIR/ShieldCode_v2.34_install/ShieldCode_v2.34/data/codeshield.sqlite3" \
      "$SEARCH_DIR/ShieldCode_v2.33/data/codeshield.sqlite3" \
      "$SEARCH_DIR/ShieldCode_v2.33_install/ShieldCode_v2.33/data/codeshield.sqlite3" \
      "$SEARCH_DIR/ShieldCode_v2.32/data/codeshield.sqlite3" \
      "$SEARCH_DIR/ShieldCode_v2.32_install/ShieldCode_v2.32/data/codeshield.sqlite3" \
      "$SEARCH_DIR/ShieldCode_v2.31/data/codeshield.sqlite3" \
      "$SEARCH_DIR/ShieldCode_v2.31_install/ShieldCode_v2.31/data/codeshield.sqlite3" \
      "$SEARCH_DIR/CodeShield_AI_v2.2/data/codeshield.sqlite3" \
      "$SEARCH_DIR/CodeShield_AI_2.5_install/CodeShield_AI_v2.5/data/codeshield.sqlite3"; do
      if [ -f "$CANDIDATE" ]; then
        mkdir -p "$PWD/data"
        echo "Переносим аккаунты и историю из предыдущей версии ShieldCode. Исходную базу не изменяем."
        python3 - "$CANDIDATE" "$PWD/data/codeshield.sqlite3" <<'PY'
import sqlite3
import sys
from pathlib import Path
from urllib.parse import quote

source_path = Path(sys.argv[1]).resolve()
source_uri = "file:" + quote(source_path.as_posix(), safe="/") + "?mode=ro"
with sqlite3.connect(source_uri, uri=True) as source:
    with sqlite3.connect(sys.argv[2]) as destination:
        source.backup(destination)
PY
        MIGRATED=1
        break
      fi
    done
    if [ "$MIGRATED" -eq 1 ]; then
      break
    fi
  done
fi
PORT="${SHIELDCODE_PORT:-${CODESHIELD_PORT:-8765}}"
python3 server.py &
SERVER_PID=$!
cleanup() { kill "$SERVER_PID" 2>/dev/null || true; }
trap cleanup EXIT INT TERM
sleep 1
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "ShieldCode не запустился. Проверь сообщение об ошибке выше."
  echo "Если порт ${PORT} занят другой копией, останови её в прежнем окне Терминала сочетанием Control+C."
  echo "Или запусти ShieldCode на свободном порту: SHIELDCODE_PORT=8776 ./run_mac_linux.sh"
  wait "$SERVER_PID" || true
  exit 1
fi
URL="http://127.0.0.1:${PORT}"
if command -v open >/dev/null 2>&1; then
  open "$URL" || true
elif command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$URL" >/dev/null 2>&1 || true
fi
wait "$SERVER_PID"
