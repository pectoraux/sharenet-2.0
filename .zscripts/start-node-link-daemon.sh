#!/bin/bash
set -e
PROJECT_DIR="/home/z/my-project"
NL_DIR="$PROJECT_DIR/mini-services/node-link"
LOG_FILE="$PROJECT_DIR/.zscripts/mini-service-node-link.log"
PID_FILE="$PROJECT_DIR/.zscripts/mini-service-node-link.pid"

cd "$NL_DIR"
if [ -f "$PID_FILE" ]; then
  OLD_PID="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
    echo "[node-link] already running (PID $OLD_PID)"
    exit 0
  fi
  rm -f "$PID_FILE"
fi

# Install deps if needed
[ -d node_modules ] || bun install

nohup setsid bash -c 'cd "'"$NL_DIR"'" && exec /usr/local/bin/bun --hot run index.ts' >"$LOG_FILE" 2>&1 < /dev/null &
DAEMON_PID=$!
echo "$DAEMON_PID" > "$PID_FILE"
echo "[node-link] launched (initial PID $DAEMON_PID)"
sleep 2
echo "[node-link] log tail:"
tail -10 "$LOG_FILE" 2>/dev/null
