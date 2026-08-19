#!/usr/bin/env bash
# Double-click this in Finder to start ROB and open the console.
# Closing the Terminal window stops ROB.
#
# Restart-safe: if a previous ROB is still holding the port, it is stopped
# first. Without that, the new process fails to bind, the port check still
# succeeds against the OLD server, and the browser opens on a stale version
# that looks like it started correctly. Silently serving the previous build
# is worse than refusing to start.
set -euo pipefail
cd "$(dirname "$0")"

PORT="${ROB_PORT:-8422}"
HOME_DIR="${ROB_HOME:-$PWD/rob_home}"

printf '\033]0;ROB\007'

# --- stop a previous ROB, and only a previous ROB -------------------------
holder="$(lsof -ti "tcp:$PORT" -sTCP:LISTEN 2>/dev/null | head -1 || true)"
if [ -n "$holder" ]; then
  cmd="$(ps -o command= -p "$holder" 2>/dev/null || true)"
  case "$cmd" in
    *"rob serve"*|*"rob.serve"*)
      echo "  Stopping the ROB already running on port $PORT (pid $holder)..."
      kill "$holder" 2>/dev/null || true
      for _ in $(seq 1 20); do
        lsof -ti "tcp:$PORT" -sTCP:LISTEN >/dev/null 2>&1 || break
        sleep 0.25
      done
      lsof -ti "tcp:$PORT" -sTCP:LISTEN >/dev/null 2>&1 && kill -9 "$holder" 2>/dev/null || true
      sleep 0.5
      ;;
    *)
      echo
      echo "  Port $PORT is held by something that is not ROB:"
      echo "    pid $holder — $cmd"
      echo
      echo "  Not touching it. Start ROB on another port instead:"
      echo "    ROB_PORT=8423 ./ROB.command"
      echo
      read -r -p "  Press Return to close." _ || true
      exit 1
      ;;
  esac
fi

cat <<BANNER

  ROB - Remediation & Optimisation Bot
  workspace: $HOME_DIR
  console:   http://127.0.0.1:$PORT

  Leave this window open. Close it, or press Ctrl-C, to stop ROB.

BANNER

python3 -m rob serve --home "$HOME_DIR" --port "$PORT" &
ROB_PID=$!
trap 'kill $ROB_PID 2>/dev/null || true' EXIT INT TERM

# Wait for THIS process to be serving before opening a browser, so a failed
# start is visible as a failed start rather than as an old page.
opened=""
for _ in $(seq 1 40); do
  if ! kill -0 "$ROB_PID" 2>/dev/null; then
    echo
    echo "  ROB failed to start. The error is above."
    read -r -p "  Press Return to close." _ || true
    exit 1
  fi
  if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
    open "http://127.0.0.1:$PORT"
    opened="yes"
    break
  fi
  sleep 0.25
done
[ -n "$opened" ] || echo "  Console did not come up in 10s. Open http://127.0.0.1:$PORT yourself."

wait $ROB_PID
