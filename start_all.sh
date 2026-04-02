#!/bin/bash

# Padding Oracle Project - Start All Servers
# Starts all 4 servers and opens them in the browser
# Compatible with macOS, Linux, and Windows (Git Bash / WSL)

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Detect Python — prefer venv, fall back to python3/python
if [ -f "$PROJECT_DIR/venv/bin/python" ]; then
    PYTHON="$PROJECT_DIR/venv/bin/python"
elif [ -f "$PROJECT_DIR/venv/Scripts/python.exe" ]; then
    PYTHON="$PROJECT_DIR/venv/Scripts/python.exe"
elif command -v python3 &>/dev/null; then
    PYTHON="python3"
else
    PYTHON="python"
fi

# Detect OS for browser open command
open_browser() {
    local url="$1"
    case "$(uname -s)" in
        Darwin*)  open "$url" ;;
        Linux*)   xdg-open "$url" 2>/dev/null || echo "Open manually: $url" ;;
        CYGWIN*|MINGW*|MSYS*) start "$url" ;;
        *)        echo "Open manually: $url" ;;
    esac
}

PIDS=()

cleanup() {
    echo ""
    echo "Stopping all servers..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null
    done
    wait 2>/dev/null
    echo "All servers stopped."
    exit 0
}

trap cleanup SIGINT SIGTERM

start_server() {
    local name="$1"
    local script="$2"
    local port="$3"

    echo "Starting $name on port $port..."
    "$PYTHON" "$script" &
    PIDS+=($!)
}

# Start all servers
start_server "Phase 1 - CBC Vulnerable Server"   "$PROJECT_DIR/phase1/server.py"             5000
start_server "Phase 3 - GCM Secure Server"       "$PROJECT_DIR/phase3/server.py"             5001
start_server "Phase 2 - Attack Visualizer"       "$PROJECT_DIR/phase2/attack_visualizer.py"  5002
start_server "Phase 4 - Dashboard"               "$PROJECT_DIR/phase4/server.py"             5004

# Wait for servers to start
echo ""
echo "Waiting for servers to initialize..."
sleep 2

# Open all in browser
echo "Opening all servers in browser..."
open_browser "http://127.0.0.1:5000"
open_browser "http://127.0.0.1:5001"
open_browser "http://127.0.0.1:5002"
open_browser "http://127.0.0.1:5004"

echo ""
echo "All servers running:"
echo "  Phase 1 - CBC Vulnerable Server  -> http://127.0.0.1:5000"
echo "  Phase 3 - GCM Secure Server      -> http://127.0.0.1:5001"
echo "  Phase 2 - Attack Visualizer      -> http://127.0.0.1:5002"
echo "  Phase 4 - Dashboard              -> http://127.0.0.1:5004"
echo ""
echo "Press Ctrl+C to stop all servers."

wait
