#!/bin/bash

# Padding Oracle Project — Docker launcher
# Starts all 4 containers and opens browser tabs once each service is ready.

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

# ── Browser helper (macOS / Linux / Windows Git Bash) ─────────────────────────
open_browser() {
    case "$(uname -s)" in
        Darwin*)            open "$1" ;;
        Linux*)             xdg-open "$1" 2>/dev/null || echo "Open manually: $1" ;;
        CYGWIN*|MINGW*|MSYS*) start "$1" ;;
        *)                  echo "Open manually: $1" ;;
    esac
}

# ── Wait until a URL returns HTTP 200 ─────────────────────────────────────────
wait_for() {
    local name="$1"
    local url="$2"
    local max=30   # max seconds to wait
    local i=0
    printf "  Waiting for %-35s" "$name..."
    while [ $i -lt $max ]; do
        if curl -sf "$url" -o /dev/null 2>/dev/null; then
            echo " ready"
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    echo " TIMEOUT (check: docker compose logs)"
    return 1
}

# ── Start containers in the background ────────────────────────────────────────
echo ""
echo "Starting containers..."
docker compose up -d
echo ""

# ── Wait for each service ─────────────────────────────────────────────────────
echo "Waiting for services to become healthy:"
wait_for "Phase 1 — CBC Vulnerable Server" "http://localhost:5000/status"
wait_for "Phase 3 — GCM Secure Server"     "http://localhost:5001/status"
wait_for "Phase 2 — Attack Visualizer"     "http://localhost:5002"
wait_for "Phase 4 — Dashboard"             "http://localhost:5004"

# ── Open browser tabs ─────────────────────────────────────────────────────────
echo ""
echo "Opening browser tabs..."
open_browser "http://localhost:5000"
open_browser "http://localhost:5001"
open_browser "http://localhost:5002"
open_browser "http://localhost:5004"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "All services running:"
echo "  Phase 1 — CBC Vulnerable Server  →  http://localhost:5000"
echo "  Phase 3 — GCM Secure Server      →  http://localhost:5001"
echo "  Phase 2 — Attack Visualizer      →  http://localhost:5002"
echo "  Phase 4 — Dashboard              →  http://localhost:5004"
echo ""
echo "To follow logs:  docker compose logs -f"
echo "To stop all:     docker compose down"
echo ""
