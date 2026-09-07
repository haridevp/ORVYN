#!/usr/bin/env bash
# ==============================================================================
# 🛡️ AI Automated Penetration Testing Platform - Startup Launcher
# ==============================================================================
# Usage:
#   ./start.sh          # Auto-detects and launches the platform (Docker or Local)
#   ./start.sh --docker # Force Docker Compose cluster launch
#   ./start.sh --local  # Force native Local Development launch
#   ./start.sh --stop   # Stop all running platform services
#   ./start.sh --status # Check health of platform components
# ==============================================================================

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

BACKEND_DIR="$PROJECT_ROOT/src/backend"
FRONTEND_DIR="$PROJECT_ROOT/frontend"
VENV_DIR="$BACKEND_DIR/.venv"

# Terminal Colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
PURPLE='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${CYAN}${BOLD}"
    cat << 'EOF'
    ██████╗ ███████╗███╗   ██╗████████╗███████╗███████╗████████╗
    ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
    ██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ███████╗   ██║   
    ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ╚════██║   ██║   
    ██║     ███████╗██║ ╚████║   ██║   ███████╗███████║   ██║   
    ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝   
             AI-Automated Penetration Testing & SOC Suite
EOF
    echo -e "${NC}"
}

print_success() { echo -e "  ${GREEN}✔${NC} $1"; }
print_info()    { echo -e "  ${CYAN}ℹ${NC} $1"; }
print_warn()    { echo -e "  ${YELLOW}⚠${NC} $1"; }
print_error()   { echo -e "  ${RED}✖${NC} $1"; }

check_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "none"
        return 1
    fi

    # 1. Check if user already has direct docker access
    if docker info >/dev/null 2>&1; then
        echo "docker"
        return 0
    fi

    # 2. Check if non-interactive sudo can adjust socket permissions
    sudo -n chmod 666 /var/run/docker.sock >/dev/null 2>&1 || true
    if docker info >/dev/null 2>&1; then
        echo "docker"
        return 0
    fi

    # 3. Default to sudo docker so the user is prompted for permission in their terminal
    echo "sudo docker"
    return 0
}

# --- Command: STOP ---
if [[ "$1" == "--stop" || "$1" == "--down" || "$1" == "stop" ]]; then
    print_banner
    print_info "Stopping platform services..."
    
    DOCKER_CMD=$(check_docker || true)
    if [[ "$DOCKER_CMD" != "none" ]]; then
        $DOCKER_CMD compose down >/dev/null 2>&1 || true
    fi

    # Kill local instances if running
    if [[ -f "$PROJECT_ROOT/.backend.pid" ]]; then
        kill $(cat "$PROJECT_ROOT/.backend.pid") >/dev/null 2>&1 || true
        rm -f "$PROJECT_ROOT/.backend.pid"
    fi
    if [[ -f "$PROJECT_ROOT/.frontend.pid" ]]; then
        kill $(cat "$PROJECT_ROOT/.frontend.pid") >/dev/null 2>&1 || true
        rm -f "$PROJECT_ROOT/.frontend.pid"
    fi

    # Also kill any leftover processes on ports 8000 and 5173
    fuser -k 8000/tcp >/dev/null 2>&1 || true
    fuser -k 5173/tcp >/dev/null 2>&1 || true

    print_success "All platform services stopped successfully."
    exit 0
fi

# --- Command: STATUS ---
if [[ "$1" == "--status" || "$1" == "status" ]]; then
    print_banner
    print_info "Checking platform component status..."
    
    # Check Backend
    if curl -s -f http://localhost:8000/health >/dev/null 2>&1; then
        print_success "Backend API (Port 8000): ${GREEN}HEALTHY${NC} (http://localhost:8000)"
    else
        print_warn "Backend API (Port 8000): ${RED}OFFLINE${NC}"
    fi

    # Check Frontend
    if curl -s -f http://localhost:5173 >/dev/null 2>&1; then
        print_success "Frontend Dashboard (Port 5173): ${GREEN}ONLINE${NC} (http://localhost:5173)"
    else
        print_warn "Frontend Dashboard (Port 5173): ${RED}OFFLINE${NC}"
    fi
    exit 0
fi

# --- Main Startup Flow ---
print_banner

DOCKER_CMD=$(check_docker || true)

# By default, start.sh always runs docker compose
MODE="docker"

if [[ "$1" == "--local" ]]; then
    MODE="local"
fi

if [[ "$MODE" == "docker" ]]; then
    if [[ "$DOCKER_CMD" == "none" ]]; then
        print_error "Docker binary not found on PATH. Please install Docker or run with './start.sh --local'."
        exit 1
    fi

    if [[ "$DOCKER_CMD" == "sudo docker" ]]; then
        print_warn "Docker daemon requires elevated permissions to access /var/run/docker.sock."
        print_info "Prompting for sudo password to launch containers..."
    fi

    print_info "Launching platform cluster via ${BOLD}${DOCKER_CMD} compose${NC}..."
    echo -e "  ${DIM}Services: Backend (FastAPI+ZAP+Nuclei+Nikto), Celery Worker, Redis, PostgreSQL${NC}"
    echo ""

    REBUILD_FLAG=""
    for arg in "$@"; do
        if [[ "$arg" == "--build" ]]; then
            REBUILD_FLAG="--build"
            break
        fi
    done

    if [[ -n "$REBUILD_FLAG" ]]; then
        print_info "Rebuilding container images (--build specified)..."
        $DOCKER_CMD compose up --build -d
    else
        $DOCKER_CMD compose up -d
    fi

    print_info "Waiting for platform services health check..."
    READY=false
    for i in {1..35}; do
        if curl -s -f http://localhost:8000/health >/dev/null 2>&1; then
            READY=true
            break
        fi
        sleep 1
    done

    # Wait for frontend container on port 5173
    FRONTEND_READY=false
    for i in {1..20}; do
        if curl -s -f http://localhost:5173 >/dev/null 2>&1; then
            FRONTEND_READY=true
            break
        fi
        sleep 1
    done

    if [[ "$FRONTEND_READY" != "true" ]]; then
        # If containerized frontend failed or wasn't included, start fallback frontend locally
        print_info "Containerized frontend not detected on port 5173. Launching host fallback..."
        if [[ ! -d "$FRONTEND_DIR/node_modules" ]]; then
            (cd "$FRONTEND_DIR" && npm install)
        fi
        (cd "$FRONTEND_DIR" && nohup npm run dev -- --host 0.0.0.0 > "$PROJECT_ROOT/.frontend.log" 2>&1 & echo $! > "$PROJECT_ROOT/.frontend.pid")
        sleep 2
    fi

else
    # Local Mode
    print_info "Starting platform in ${BOLD}Local Native Mode${NC}..."

    # 1. Setup Python backend
    print_info "Checking backend Python virtual environment..."
    if [[ ! -d "$VENV_DIR" ]]; then
        python3 -m venv "$VENV_DIR"
    fi
    source "$VENV_DIR/bin/activate"

    if ! python3 -c "import fastapi, uvicorn, rich, requests" >/dev/null 2>&1; then
        print_info "Installing backend dependencies from requirements.txt..."
        pip install --no-cache-dir -r "$BACKEND_DIR/requirements.txt"
    fi

    # 2. Setup Node frontend
    print_info "Checking frontend node dependencies..."
    if [[ ! -d "$FRONTEND_DIR/node_modules" ]]; then
        (cd "$FRONTEND_DIR" && npm install)
    fi

    # 3. Start Backend
    print_info "Starting FastAPI backend on port 8000..."
    fuser -k 8000/tcp >/dev/null 2>&1 || true
    (cd "$BACKEND_DIR" && nohup "$VENV_DIR/bin/uvicorn" main:app --host 0.0.0.0 --port 8000 > "$PROJECT_ROOT/.backend.log" 2>&1 & echo $! > "$PROJECT_ROOT/.backend.pid")

    # 4. Start Frontend
    print_info "Starting Vite frontend dashboard on port 5173..."
    fuser -k 5173/tcp >/dev/null 2>&1 || true
    (cd "$FRONTEND_DIR" && nohup npm run dev -- --host 0.0.0.0 > "$PROJECT_ROOT/.frontend.log" 2>&1 & echo $! > "$PROJECT_ROOT/.frontend.pid")

    # 5. Wait for readiness
    print_info "Verifying service readiness..."
    for i in {1..20}; do
        if curl -s -f http://localhost:8000/health >/dev/null 2>&1 && curl -s -f http://localhost:5173 >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
fi

# Final Output Card
echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}   ${GREEN}${BOLD}🚀 AI AUTOMATED PENETRATION TESTING PLATFORM IS READY!${NC}             ${CYAN}║${NC}"
echo -e "${CYAN}╠═══════════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  🌐 ${BOLD}Web Dashboard:${NC}   ${CYAN}http://localhost:5173${NC}                            ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  🔑 ${BOLD}Default Login:${NC}   Username: ${YELLOW}admin${NC} | Password: ${YELLOW}admin${NC}             ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  ⚙️  ${BOLD}API Docs:${NC}        ${CYAN}http://localhost:8000/docs${NC}                       ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  💻 ${BOLD}CLI Utility:${NC}     ${PURPLE}./cli.py scan <target> [options]${NC}                ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  🛑 ${BOLD}To Stop:${NC}         ${DIM}./start.sh --stop${NC}                               ${CYAN}║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
print_success "Ready for vulnerability assessments. Enjoy!"
