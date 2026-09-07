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
             Automated Penetration Testing & DAST Platform
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

# --- Command: HELP & ADVANCED CLI MANUAL ---
if [[ "$1" == "--help" || "$1" == "-h" || "$1" == "help" ]]; then
    print_banner
    cat << 'EOF'
ADVANCED CLI & PLATFORM MANUAL
==============================

The AI Automated Penetration Testing platform provides both a full containerized
web dashboard (Vite + FastAPI + Celery + Redis + PostgreSQL) and a powerful,
high-performance CLI for terminal-driven vulnerability assessments and CI/CD pipelines.

SYNOPSIS:
    ./start.sh [PLATFORM_COMMAND]
    ./start.sh scan <target> [SCAN_OPTIONS]
    ./start.sh probe <target>
    ./start.sh cli
    ./cli.py <command> [OPTIONS]

--------------------------------------------------------------------------------
1. PLATFORM & CLUSTER MANAGEMENT
--------------------------------------------------------------------------------
    ./start.sh              Auto-detects and launches platform cluster via Docker Compose
    ./start.sh --build      Rebuilds all container images from source without cache
    ./start.sh --local      Launches platform natively using host Python venv & Vite
    ./start.sh --stop       Gracefully stops all platform containers & background processes
    ./start.sh --status     Checks health of backend API, engines, and frontend
    ./start.sh --help, -h   Displays this advanced CLI usage manual

--------------------------------------------------------------------------------
2. TERMINAL VULNERABILITY ASSESSMENT (CLI)
--------------------------------------------------------------------------------
    ./start.sh scan <target> [OPTIONS]
    ./cli.py scan <target> [OPTIONS]

    TARGET SPECIFICATION:
        target                  Hostname, IP address, or full URL (e.g. scanme.nmap.org,
                                http://192.168.1.50:8080, or https://example.com)

    SCAN INTENSITY PROFILES:
        --profile recon         Rapid reconnaissance (~15-25s): Port probing, tech stack
                                identification, DNS enumeration, and low-risk templates.
        --profile web           Standard Web DAST (~45s): Active crawling, injection checks
                                (XSS, SQLi, SSRF, LFI), header audits, and misconfigurations.
        --profile full          Comprehensive audit (~85s): Exhaustive multi-scanner crawl,
                                deep fuzzing, OWASP Top 10 coverage, and CVE template suite.
        --profile unlimited     Exhaustive Deep Scan (NO TIMEOUT): Runs all engines without
                                artificial execution timeouts. Recommended for large surface
                                areas, heavy web applications, or slow networks.

    SCOPE & PERIMETER CONTROL:
        --in-scope <patterns>   Comma-separated list of allowed domains or wildcard masks.
                                Default: *.target.com, target.com
                                Example: --in-scope "*.corp.internal,api.corp.internal"
        --out-of-scope <rules>  Comma-separated deny-list patterns to strictly exclude.
        --exclude <rules>       Matches against URLs, domains, and paths.
                                Example: --out-of-scope "logout,admin/delete,*.billing.internal"

    ENGINE SELECTION:
        --scanners <list>       Comma-separated subset of scanners to orchestrate.
                                Choices: nuclei, zap, nikto, whatweb, nmap, sslyze, wapiti
                                (default: all 7 engines).
                                Example: --scanners "nuclei,zap,nmap,whatweb"

    REPORT EXPORTS & ARTIFACTS:
        -o, --output <file>     Export assessment findings directly to file.
                                Supported formats by extension:
                                  - .pdf  : Corporate executive PDF report ([COMPANY NAME] branding)
                                  - .md   : Clean executive Markdown report with CVSS & remediation
                                  - .json : Structured machine-readable JSON schema for CI/CD
                                  - .txt  : Plain-text findings summary
                                Example: -o /tmp/audit_report.pdf

    TELEMETRY & LOG VERBOSITY:
        -v, --verbose           Stream live scanner stdout/stderr execution logs in real time.
        --detailed              Expand full vulnerability evidence, HTTP requests, responses,
                                and MITRE CWE / OWASP remediation references.
        --no-probe              Skip pre-flight DNS, TLS, and reachability diagnostics.
        --force                 Continue execution even if pre-flight target check fails.
        --json                  Output raw machine-readable JSON directly to stdout.
        --api <url>             Execute scan against a remote platform cluster (e.g. http://localhost:8000).
                                If omitted, scanners run locally in-process.

--------------------------------------------------------------------------------
3. TARGET DIAGNOSTICS & PROBING
--------------------------------------------------------------------------------
    ./start.sh probe <target>
    ./cli.py probe <target>

    Performs rapid non-intrusive pre-flight diagnostics:
      - DNS resolution & IPv4/IPv6 resolution
      - TLS / HTTP connectivity & latency round-trip time (RTT)
      - Server header banner disclosure & HTTP status response
      - Typo-squatting detection and hostname validation

--------------------------------------------------------------------------------
4. INTERACTIVE CONSOLE WIZARD
--------------------------------------------------------------------------------
    ./start.sh cli
    ./start.sh -i

    Launches an interactive guided CLI prompt to configure target domain, profile,
    and output options step-by-step.

--------------------------------------------------------------------------------
5. ADVANCED PRODUCTION RECIPES & EXAMPLES
--------------------------------------------------------------------------------
    # Recipe 1: Rapid pre-flight target diagnostics
    ./start.sh probe scanme.nmap.org

    # Recipe 2: Full web audit with live verbose logs and Markdown report
    ./start.sh scan scanme.nmap.org --profile web -v -o report.md --detailed

    # Recipe 3: Exhaustive deep scan with NO timeouts
    ./start.sh scan target.com --profile unlimited -o full_audit.md

    # Recipe 4: Wildcard perimeter with strict exclusion of sensitive endpoints
    ./start.sh scan example.com \
        --in-scope "*.example.com" \
        --out-of-scope "logout,auth/reset,admin/delete,payment.*" \
        -o perimeter_findings.json

    # Recipe 5: CI/CD Pipeline security gate (JSON exit output)
    ./cli.py scan staging.internal --profile recon --no-probe --json -o ci_results.json

    # Recipe 6: Target a remote platform backend over the network
    ./start.sh scan target.com --api http://soc-cluster.corp:8000 -v -o remote_audit.md

EOF
    exit 0
fi

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
    echo -e "  ${BOLD}Platform Cluster Health & Status Check${NC}"
    echo ""
    
    # 1. Backend API Check
    if curl -s -f http://localhost:8000/health >/dev/null 2>&1; then
        print_success "Backend API: Online (http://localhost:8000/health)"
    else
        print_error "Backend API: Offline"
    fi

    # 2. Frontend Check
    if curl -s -f http://localhost:5173 >/dev/null 2>&1; then
        print_success "Frontend Dashboard: Online (http://localhost:5173)"
    else
        print_error "Frontend Dashboard: Offline"
    fi

    # 3. Docker Container Status
    DOCKER_CMD=$(check_docker || true)
    if [[ "$DOCKER_CMD" != "none" ]]; then
        echo ""
        print_info "Docker Container Status:"
        $DOCKER_CMD ps --filter "name=fastapi_app|celery_worker|redis|postgres|frontend_app" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || true
    fi
    exit 0
fi

# --- Command: SCAN (Terminal Vulnerability Assessment) ---
if [[ "$1" == "scan" || "$1" == "--scan" ]]; then
    shift
    exec "$PROJECT_ROOT/cli.py" scan "$@"
fi

# --- Command: PROBE (Terminal Host Diagnostics) ---
if [[ "$1" == "probe" || "$1" == "--probe" ]]; then
    shift
    exec "$PROJECT_ROOT/cli.py" probe "$@"
fi

# --- Command: CLI / INTERACTIVE CONSOLE ---
if [[ "$1" == "cli" || "$1" == "--cli" || "$1" == "-i" || "$1" == "--interactive" ]]; then
    print_banner
    echo -e "  ${BOLD}🛡️  Interactive Terminal Penetration Testing Console${NC}"
    echo ""
    read -r -p "  Enter target domain or URL (e.g. scanme.nmap.org): " INTER_TARGET
    if [[ -z "$INTER_TARGET" ]]; then
        print_error "Target cannot be empty."
        exit 1
    fi
    echo ""
    echo -e "  Select Scan Profile:"
    echo -e "    ${BOLD}1${NC}) Recon (~20s fast check)"
    echo -e "    ${BOLD}2${NC}) Web (~45s DAST & injection suite)"
    echo -e "    ${BOLD}3${NC}) Full (~85s comprehensive audit)"
    echo -e "    ${BOLD}4${NC}) Unlimited (Exhaustive deep scan, no timeout)"
    read -r -p "  Choice [1-4] (default: 2): " PROF_SEL
    case "$PROF_SEL" in
        1) PROF_NAME="recon" ;;
        3) PROF_NAME="full" ;;
        4) PROF_NAME="unlimited" ;;
        *) PROF_NAME="web" ;;
    esac
    echo ""
    print_info "Starting terminal scan for ${BOLD}$INTER_TARGET${NC} with profile: ${BOLD}$PROF_NAME${NC}..."
    echo ""
    exec "$PROJECT_ROOT/cli.py" scan "$INTER_TARGET" --profile "$PROF_NAME" --detailed -o "$PROJECT_ROOT/terminal_scan_report.md"
fi

# --- Main Startup Flow ---
echo ""
print_info "Initializing platform cluster & security engines..."
echo ""

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

    # Release any leftover host background processes on port 5173/8000 so docker can bind cleanly
    if [[ -f "$PROJECT_ROOT/.frontend.pid" ]]; then
        kill $(cat "$PROJECT_ROOT/.frontend.pid") >/dev/null 2>&1 || true
        rm -f "$PROJECT_ROOT/.frontend.pid"
    fi
    fuser -k 5173/tcp >/dev/null 2>&1 || true

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

# Replace loading screen with clean logo and platform details card
if [ -t 1 ]; then
    clear
fi

print_banner

# Final Output Card
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}   ${GREEN}${BOLD}🚀 AUTOMATED PENETRATION TESTING PLATFORM READY${NC}                     ${CYAN}║${NC}"
echo -e "${CYAN}╠═══════════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  🌐 ${BOLD}Web Dashboard:${NC}   ${CYAN}http://localhost:5173${NC}                            ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  🔑 ${BOLD}Default Login:${NC}   Username: ${YELLOW}admin${NC} | Password: ${YELLOW}admin${NC}             ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  ⚙️  ${BOLD}API Docs:${NC}        ${CYAN}http://localhost:8000/docs${NC}                       ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  💻 ${BOLD}Terminal Scan:${NC}   ${PURPLE}./start.sh scan <target> [--profile unlimited]${NC}      ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  🔍 ${BOLD}Target Probe:${NC}    ${PURPLE}./start.sh probe <target>${NC}                           ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  📖 ${BOLD}CLI Manual:${NC}      ${CYAN}./start.sh --help${NC}                                   ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  🛑 ${BOLD}To Stop:${NC}         ${DIM}./start.sh --stop${NC}                               ${CYAN}║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Interactive terminal scan option if running inside an interactive terminal
if [ -t 0 ]; then
    echo -e "${YELLOW}🎯 Launch a terminal vulnerability scan now? (y/N):${NC} "
    read -r -p "> " RUN_SCAN || true
    if [[ "$RUN_SCAN" =~ ^[Yy]$ ]]; then
        echo ""
        read -r -p "  Enter target domain or URL (e.g. scanme.nmap.org): " TERM_TARGET
        if [[ -n "$TERM_TARGET" ]]; then
            echo ""
            echo -e "  Select Intensity Profile:"
            echo -e "    1) Recon (~20s fast check)"
            echo -e "    2) Web (~45s standard DAST)"
            echo -e "    3) Full (~85s comprehensive)"
            echo -e "    4) Unlimited (Exhaustive, no timeout)"
            read -r -p "  Profile [1-4] (default: 2): " PROF_SEL
            case "$PROF_SEL" in
                1) P_NAME="recon" ;;
                3) P_NAME="full" ;;
                4) P_NAME="unlimited" ;;
                *) P_NAME="web" ;;
            esac
            echo ""
            print_info "Executing terminal penetration assessment for ${BOLD}$TERM_TARGET${NC}..."
            echo ""
            "$PROJECT_ROOT/cli.py" scan "$TERM_TARGET" --profile "$P_NAME" --detailed --force -o "$PROJECT_ROOT/scan_report.md"
            echo ""
            print_success "Assessment complete! Audit report saved to ${BOLD}scan_report.md${NC}"
        fi
    fi
else
    print_success "Ready for vulnerability assessments. Run './start.sh scan <target>' anytime!"
fi
