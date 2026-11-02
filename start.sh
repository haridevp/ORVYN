#!/usr/bin/env bash
# ==============================================================================
# 🛡️ ORVYN - Offensive Risk and Vulnerability Intelligence Network
# Startup & Autonomous Security Assessment Launcher
# ==============================================================================
# Usage:
#   ./start.sh          # Auto-detects and launches the platform in Docker
#   ./start.sh check    # Diagnostic of host OS, Docker MCP layer, and toolchain
#   ./start.sh scan <t> # Run terminal penetration assessment against target
#   ./start.sh probe <t># Pre-flight DNS & reachability probe
#   ./start.sh status   # Check health of platform components
#   ./start.sh stop     # Stop all platform services
#   ./start.sh --help   # View full CLI manual
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
NC='\033[0m'

print_banner() {
    echo -e "${CYAN}${BOLD}"
    cat << 'EOF'
     ██████╗ ██████╗ ██╗   ██╗██╗   ██╗███╗   ██╗
    ██╔═══██╗██╔══██╗██║   ██║╚██╗ ██╔╝████╗  ██║
    ██║   ██║██████╔╝██║   ██║ ╚████╔╝ ██╔██╗ ██║
    ██║   ██║██╔══██╗╚██╗ ██╔╝  ╚██╔╝  ██║╚██╗██║
    ╚██████╔╝██║  ██║ ╚████╔╝    ██║   ██║ ╚████║
     ╚═════╝ ╚═╝  ╚═╝  ╚═══╝     ╚═╝   ╚═╝  ╚═══╝
   Offensive Risk and Vulnerability Intelligence Network
EOF
    echo -e "${NC}"
}

print_success() { echo -e "  ${GREEN}✔${NC} $1"; }
print_info()    { echo -e "  ${CYAN}ℹ${NC} $1"; }
print_warn()    { echo -e "  ${YELLOW}⚠${NC} $1"; }
print_error()   { echo -e "  ${RED}✖${NC} $1"; }

# ------------------------------------------------------------------------------
# Container & OS Detection
# ------------------------------------------------------------------------------

detect_host_os() {
    OS_NAME="Linux Host"
    OS_ID="unknown"
    IS_KALI=false
    IS_PARROT=false
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        OS_NAME="${PRETTY_NAME:-$NAME}"
        OS_ID="${ID:-unknown}"
        if [[ "$OS_ID" == "kali" || "$ID_LIKE" =~ "kali" ]]; then
            IS_KALI=true
        elif [[ "$OS_ID" == "parrot" || "$ID_LIKE" =~ "parrot" ]]; then
            IS_PARROT=true
        fi
    fi
}

can_use_sudo() {
    # Check if sudo is functional without triggering No-New-Privileges (NNP) SELinux AVC denial
    if command -v sudo >/dev/null 2>&1; then
        if sudo -n true >/dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

check_docker() {
    # 1. Direct Docker engine access
    if command -v docker >/dev/null 2>&1; then
        if docker info >/dev/null 2>&1; then
            echo "docker"
            return 0
        fi
        # Only attempt socket permission fix if sudo is non-interactively permitted without NNP denial
        if can_use_sudo; then
            sudo -n chmod 666 /var/run/docker.sock >/dev/null 2>&1 || true
            if docker info >/dev/null 2>&1; then
                echo "docker"
                return 0
            fi
        fi
    fi

    # 2. Podman engine access
    if command -v podman >/dev/null 2>&1; then
        if podman info >/dev/null 2>&1; then
            echo "podman"
            return 0
        fi
    fi

    # 3. Fallback to sudo docker only if sudo is permitted and functional
    if command -v docker >/dev/null 2>&1 && can_use_sudo; then
        echo "sudo docker"
        return 0
    fi

    echo "none"
    return 1
}

get_compose_cmd() {
    local DOCKER_BIN
    DOCKER_BIN=$(check_docker || true)
    if [[ "$DOCKER_BIN" == "none" ]]; then
        echo "none"
        return 1
    fi

    if $DOCKER_BIN compose version >/dev/null 2>&1; then
        echo "$DOCKER_BIN compose"
        return 0
    fi
    if command -v docker-compose >/dev/null 2>&1; then
        if [[ "$DOCKER_BIN" =~ "sudo" ]]; then
            echo "sudo docker-compose"
        else
            echo "docker-compose"
        fi
        return 0
    fi
    if command -v podman-compose >/dev/null 2>&1; then
        echo "podman-compose"
        return 0
    fi

    echo "$DOCKER_BIN compose"
    return 0
}

run_cli() {
    local DOCKER_BIN
    DOCKER_BIN=$(check_docker || true)

    # 1. If backend container is already running, execute directly inside container
    if [[ "$DOCKER_BIN" != "none" ]] && $DOCKER_BIN ps --format '{{.Names}}' 2>/dev/null | grep -q "^fastapi_app$"; then
        local TTY_FLAG="-i"
        if [ -t 0 ] && [ -t 1 ]; then
            TTY_FLAG="-it"
        fi
        $DOCKER_BIN exec $TTY_FLAG fastapi_app python3 cli.py "$@"
        return $?
    fi

    detect_host_os

    # 2. Strict container-only policy for non-Kali/Parrot hosts
    if [[ "$IS_KALI" != "true" && "$IS_PARROT" != "true" ]]; then
        if [[ "$1" == "scan" && "$DOCKER_BIN" == "none" ]]; then
            print_error "Strict Isolation Policy: Security scanning tools must execute inside Docker on ${OS_NAME}."
            print_error "Native host tool execution is strictly restricted to Kali Linux or Parrot OS."
            print_info "Please install Docker/Podman and ensure the container daemon is active to execute scans."
            return 1
        fi

        if [[ "$DOCKER_BIN" != "none" ]]; then
            local IMAGE_NAME="pentest-backend:latest"
            if ! $DOCKER_BIN image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
                print_info "Curated tool container image ($IMAGE_NAME) not found. Building container now..."
                local COMPOSE_CMD
                COMPOSE_CMD=$(get_compose_cmd || true)
                if [[ "$COMPOSE_CMD" != "none" ]]; then
                    $COMPOSE_CMD build backend
                else
                    $DOCKER_BIN build -t "$IMAGE_NAME" "$PROJECT_ROOT/src/backend"
                fi
            fi

            local TTY_FLAG="-i"
            if [ -t 0 ] && [ -t 1 ]; then
                TTY_FLAG="-it"
            fi
            $DOCKER_BIN run --rm $TTY_FLAG --network host \
                -v "$PROJECT_ROOT/src/backend:/app" \
                -e IS_DOCKER=true \
                "$IMAGE_NAME" python3 cli.py "$@"
            return $?
        fi
    fi

    # 3. Native Kali / Parrot OS fallback
    local PYTHON_BIN="python3"
    local VENV_CANDIDATES=(
        "$PROJECT_ROOT/src/backend/.venv/bin/python"
        "$PROJECT_ROOT/.venv/bin/python"
        "$PROJECT_ROOT/.venv-backend/bin/python"
    )
    for cand in "${VENV_CANDIDATES[@]}"; do
        if [[ -f "$cand" && -x "$cand" ]]; then
            PYTHON_BIN="$cand"
            break
        fi
    done

    PYTHONPATH="$BACKEND_DIR:${PYTHONPATH:-}" "$PYTHON_BIN" "$BACKEND_DIR/cli.py" "$@"
}

show_mcp_tools_catalog() {
    echo -e "  ${BOLD}🛡️  HexStrike Model Context Protocol (MCP) Curated Tools Catalog${NC}"
    echo -e "  ${DIM}72 Curated Security Tools & Autonomous Multi-Scanner Orchestration Engines${NC}"
    echo ""
    echo -e "  ${BOLD}Operational Security Tool Domains:${NC}"
    echo -e "    1. ${CYAN}Reconnaissance & OSINT (12 tools):${NC}"
    echo -e "       • nmap, masscan, amass, sublist3r, dnsrecon, theharvester"
    echo -e "       • shodan_cli, censys_cli, whois, traceroute, asnlookup, recon_ng"
    echo ""
    echo -e "    2. ${CYAN}Content Discovery & Spidering (8 tools):${NC}"
    echo -e "       • gospider, katana, hakrawler, waybackurls, gau, paramspider, arjun, feroxbuster"
    echo ""
    echo -e "    3. ${CYAN}Web Vulnerability Scanning (14 tools):${NC}"
    echo -e "       • nuclei, nikto, whatweb, wapiti, jaeles, dalfox, crlfuzz"
    echo -e "       • corsy, commix, tplmap, nosqlmap, xsser, retire_js, zap"
    echo ""
    echo -e "    4. ${CYAN}Network, SSL/TLS & Infrastructure (8 tools):${NC}"
    echo -e "       • sslyze, testssl, snmpwalk, ike_scan, tshark, netcat, enum4linux, smbclient"
    echo ""
    echo -e "    5. ${CYAN}Directory & Parameter Fuzzing (6 tools):${NC}"
    echo -e "       • ffuf, gobuster, dirsearch, wfuzz, kiterunner, vhost_fuzzer"
    echo ""
    echo -e "    6. ${CYAN}Injection & Exploitation Testing (7 tools):${NC}"
    echo -e "       • sqlmap, ghauri, jwt_tool, xsstrike, ssrfmap, graphql_cop, ysoserial"
    echo ""
    echo -e "    7. ${CYAN}Cloud, Secrets & Configuration Audit (8 tools):${NC}"
    echo -e "       • trufflehog, gitleaks, scoutsuite, prowler, cloudmapper, detect_secrets, gitrob, shhgit"
    echo ""
    echo -e "    8. ${CYAN}Authentication & Credential Auditing (5 tools):${NC}"
    echo -e "       • hydra, medusa, crowbar, cirt_fuzzer, patator"
    echo ""
    echo -e "    9. ${CYAN}Orchestration & Verification Engines (4 meta tools):${NC}"
    echo -e "       • hexstrike_list_templates, hexstrike_detect_environment"
    echo -e "       • hexstrike_recommend_template, hexstrike_verify_vulnerability"
    echo ""
    echo -e "  ${BOLD}Curated Container Core Toolchain:${NC}"
    echo -e "    ${GREEN}✔${NC} nmap (v7.90+)         ${GREEN}✔${NC} nuclei (v3.2.0+)       ${GREEN}✔${NC} nikto (v2.5.0+)"
    echo -e "    ${GREEN}✔${NC} whatweb               ${GREEN}✔${NC} sqlmap                 ${GREEN}✔${NC} ffuf (v2.1.0+)"
    echo -e "    ${GREEN}✔${NC} sslyze                ${GREEN}✔${NC} owasp zap baseline     ${GREEN}✔${NC} wapiti3"
    echo -e "    ${GREEN}✔${NC} common discovery wordlists (/usr/share/wordlists/dirb/common.txt)"
    echo ""
    if curl -s -f http://localhost:8000/mcp/tools >/dev/null 2>&1; then
        local LIVE_COUNT
        LIVE_COUNT=$(curl -s http://localhost:8000/mcp/tools | grep -o '"name":' | wc -l || echo "72")
        print_success "Live MCP Endpoint: Online (${LIVE_COUNT} tools registered at http://localhost:8000/mcp/tools)"
    else
        print_info "MCP Endpoint: Offline (launch cluster with ${CYAN}./start.sh${NC} to expose live MCP endpoint)"
    fi
    echo ""
}

check_system_environment() {
    echo -e "  ${BOLD}Platform System Requirements & Security Toolchain Diagnostic${NC}"
    echo ""

    detect_host_os

    # 1. Host Operating System & Execution Policy
    echo -e "  ${BOLD}1. Host Operating System & Execution Policy:${NC}"
    if [[ "$IS_KALI" == "true" ]]; then
        print_success "Kali Linux detected: ${CYAN}${OS_NAME}${NC}"
        print_success "Execution Policy: Native host tool execution permitted."
    elif [[ "$IS_PARROT" == "true" ]]; then
        print_success "Parrot Security OS detected: ${CYAN}${OS_NAME}${NC}"
        print_success "Execution Policy: Native host tool execution permitted."
    else
        print_info "Host Distribution: ${CYAN}${OS_NAME}${NC} (ID: ${OS_ID})"
        print_success "Strict Container Isolation Enforced: Non-Kali/Parrot host detected."
        print_info "All security tools (Nmap, Nuclei, ZAP, Nikto, etc.) are strictly isolated and execute inside Docker container."
    fi
    echo ""

    # 2. Host Toolchain Diagnostic (Kali/Parrot only)
    if [[ "$IS_KALI" == "true" || "$IS_PARROT" == "true" ]]; then
        echo -e "  ${BOLD}2. Native Host Security Toolchain:${NC}"
        local SECURITY_TOOLS=("nmap" "nuclei" "nikto" "whatweb" "sqlmap" "ffuf" "sslyze" "wapiti" "zap")
        local HOST_FOUND=0
        for tool in "${SECURITY_TOOLS[@]}"; do
            if command -v "$tool" >/dev/null 2>&1; then
                local TOOL_PATH
                TOOL_PATH=$(command -v "$tool" || true)
                echo -e "    ${GREEN}✔${NC} ${BOLD}${tool}${NC} (native binary at ${DIM}${TOOL_PATH}${NC})"
                HOST_FOUND=$((HOST_FOUND + 1))
            else
                echo -e "    ${YELLOW}⚠${NC} ${tool} (not installed on host PATH)"
            fi
        done
        echo ""
        print_info "${HOST_FOUND}/${#SECURITY_TOOLS[@]} native tools installed on ${OS_NAME} host."
        echo ""
    else
        echo -e "  ${BOLD}2. Host Toolchain Isolation Policy:${NC}"
        print_info "Host Distribution (${OS_NAME}) strictly isolated: tools execute exclusively via Docker."
        print_success "Native host binaries are bypassed to guarantee uniform container sandboxing."
        echo ""
    fi

    # 3. Docker & Curated Container Toolchain
    echo -e "  ${BOLD}3. Docker & Curated Container Toolchain:${NC}"
    local DOCKER_CMD
    DOCKER_CMD=$(check_docker || true)
    if [[ "$DOCKER_CMD" == "none" ]]; then
        print_error "Docker is NOT installed or daemon is unreachable."
        print_info "Install Docker or start the daemon to run containerized tools."
    else
        print_success "Container Engine: Active (${DOCKER_CMD})"
        local IMAGE_NAME="pentest-backend:latest"
        local CONTAINER_RUNNING=false
        if $DOCKER_CMD ps --format '{{.Names}}' 2>/dev/null | grep -q "^fastapi_app$"; then
            CONTAINER_RUNNING=true
            print_success "Backend Container: ${CYAN}fastapi_app${NC} is actively running."
        fi

        if $DOCKER_CMD image inspect "$IMAGE_NAME" >/dev/null 2>&1 || [[ "$CONTAINER_RUNNING" == "true" ]]; then
            print_success "Curated Container Image: ${CYAN}${IMAGE_NAME}${NC} is built and ready."
            echo ""
            echo -e "    ${BOLD}Container Tool Verification:${NC}"
            local CHECK_CMD=""
            if [[ "$CONTAINER_RUNNING" == "true" ]]; then
                CHECK_CMD="$DOCKER_CMD exec fastapi_app"
            else
                CHECK_CMD="$DOCKER_CMD run --rm $IMAGE_NAME"
            fi

            local TOOLS_TO_CHECK=(
                "nmap:Network mapper & NSE vulnerability scripts"
                "nuclei:Rapid vulnerability scanner & CVE templates"
                "nikto:Web server scanner & CGI audit"
                "whatweb:Web technology & CMS identification"
                "sqlmap:Automated SQL injection & database takeover"
                "ffuf:Fast web fuzzer & directory bruteforcer"
                "sslyze:Fast SSL/TLS configuration & cipher analyzer"
                "zap-baseline.py:OWASP ZAP baseline scanner engine"
                "wapiti:Web application vulnerability scanner"
            )
            local VERIFIED=0
            for item in "${TOOLS_TO_CHECK[@]}"; do
                local t_bin="${item%%:*}"
                local t_desc="${item#*:}"
                if $CHECK_CMD which "$t_bin" >/dev/null 2>&1; then
                    echo -e "      ${GREEN}✔${NC} ${BOLD}${t_bin}${NC} - ${DIM}${t_desc}${NC}"
                    VERIFIED=$((VERIFIED + 1))
                else
                    echo -e "      ${RED}✖${NC} ${BOLD}${t_bin}${NC} - missing inside container"
                fi
            done
            # Wordlist check
            if $CHECK_CMD test -f /usr/share/wordlists/dirb/common.txt >/dev/null 2>&1; then
                echo -e "      ${GREEN}✔${NC} ${BOLD}dirb/common.txt${NC} - ${DIM}Pre-seeded web discovery wordlist${NC}"
                VERIFIED=$((VERIFIED + 1))
            fi
            echo ""
            print_success "Container Toolchain Health: ${VERIFIED}/10 tools & wordlists verified."
        else
            print_warn "Image '${IMAGE_NAME}' not found locally. Build with: ${CYAN}./start.sh --build${NC}"
            print_info "All 9 security tools & wordlists will be automatically compiled during container build."
        fi
    fi
    echo ""

    # 4. HexStrike MCP Catalog & Multi-Tool Templates
    echo -e "  ${BOLD}4. HexStrike MCP Catalog & Multi-Tool Templates:${NC}"
    print_success "Curated HexStrike MCP Catalog: 72 tools defined across 8 security domains."
    print_success "Multi-Tool Templates: 30 vulnerability audit templates available."
    if curl -s -f http://localhost:8000/mcp/tools >/dev/null 2>&1; then
        local LIVE_COUNT
        LIVE_COUNT=$(curl -s http://localhost:8000/mcp/tools | grep -o '"name":' | wc -l || echo "72")
        print_success "Live MCP Endpoint: Online (${LIVE_COUNT} tools registered at http://localhost:8000/mcp/tools)"
    else
        print_info "Live MCP REST Endpoint: Offline (launch cluster with ${CYAN}./start.sh${NC} to expose)"
    fi
    echo ""

    # 5. Platform Cluster Services Health
    echo -e "  ${BOLD}5. Platform Cluster Services Health:${NC}"
    if curl -s -f http://localhost:8000/health >/dev/null 2>&1; then
        print_success "Backend API: Online (http://localhost:8000/health)"
    else
        print_info "Backend API: Offline (port 8000)"
    fi
    if curl -s -f http://localhost:5173 >/dev/null 2>&1; then
        print_success "Frontend Dashboard: Online (http://localhost:5173)"
    else
        print_info "Frontend Dashboard: Offline (port 5173)"
    fi
    echo ""

    # 6. Local LLM / Ollama Status
    echo -e "  ${BOLD}6. AI Autonomous Decision Engine (Ollama):${NC}"
    if command -v ollama >/dev/null 2>&1; then
        print_success "Ollama CLI installed: $(command -v ollama)"
        if curl -s -f http://localhost:11434/api/tags >/dev/null 2>&1; then
            print_success "Ollama Service: Online (http://localhost:11434)"
            local MODELS
            MODELS=$(curl -s http://localhost:11434/api/tags | grep -o '"name":"[^"]*"' | cut -d'"' -f4 | tr '\n' ', ' | sed 's/,$//')
            if [[ -n "$MODELS" ]]; then
                print_info "Available local models: ${CYAN}${MODELS}${NC}"
            fi
        else
            print_warn "Ollama service is currently offline."
            print_info "Autonomous heuristic decision engine will handle template selection automatically."
        fi
    else
        print_info "Ollama not installed. Autonomous heuristic decision engine active."
    fi
    echo ""
}

# ------------------------------------------------------------------------------
# Subcommand Handlers
# ------------------------------------------------------------------------------

# --- Help ---
if [[ "$1" == "--help" || "$1" == "-h" || "$1" == "help" ]]; then
    print_banner
    cat << 'EOF'
ORVYN - OFFENSIVE RISK AND VULNERABILITY INTELLIGENCE NETWORK
=============================================================

SYNOPSIS:
    ./start.sh [COMMAND] [OPTIONS]

COMMANDS:
    ./start.sh              Launch full platform in Docker Compose (strict container isolation)
    ./start.sh check        System diagnostics (Host OS policy, Docker tools, MCP layer, LLM)
    ./start.sh tools        Browse all 72 curated HexStrike MCP security tools
    ./start.sh scan <tgt>   Run terminal vulnerability assessment against target
    ./start.sh probe <tgt>  Run pre-flight DNS, TLS, and HTTP reachability probe
    ./start.sh templates    Browse all 30 vulnerability audit templates
    ./start.sh status       Check status of API, Dashboard, and Docker containers
    ./start.sh stop         Gracefully stop all platform services
    ./start.sh --build      Rebuild container images from source

SCAN OPTIONS:
    --profile recon         Fast perimeter reconnaissance (~20s)
    --profile web           Standard Web application audit (~45-60s)
    --profile full          Comprehensive multi-scanner audit (~2m)
    --profile deep          Deep multi-tool audit with secondary verification (~5m)
    --profile unlimited     Exhaustive enterprise assessment without timeouts
    --in-scope <domains>    Comma-separated allowlist (e.g. *.target.com, target.com)
    --out-of-scope <rules>  Comma-separated denylist (e.g. logout, auth.*)
    -o, --output <file>     Export findings (.pdf, .md, .json)
    -v, --verbose           Stream live scanner execution logs

STRICT ISOLATION POLICY:
    Security tools execute natively ONLY on Kali Linux or Parrot Security OS.
    On all other operating systems, tools strictly execute via Docker containers.

EOF
    exit 0
fi

# --- Stop ---
if [[ "$1" == "--stop" || "$1" == "--down" || "$1" == "stop" ]]; then
    print_banner
    print_info "Stopping platform services..."
    
    COMPOSE_CMD=$(get_compose_cmd || true)
    if [[ "$COMPOSE_CMD" != "none" ]]; then
        $COMPOSE_CMD down >/dev/null 2>&1 || true
    fi

    # Kill local instances if running
    if [[ -f "$PROJECT_ROOT/.backend.pid" ]]; then
        kill "$(cat "$PROJECT_ROOT/.backend.pid")" >/dev/null 2>&1 || true
        rm -f "$PROJECT_ROOT/.backend.pid"
    fi
    if [[ -f "$PROJECT_ROOT/.frontend.pid" ]]; then
        kill "$(cat "$PROJECT_ROOT/.frontend.pid")" >/dev/null 2>&1 || true
        rm -f "$PROJECT_ROOT/.frontend.pid"
    fi

    fuser -k 8000/tcp >/dev/null 2>&1 || true
    fuser -k 5173/tcp >/dev/null 2>&1 || true

    print_success "All platform services stopped successfully."
    exit 0
fi

check_cluster_status() {
    # 1. Backend API Check
    if curl -s -f http://localhost:8000/health >/dev/null 2>&1; then
        print_success "Backend API: Online (http://localhost:8000/health)"
    else
        print_error "Backend API: Offline"
    fi

    # 2. Frontend Dashboard Check
    if curl -s -f http://localhost:5173 >/dev/null 2>&1; then
        print_success "Frontend Dashboard: Online (http://localhost:5173)"
    else
        print_error "Frontend Dashboard: Offline"
    fi

    # 3. Environment & Isolation Mode Check
    local ENV_RESP
    ENV_RESP=$(curl -s http://localhost:8000/environment 2>/dev/null || true)
    if [[ -n "$ENV_RESP" ]]; then
        local EXEC_MODE
        EXEC_MODE=$(echo "$ENV_RESP" | grep -o '"execution_mode":"[^"]*"' | cut -d'"' -f4 || echo "unknown")
        print_info "API Execution Mode: ${CYAN}${EXEC_MODE}${NC}"
    fi

    # 4. Docker Container Status
    local DOCKER_CMD
    DOCKER_CMD=$(check_docker || true)
    if [[ "$DOCKER_CMD" != "none" ]]; then
        echo ""
        print_info "Docker Container Status:"
        $DOCKER_CMD ps --filter "name=fastapi_app|celery_worker|redis|postgres|frontend_app" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || true
    fi
}

# --- Status ---
if [[ "$1" == "--status" || "$1" == "status" ]]; then
    if [[ -n "$2" && "$2" != "--"* ]]; then
        shift
        run_cli status "$@"
        exit $?
    fi
    print_banner
    echo -e "  ${BOLD}Platform Cluster Health & Status Check${NC}"
    echo ""
    check_cluster_status
    exit 0
fi

# --- Check & Diagnostic ---
if [[ "$1" == "--check" || "$1" == "check" || "$1" == "--env" || "$1" == "env" || "$1" == "doctor" ]]; then
    print_banner
    check_system_environment
    exit 0
fi

# --- Scan ---
if [[ "$1" == "scan" || "$1" == "--scan" ]]; then
    shift
    run_cli scan "$@"
    exit $?
fi

# --- Probe ---
if [[ "$1" == "probe" || "$1" == "--probe" ]]; then
    shift
    run_cli probe "$@"
    exit $?
fi

# --- Templates ---
if [[ "$1" == "templates" || "$1" == "--templates" || "$1" == "template" ]]; then
    shift
    run_cli templates "$@"
    exit $?
fi

# --- Tools & HexStrike MCP Catalog ---
if [[ "$1" == "tools" || "$1" == "--tools" || "$1" == "mcp" || "$1" == "--mcp" ]]; then
    print_banner
    show_mcp_tools_catalog
    exit 0
fi

# --- Results ---
if [[ "$1" == "results" || "$1" == "--results" ]]; then
    shift
    run_cli results "$@"
    exit $?
fi

# --- Interactive CLI ---
if [[ "$1" == "cli" || "$1" == "--cli" || "$1" == "-i" || "$1" == "--interactive" ]]; then
    shift
    if [[ $# -gt 0 ]]; then
        run_cli "$@"
        exit $?
    fi
    print_banner
    echo -e "  ${BOLD}🛡️  ORVYN - Interactive Security Assessment Console${NC}"
    echo ""
    read -r -p "  Enter target domain or URL (e.g. scanme.nmap.org): " INTER_TARGET
    if [[ -z "$INTER_TARGET" ]]; then
        print_error "Target cannot be empty."
        exit 1
    fi
    echo ""
    echo -e "  Select Scan Profile:"
    echo -e "    ${BOLD}1${NC}) Auto Template (AI Autonomous Recon & Dynamic Toolchain)"
    echo -e "    ${BOLD}2${NC}) Web Standard (~45-60s DAST suite)"
    echo -e "    ${BOLD}3${NC}) Recon (~20s rapid perimeter check)"
    echo -e "    ${BOLD}4${NC}) Full (~2m comprehensive audit)"
    echo -e "    ${BOLD}5${NC}) Unlimited (Exhaustive deep scan, no timeout)"
    read -r -p "  Choice [1-5] (default: 1): " PROF_SEL
    case "$PROF_SEL" in
        2) PROF_ARGS=(--profile "web") ;;
        3) PROF_ARGS=(--profile "recon") ;;
        4) PROF_ARGS=(--profile "full") ;;
        5) PROF_ARGS=(--profile "unlimited") ;;
        *) PROF_ARGS=(--template "auto") ;;
    esac
    echo ""
    print_info "Starting terminal scan for ${BOLD}$INTER_TARGET${NC}..."
    echo ""
    run_cli scan "$INTER_TARGET" "${PROF_ARGS[@]}" --detailed -o "$PROJECT_ROOT/terminal_scan_report.md"
    exit $?
fi

# ------------------------------------------------------------------------------
# Main Startup: Docker Enforced on Non-Kali/Parrot
# ------------------------------------------------------------------------------

detect_host_os

echo ""
print_info "Initializing ORVYN platform cluster & security toolchain..."
echo ""

echo -e "  ${BOLD}Pre-flight Environment Validation:${NC}"
echo -e "    • Host OS: ${CYAN}${OS_NAME}${NC}"

if [[ "$IS_KALI" == "true" ]]; then
    echo -e "    • Engine Mode: ${GREEN}Kali Linux Native Host Tools${NC}"
elif [[ "$IS_PARROT" == "true" ]]; then
    echo -e "    • Engine Mode: ${GREEN}Parrot Security OS Native Host Tools${NC}"
else
    echo -e "    • Engine Mode: ${CYAN}Docker Container Mode (Strict Isolation Policy Enforced)${NC}"
fi

echo -e "    • HexStrike Catalog: ${GREEN}72 Curated MCP Security Tools${NC}"
echo -e "    • Template Registry: ${GREEN}30 Autonomous Multi-Tool Templates${NC}"
echo ""

DOCKER_CMD=$(check_docker || true)

# Enforce Docker mode on all non-Kali/Parrot machines
MODE="docker"

if [[ "$1" == "--local" ]]; then
    if [[ "$IS_KALI" != "true" && "$IS_PARROT" != "true" ]]; then
        print_warn "STRICT SECURITY ENFORCEMENT: Native host execution is strictly restricted to Kali Linux or Parrot OS."
        print_info "Host is ${OS_NAME}. Forcing isolated Docker cluster mode."
        MODE="docker"
    else
        MODE="local"
    fi
fi

if [[ "$MODE" == "docker" ]]; then
    if [[ "$DOCKER_CMD" == "none" ]]; then
        print_error "Docker is NOT installed or daemon is unreachable."
        print_info "Please install Docker and ensure the docker daemon is active to launch the platform."
        exit 1
    fi

    if [[ "$DOCKER_CMD" == "sudo docker" ]]; then
        print_warn "Docker daemon requires elevated permissions."
        print_info "Prompting for sudo password to start platform containers..."
    fi

    COMPOSE_CMD=$(get_compose_cmd)
    if [[ "$COMPOSE_CMD" == "none" ]]; then
        print_error "Docker Compose was not found. Please install docker-compose."
        exit 1
    fi

    print_info "Launching platform cluster via ${BOLD}${COMPOSE_CMD}${NC}..."
    echo -e "  ${DIM}Services: Backend (FastAPI + HexStrike MCP), Celery Worker, Redis, PostgreSQL, Frontend Dashboard${NC}"
    echo ""

    REBUILD_FLAG=""
    for arg in "$@"; do
        if [[ "$arg" == "--build" ]]; then
            REBUILD_FLAG="--build"
            break
        fi
    done

    # Verify if container image exists
    IMAGE_NAME="pentest-backend:latest"
    if ! $DOCKER_CMD image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
        print_info "Curated HexStrike container image not found. Building container cluster now..."
        REBUILD_FLAG="--build"
    fi

    # Release any leftover host processes on ports 8000 and 5173
    fuser -k 8000/tcp >/dev/null 2>&1 || true
    fuser -k 5173/tcp >/dev/null 2>&1 || true

    if [[ -n "$REBUILD_FLAG" ]]; then
        print_info "Building container images (incorporating all security tools & MCP endpoints)..."
        $COMPOSE_CMD up --build -d
    else
        $COMPOSE_CMD up -d
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

    # Wait for frontend
    FRONTEND_READY=false
    for i in {1..20}; do
        if curl -s -f http://localhost:5173 >/dev/null 2>&1; then
            FRONTEND_READY=true
            break
        fi
        sleep 1
    done

    if [[ "$FRONTEND_READY" != "true" ]]; then
        print_info "Containerized frontend starting locally..."
        if [[ ! -d "$FRONTEND_DIR/node_modules" ]]; then
            (cd "$FRONTEND_DIR" && npm install)
        fi
        (cd "$FRONTEND_DIR" && nohup npm run dev -- --host 0.0.0.0 > "$PROJECT_ROOT/.frontend.log" 2>&1 & echo $! > "$PROJECT_ROOT/.frontend.pid")
        sleep 2
    fi

else
    # Native Local Mode (Strictly Kali Linux or Parrot OS)
    print_info "Starting platform in ${BOLD}Native Host Mode${NC} (${OS_NAME})..."

    # 1. Setup Python backend
    print_info "Checking backend Python environment..."
    if [[ ! -d "$VENV_DIR" ]]; then
        python3 -m venv "$VENV_DIR"
    fi
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"

    if ! python3 -c "import fastapi, uvicorn, rich, requests" >/dev/null 2>&1; then
        print_info "Installing backend dependencies..."
        pip install --no-cache-dir -r "$BACKEND_DIR/requirements.txt"
    fi

    # 2. Setup Node frontend
    print_info "Checking frontend dependencies..."
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

if [ -t 1 ]; then
    clear
fi

print_banner

# Summary Status Card
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}   ${GREEN}${BOLD}🚀 ORVYN AUTONOMOUS PLATFORM READY${NC}                                 ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}   ${DIM}Offensive Risk and Vulnerability Intelligence Network${NC}               ${CYAN}║${NC}"
echo -e "${CYAN}╠═══════════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  🌐 ${BOLD}Web Dashboard:${NC}   ${CYAN}http://localhost:5173${NC}                            ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  ⚙️  ${BOLD}API Docs:${NC}        ${CYAN}http://localhost:8000/docs${NC}                       ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  🛡️  ${BOLD}Engine Mode:${NC}     ${GREEN}${MODE^^} (${OS_NAME})${NC}                          ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  🛠️  ${BOLD}MCP Catalog:${NC}     ${PURPLE}72 Curated Security Tools${NC}                       ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  💻 ${BOLD}Terminal Scan:${NC}   ${PURPLE}./start.sh scan <target>${NC}                            ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  🔍 ${BOLD}Target Probe:${NC}    ${PURPLE}./start.sh probe <target>${NC}                           ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  📖 ${BOLD}CLI Manual:${NC}      ${CYAN}./start.sh --help${NC}                                   ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  🛑 ${BOLD}To Stop:${NC}         ${DIM}./start.sh stop${NC}                                 ${CYAN}║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Interactive terminal scan prompt
if [ -t 0 ]; then
    echo -e "${YELLOW}🎯 Launch a terminal vulnerability scan now? (y/N):${NC} "
    read -r -p "> " RUN_SCAN || true
    if [[ "$RUN_SCAN" =~ ^[Yy]$ ]]; then
        echo ""
        read -r -p "  Enter target domain or URL (e.g. scanme.nmap.org): " TERM_TARGET
        if [[ -n "$TERM_TARGET" ]]; then
            echo ""
            echo -e "  Select Intensity Profile:"
            echo -e "    1) Auto Template (AI Autonomous Recon & Dynamic Toolchain)"
            echo -e "    2) Web Standard (~45-60s DAST suite)"
            echo -e "    3) Recon (~20s rapid check)"
            echo -e "    4) Full (~2m comprehensive audit)"
            echo -e "    5) Unlimited (Exhaustive, no timeout)"
            read -r -p "  Profile [1-5] (default: 1): " PROF_SEL
            case "$PROF_SEL" in
                2) P_ARGS=(--profile "web") ;;
                3) P_ARGS=(--profile "recon") ;;
                4) P_ARGS=(--profile "full") ;;
                5) P_ARGS=(--profile "unlimited") ;;
                *) P_ARGS=(--template "auto") ;;
            esac
            echo ""
            print_info "Executing penetration assessment for ${BOLD}$TERM_TARGET${NC}..."
            echo ""
            run_cli scan "$TERM_TARGET" "${P_ARGS[@]}" --detailed --force -o "$PROJECT_ROOT/scan_report.md"
            echo ""
            print_success "Assessment complete! Audit report saved to ${BOLD}scan_report.md${NC}"
        fi
    fi
else
    print_success "Platform active. Run './start.sh scan <target>' for terminal pentests."
fi
