"""Environment and Host OS Detection Engine.

Automatically detects whether the platform is running on:
- Kali Linux (native host tool execution)
- Parrot Security OS (native host tool execution)
- Generic Linux / Docker container
- Local development with fallback to simulated engine
"""

from enum import Enum
import os
from pathlib import Path
import shutil
import subprocess
from typing import Optional
from pydantic import BaseModel, Field


class ExecutionMode(str, Enum):
    NATIVE_KALI = "native_kali"
    NATIVE_PARROT = "native_parrot"
    NATIVE_LINUX = "native_linux"
    DOCKERIZED_MCP = "dockerized_mcp"
    SIMULATED = "simulated"


SECURITY_TOOLS = [
    "nmap",
    "nuclei",
    "nikto",
    "whatweb",
    "sslyze",
    "wapiti",
    "zap",
    "ffuf",
    "gobuster",
    "sqlmap",
]


class EnvironmentInfo(BaseModel):
    os_id: str = "unknown"
    os_name: str = "Unknown OS"
    is_kali: bool = False
    is_parrot: bool = False
    is_docker: bool = False
    docker_available: bool = False
    execution_mode: ExecutionMode = ExecutionMode.SIMULATED
    available_tools: list[str] = Field(default_factory=list)
    missing_tools: list[str] = Field(default_factory=list)
    description: str = ""


def _parse_os_release() -> dict[str, str]:
    """Parse /etc/os-release key-value pairs."""
    os_info: dict[str, str] = {}
    os_release_path = Path("/etc/os-release")
    if not os_release_path.exists():
        return os_info

    try:
        with open(os_release_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                os_info[key.strip()] = val.strip().strip('"').strip("'")
    except Exception:
        pass

    return os_info


def _is_inside_docker() -> bool:
    """Check if process is currently executing inside a Docker container."""
    if Path("/.dockerenv").exists():
        return True
    try:
        cgroup_path = Path("/proc/1/cgroup")
        if cgroup_path.exists():
            content = cgroup_path.read_text(encoding="utf-8", errors="ignore")
            if "docker" in content or "kubepods" in content or "containerd" in content:
                return True
    except Exception:
        pass
    return False


def _is_docker_available() -> bool:
    """Check if docker binary and daemon are accessible on host."""
    docker_bin = shutil.which("docker")
    if not docker_bin:
        return False
    try:
        res = subprocess.run(
            [docker_bin, "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )
        return res.returncode == 0
    except Exception:
        return False


def detect_environment() -> EnvironmentInfo:
    """Detect host OS, installed security binaries, and execution mode."""
    os_data = _parse_os_release()
    os_id = os_data.get("ID", "").lower()
    id_like = os_data.get("ID_LIKE", "").lower()
    pretty_name = os_data.get("PRETTY_NAME", os_data.get("NAME", "Linux Host"))

    is_kali = os_id == "kali" or "kali" in id_like
    is_parrot = os_id == "parrot" or "parrot" in id_like
    is_docker = _is_inside_docker()
    docker_available = _is_docker_available()

    # Detect installed tools on PATH
    available_tools: list[str] = []
    missing_tools: list[str] = []
    for tool in SECURITY_TOOLS:
        if shutil.which(tool):
            available_tools.append(tool)
        else:
            missing_tools.append(tool)

    # Determine execution mode
    if is_kali and len(available_tools) >= 2:
        mode = ExecutionMode.NATIVE_KALI
        desc = f"Kali Linux detected ({len(available_tools)}/{len(SECURITY_TOOLS)} security tools available natively on host)"
    elif is_parrot and len(available_tools) >= 2:
        mode = ExecutionMode.NATIVE_PARROT
        desc = f"Parrot Security OS detected ({len(available_tools)}/{len(SECURITY_TOOLS)} security tools available natively on host)"
    elif len(available_tools) >= 3:
        mode = ExecutionMode.NATIVE_LINUX
        desc = f"Host Linux detected with native tools: {', '.join(available_tools)}"
    elif docker_available or is_docker:
        mode = ExecutionMode.DOCKERIZED_MCP
        desc = "Curated HexStrike MCP container mode (tools executed via isolated Docker containers)"
    else:
        mode = ExecutionMode.SIMULATED
        desc = "Development simulation mode with realistic security telemetry"

    return EnvironmentInfo(
        os_id=os_id or "generic",
        os_name=pretty_name,
        is_kali=is_kali,
        is_parrot=is_parrot,
        is_docker=is_docker,
        docker_available=docker_available,
        execution_mode=mode,
        available_tools=available_tools,
        missing_tools=missing_tools,
        description=desc,
    )
