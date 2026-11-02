"""Environment and Host OS Detection Engine.

Automatically detects whether the platform is running on:
- Kali Linux (native host tool execution)
- Parrot Security OS (native host tool execution)
- Generic Linux / Docker container
- Host Linux standalone tool discovery and execution
"""

from enum import Enum
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Optional
from pydantic import BaseModel, Field

_repo_root = Path(__file__).resolve().parents[2]
_extra_bins = [
    str(_repo_root / ".venv" / "bin"),
    str(_repo_root / ".venv-backend" / "bin"),
    str(_repo_root / "src" / "backend" / ".venv" / "bin"),
    str(Path(sys.prefix) / "bin"),
    str(Path.home() / "go" / "bin"),
    str(Path.home() / ".local" / "bin"),
    "/usr/local/bin",
    "/zap",
    "/opt/nikto/program",
    "/opt/venv/bin",
]
_current_path = os.environ.get("PATH", "")
for _bin_path in _extra_bins:
    if _bin_path not in _current_path.split(os.pathsep):
        _current_path = f"{_bin_path}{os.pathsep}{_current_path}"
os.environ["PATH"] = _current_path


class ExecutionMode(str, Enum):
    NATIVE_KALI = "native_kali"
    NATIVE_PARROT = "native_parrot"
    NATIVE_LINUX = "native_linux"
    DOCKERIZED_MCP = "dockerized_mcp"


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
    execution_mode: ExecutionMode = ExecutionMode.NATIVE_LINUX
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
    """Check if process is currently executing inside a Docker or Podman container."""
    if Path("/.dockerenv").exists() or Path("/run/.containerenv").exists():
        return True
    if os.environ.get("IS_DOCKER", "").lower() in ("true", "1") or os.environ.get("CONTAINER", "").lower() in ("docker", "podman", "containerd"):
        return True
    # Container signature: pentest-backend image uniquely has /zap and /opt/nikto installed
    if Path("/zap").is_dir() and (Path("/opt/nikto").is_dir() or Path("/usr/local/bin/nikto").exists()):
        return True
    try:
        cgroup_path = Path("/proc/1/cgroup")
        if cgroup_path.exists():
            content = cgroup_path.read_text(encoding="utf-8", errors="ignore")
            if "docker" in content or "kubepods" in content or "containerd" in content or "libpod" in content:
                return True
    except Exception:
        pass
    try:
        self_cgroup = Path("/proc/self/cgroup")
        if self_cgroup.exists():
            content = self_cgroup.read_text(encoding="utf-8", errors="ignore")
            if "docker" in content or "kubepods" in content or "containerd" in content or "libpod" in content:
                return True
    except Exception:
        pass
    return False


def get_container_cli() -> Optional[str]:
    """Get the functional container CLI binary ('docker' or 'podman')."""
    # Test which container engine actually has active daemon/socket access
    for cli in ("docker", "podman"):
        bin_path = shutil.which(cli)
        if not bin_path:
            continue
        try:
            res = subprocess.run(
                [bin_path, "info"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
            if res.returncode == 0:
                return cli
        except Exception:
            pass

    # Fallback to whichever is installed on PATH
    for cli in ("podman", "docker"):
        if shutil.which(cli):
            return cli
    return None


def _is_docker_available() -> bool:
    """Check if docker or podman binary and daemon are accessible on host."""
    for cli in ("docker", "podman"):
        bin_path = shutil.which(cli)
        if not bin_path:
            continue
        try:
            res = subprocess.run(
                [bin_path, "info"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
            if res.returncode == 0:
                return True
        except Exception:
            pass
    return False


def detect_environment() -> EnvironmentInfo:
    """Detect host OS, installed security binaries, and execution mode.
    
    STRICT POLICY: Native host execution is strictly restricted to Kali Linux
    and Parrot Security OS. On all other operating systems, tools are strictly
    isolated and executed via Docker/Podman container mode.
    """
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
        if shutil.which(tool) or (tool == "zap" and (shutil.which("zap-baseline.py") or shutil.which("zap.sh"))):
            available_tools.append(tool)
        else:
            missing_tools.append(tool)

    # Determine execution mode (STRICT: Docker only unless Kali or Parrot)
    if is_kali and len(available_tools) >= 1:
        mode = ExecutionMode.NATIVE_KALI
        desc = f"Kali Linux detected ({len(available_tools)}/{len(SECURITY_TOOLS)} security tools available natively on host)"
    elif is_parrot and len(available_tools) >= 1:
        mode = ExecutionMode.NATIVE_PARROT
        desc = f"Parrot Security OS detected ({len(available_tools)}/{len(SECURITY_TOOLS)} security tools available natively on host)"
    elif is_docker:
        mode = ExecutionMode.DOCKERIZED_MCP
        desc = "Running inside isolated container environment"
    else:
        # Strict isolation: Any other host OS (Fedora, Ubuntu, Debian, macOS, etc.)
        mode = ExecutionMode.DOCKERIZED_MCP
        container_cli = get_container_cli() or "docker"
        desc = f"{pretty_name} detected. Strict isolation enforced: tools execute exclusively via {container_cli.capitalize()} container."

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
