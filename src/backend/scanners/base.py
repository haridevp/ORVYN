from abc import ABC, abstractmethod
import os
from pathlib import Path
import shutil
import sys
from typing import Callable, Optional

# Ensure local venv and user go/local binary directories are on PATH
_repo_root = Path(__file__).resolve().parents[3]
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

from schemas import ScannerFinding, ScannerName


class ScannerWrapper(ABC):
    """Common interface every scanner integration must implement.

    Module 2 Member 2/3 can drop in a real implementation of `run()` per
    scanner (Nuclei/ZAP/Nikto/OpenVAS/...) without touching the job manager,
    correlation engine, or API layer - they all speak `ScannerFinding`.
    """

    name: ScannerName
    binary: str = ""

    def is_available(self) -> bool:
        from environment import detect_environment, ExecutionMode, get_container_cli
        env = detect_environment()
        is_kali_or_parrot = env.execution_mode in (ExecutionMode.NATIVE_KALI, ExecutionMode.NATIVE_PARROT)
        if is_kali_or_parrot or env.is_docker:
            return bool(self.binary and shutil.which(self.binary))
        container_cli = get_container_cli()
        return bool(container_cli or (self.binary and shutil.which(self.binary)))

    def build_execution_command(self, args: list[str]) -> list[str]:
        """Build command respecting strict Docker execution on non-Kali/Parrot OS."""
        from environment import detect_environment, ExecutionMode, get_container_cli
        env = detect_environment()
        is_kali_or_parrot = env.execution_mode in (ExecutionMode.NATIVE_KALI, ExecutionMode.NATIVE_PARROT)
        if is_kali_or_parrot or env.is_docker:
            return [self.binary] + args

        # Strict isolation: run via Docker or Podman
        container_cli = get_container_cli() or "docker"
        docker_image = os.environ.get("HEXSTRIKE_DOCKER_IMAGE", "pentest-backend:latest")
        return [
            container_cli,
            "run",
            "--rm",
            "--network",
            "host",
            docker_image,
            self.binary,
        ] + args

    @abstractmethod
    async def run(
        self,
        target: str,
        profile: str,
        in_scope: Optional[list[str]] = None,
        out_of_scope: Optional[list[str]] = None,
        log_cb: Optional[Callable[[str], None]] = None,
        finding_cb: Optional[Callable[[ScannerFinding], None]] = None,
    ) -> list[ScannerFinding]:
        """Execute the scan and return findings already in the unified schema."""
        raise NotImplementedError
