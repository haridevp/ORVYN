from abc import ABC, abstractmethod
import os
from pathlib import Path
import shutil
import sys
from typing import Callable, Optional

# Ensure local venv and user go/local binary directories are on PATH
_extra_bins = [
    str(Path(sys.prefix) / "bin"),
    str(Path.home() / "go" / "bin"),
    str(Path.home() / ".local" / "bin"),
    "/usr/local/bin",
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
        return bool(self.binary and shutil.which(self.binary))

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
