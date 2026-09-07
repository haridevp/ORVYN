from abc import ABC, abstractmethod
import shutil
from typing import Callable, Optional

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
        log_cb: Optional[Callable[[str], None]] = None,
    ) -> list[ScannerFinding]:
        """Execute the scan and return findings already in the unified schema."""
        raise NotImplementedError
