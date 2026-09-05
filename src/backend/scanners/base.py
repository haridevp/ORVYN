from abc import ABC, abstractmethod

from schemas import ScannerFinding, ScannerName


class ScannerWrapper(ABC):
    """Common interface every scanner integration must implement.

    Module 2 Member 2/3 can drop in a real implementation of `run()` per
    scanner (Nuclei/ZAP/Nikto/OpenVAS/...) without touching the job manager,
    correlation engine, or API layer - they all speak `ScannerFinding`.
    """

    name: ScannerName

    @abstractmethod
    async def run(self, target: str, profile: str) -> list[ScannerFinding]:
        """Execute the scan and return findings already in the unified schema."""
        raise NotImplementedError
