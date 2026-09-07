from schemas import ScannerName
from scanners.base import ScannerWrapper
from scanners.nikto import NiktoWrapper
from scanners.nuclei import NucleiWrapper
from scanners.zap import ZapWrapper

REGISTRY: dict[ScannerName, ScannerWrapper] = {
    ScannerName.nuclei: NucleiWrapper(),
    ScannerName.zap: ZapWrapper(),
    ScannerName.nikto: NiktoWrapper(),
}

__all__ = ["REGISTRY", "ScannerWrapper"]
