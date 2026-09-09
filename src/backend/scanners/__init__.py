from schemas import ScannerName
from scanners.base import ScannerWrapper
from scanners.ffuf import FfufWrapper
from scanners.nikto import NiktoWrapper
from scanners.nmap import NmapWrapper
from scanners.nuclei import NucleiWrapper
from scanners.sqlmap import SqlmapWrapper
from scanners.sslyze import SSLyzeWrapper
from scanners.wapiti import WapitiWrapper
from scanners.whatweb import WhatWebWrapper
from scanners.zap import ZapWrapper

REGISTRY: dict[ScannerName, ScannerWrapper] = {
    ScannerName.nuclei: NucleiWrapper(),
    ScannerName.zap: ZapWrapper(),
    ScannerName.nikto: NiktoWrapper(),
    ScannerName.whatweb: WhatWebWrapper(),
    ScannerName.nmap: NmapWrapper(),
    ScannerName.sslyze: SSLyzeWrapper(),
    ScannerName.wapiti: WapitiWrapper(),
    ScannerName.sqlmap: SqlmapWrapper(),
    ScannerName.ffuf: FfufWrapper(),
}

__all__ = ["REGISTRY", "ScannerWrapper"]
