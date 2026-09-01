import hashlib
from typing import List, Dict
from schemas import ScannerFinding

class ScanComparisonEngine:
    def __init__(self):
        pass

    def compute_hash(self, finding: ScannerFinding) -> str:
        # hash = sha256(target + vulnerability + tool)
        raw = f"{finding.target}{finding.vulnerability}{finding.tool}"
        return hashlib.sha256(raw.encode('utf-8')).hexdigest()

    def compare_scans(self, previous_findings: List[ScannerFinding], current_findings: List[ScannerFinding]) -> Dict[str, List[ScannerFinding]]:
        prev_map = {self.compute_hash(f): f for f in previous_findings}
        curr_map = {self.compute_hash(f): f for f in current_findings}
        
        persistent = []
        resolved = []
        new = []
        
        for h, f in curr_map.items():
            if h in prev_map:
                persistent.append(f)
            else:
                new.append(f)
                
        for h, f in prev_map.items():
            if h not in curr_map:
                resolved.append(f)
                
        return {
            "persistent": persistent,
            "resolved": resolved,
            "new": new
        }
