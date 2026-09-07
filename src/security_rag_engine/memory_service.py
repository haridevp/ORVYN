import hashlib
import re
from typing import List, Dict, Optional, Tuple
from sqlalchemy.orm import Session
from models_db import Target, ScanRun, VulnerabilityFinding
from schemas import ScannerFinding, ScanRunRecord, ScanSummary, FindingSummary, DeltaReport

def normalize_evidence(evidence: Optional[str]) -> str:
    if not evidence:
        return ""
    # Strip whitespaces and normalize for fingerprinting
    return re.sub(r'\s+', '', evidence).lower()

def compute_fingerprint(target: str, tool: str, vulnerability_title: str, evidence: Optional[str]) -> str:
    norm_evidence = normalize_evidence(evidence)
    raw = f"{target}|{tool}|{vulnerability_title}|{norm_evidence}"
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()

class MemoryService:
    def __init__(self, db: Session):
        self.db = db

    def get_or_create_target(self, name: str) -> Target:
        target = self.db.query(Target).filter(Target.name == name).first()
        if not target:
            target = Target(name=name)
            self.db.add(target)
            self.db.commit()
            self.db.refresh(target)
        return target

    def record_scan(self, record: ScanRunRecord) -> ScanRun:
        target = self.get_or_create_target(record.target)
        
        scan_run = ScanRun(
            scan_id=record.scan_id,
            target_id=target.id,
            scanner_tools_used=record.scanner_tools_used
        )
        self.db.add(scan_run)
        self.db.commit()
        self.db.refresh(scan_run)

        previous_scan = self.db.query(ScanRun).filter(
            ScanRun.target_id == target.id, 
            ScanRun.id < scan_run.id
        ).order_by(ScanRun.id.desc()).first()

        prev_fingerprints = set()
        if previous_scan:
            prev_fingerprints = {f.fingerprint for f in previous_scan.findings if f.status != "Resolved"}

        finding_models = []
        for finding in record.findings:
            fp = compute_fingerprint(record.target, finding.tool, finding.vulnerability, finding.evidence)
            status = "Persistent" if fp in prev_fingerprints else "New"
            
            fm = VulnerabilityFinding(
                scan_run_id=scan_run.id,
                fingerprint=fp,
                tool=finding.tool,
                vulnerability_title=finding.vulnerability,
                severity=finding.severity,
                description=finding.description,
                evidence=finding.evidence,
                reference=finding.reference,
                status=status
            )
            finding_models.append(fm)
            
        curr_fingerprints = {compute_fingerprint(record.target, f.tool, f.vulnerability, f.evidence) for f in record.findings}
        
        if previous_scan:
            for prev_f in previous_scan.findings:
                if prev_f.status != "Resolved" and prev_f.fingerprint not in curr_fingerprints:
                    res_fm = VulnerabilityFinding(
                        scan_run_id=scan_run.id,
                        fingerprint=prev_f.fingerprint,
                        tool=prev_f.tool,
                        vulnerability_title=prev_f.vulnerability_title,
                        severity=prev_f.severity,
                        description=prev_f.description,
                        evidence=prev_f.evidence,
                        reference=prev_f.reference,
                        status="Resolved"
                    )
                    finding_models.append(res_fm)

        self.db.add_all(finding_models)
        self.db.commit()
        
        return scan_run

    def get_timeline(self, target_name: str) -> List[ScanSummary]:
        target = self.db.query(Target).filter(Target.name == target_name).first()
        if not target:
            return []
            
        timeline = []
        for run in sorted(target.scan_runs, key=lambda x: x.timestamp, reverse=True):
            summary = ScanSummary(
                scan_id=run.scan_id,
                timestamp=run.timestamp.isoformat(),
                scanner_tools_used=run.scanner_tools_used,
                total_findings=len(run.findings),
                findings_summary=[
                    FindingSummary(vulnerability_title=f.vulnerability_title, severity=f.severity, status=f.status)
                    for f in run.findings
                ]
            )
            timeline.append(summary)
        return timeline

    def compare_scans(self, prev_scan_id: str, current_scan_id: str) -> DeltaReport:
        prev_run = self.db.query(ScanRun).filter(ScanRun.scan_id == prev_scan_id).first()
        curr_run = self.db.query(ScanRun).filter(ScanRun.scan_id == current_scan_id).first()
        
        if not prev_run or not curr_run:
            raise ValueError("Scan run not found")
            
        target = curr_run.target.name
        
        prev_findings = {f.fingerprint: f for f in prev_run.findings if f.status != "Resolved"}
        curr_findings = {f.fingerprint: f for f in curr_run.findings if f.status != "Resolved"}
        
        new_fps = set(curr_findings.keys()) - set(prev_findings.keys())
        persistent_fps = set(curr_findings.keys()) & set(prev_findings.keys())
        resolved_fps = set(prev_findings.keys()) - set(curr_findings.keys())
        
        def to_scanner_finding(f):
            return ScannerFinding(
                tool=f.tool,
                target=target,
                vulnerability=f.vulnerability_title,
                severity=f.severity,
                description=f.description,
                evidence=f.evidence,
                reference=f.reference
            )
            
        new_list = [to_scanner_finding(curr_findings[fp]) for fp in new_fps]
        persistent_list = [to_scanner_finding(curr_findings[fp]) for fp in persistent_fps]
        resolved_list = [to_scanner_finding(prev_findings[fp]) for fp in resolved_fps]
        
        summary = {
            "new": len(new_list),
            "persistent": len(persistent_list),
            "resolved": len(resolved_list)
        }
        
        return DeltaReport(
            target=target,
            previous_scan_id=prev_scan_id,
            current_scan_id=current_scan_id,
            new_findings=new_list,
            persistent_findings=persistent_list,
            resolved_findings=resolved_list,
            summary=summary
        )

    def diff_last_two_scans(self, target_name: str) -> DeltaReport:
        target = self.db.query(Target).filter(Target.name == target_name).first()
        if not target or len(target.scan_runs) < 2:
            raise ValueError("Not enough scans to diff")
            
        runs = sorted(target.scan_runs, key=lambda x: x.timestamp, reverse=True)
        return self.compare_scans(runs[1].scan_id, runs[0].scan_id)
