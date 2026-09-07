"""Scan job management: launches scanners concurrently, tracks per-scanner
status, captures live verbose logs, stores results, and never lets one
scanner's failure sink the job.
"""

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

from correlation import correlate_findings, duplicate_group_count, severity_distribution
from scanners import REGISTRY
from schemas import (
    ScannerFinding,
    ScannerName,
    ScannerProgress,
    ScannerRunState,
    ScanResultsResponse,
    ScanStartRequest,
    ScanStatusResponse,
    now_iso,
)


def is_item_in_scope(item_target: str, in_scope: list[str], out_of_scope: list[str]) -> bool:
    """Verify whether a finding target/evidence complies with configured scope boundaries."""
    lowered = item_target.lower()

    # 1. Deny-list check: out_of_scope exclusions take absolute priority
    for rule in out_of_scope:
        rule_clean = rule.strip().lower().lstrip("*.")
        if rule_clean and rule_clean in lowered:
            return False

    # 2. Allow-list check: if in_scope rules are defined, target must match at least one
    if in_scope:
        matched = False
        for rule in in_scope:
            rule_clean = rule.strip().lower()
            if not rule_clean or rule_clean == "*":
                matched = True
                break
            if rule_clean.startswith("*."):
                domain_part = rule_clean[2:]
                if domain_part in lowered:
                    matched = True
                    break
            elif rule_clean in lowered:
                matched = True
                break
        if not matched:
            return False

    return True


class ScanJob:
    def __init__(self, scan_id: str, request: ScanStartRequest):
        self.scan_id = scan_id
        self.target = request.target
        self.profile = request.profile
        # Default in_scope to wildcard domain if not specified: e.g. *.target.com
        target_domain = request.target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        self.in_scope = request.in_scope if request.in_scope else [f"*.{target_domain}", request.target]
        self.out_of_scope = request.out_of_scope if request.out_of_scope else []
        self.created_at = now_iso()
        self.updated_at = self.created_at
        self.scanner_progress: dict[ScannerName, ScannerProgress] = {
            tool: ScannerProgress(tool=tool, status=ScannerRunState.queued)
            for tool in request.scanners
        }
        self.findings: list[ScannerFinding] = []
        self.logs: list[str] = []

    def add_log(self, tool: ScannerName | str, message: str) -> None:
        tool_name = tool.value if hasattr(tool, "value") else str(tool)
        timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        self.logs.append(f"[{timestamp}] [{tool_name}] {message}")
        self.updated_at = now_iso()

    @property
    def overall_status(self) -> str:
        states = [p.status for p in self.scanner_progress.values()]
        if any(s == ScannerRunState.error for s in states) and all(
            s in (ScannerRunState.completed, ScannerRunState.error) for s in states
        ):
            return "error" if all(s == ScannerRunState.error for s in states) else "completed"
        if all(s == ScannerRunState.completed for s in states):
            return "completed"
        if any(s == ScannerRunState.running for s in states):
            return "running"
        return "queued"

    def to_status_response(self) -> ScanStatusResponse:
        return ScanStatusResponse(
            scan_id=self.scan_id,
            target=self.target,
            profile=self.profile,
            overall_status=self.overall_status,
            scanners=list(self.scanner_progress.values()),
            in_scope=list(self.in_scope),
            out_of_scope=list(self.out_of_scope),
            logs=list(self.logs),
            created_at=self.created_at,
            updated_at=self.updated_at,
        )

    def to_results_response(self) -> ScanResultsResponse:
        correlated = correlate_findings(self.findings)
        return ScanResultsResponse(
            scan_id=self.scan_id,
            target=self.target,
            overall_status=self.overall_status,
            raw_findings=self.findings,
            correlated_findings=correlated,
            severity_distribution=severity_distribution(self.findings),
            duplicate_groups=duplicate_group_count(correlated),
            in_scope=list(self.in_scope),
            out_of_scope=list(self.out_of_scope),
            logs=list(self.logs),
        )


class JobManager:
    def __init__(self):
        self._jobs: dict[str, ScanJob] = {}

    async def start_scan(self, request: ScanStartRequest) -> ScanJob:
        scan_id = f"scan-{uuid4().hex[:12]}"
        job = ScanJob(scan_id, request)
        self._jobs[scan_id] = job
        scope_summary = f"In-Scope: [{', '.join(job.in_scope)}] | Out-of-Scope: [{', '.join(job.out_of_scope) if job.out_of_scope else 'None'}]"
        job.add_log("system", f"Job {scan_id} queued for target {request.target} (profile: {request.profile}). {scope_summary}")
        for tool in request.scanners:
            asyncio.create_task(self._run_scanner(job, tool))
        return job

    async def _run_scanner(self, job: ScanJob, tool: ScannerName) -> None:
        progress = job.scanner_progress[tool]
        progress.status = ScannerRunState.running
        progress.started_at = now_iso()
        job.updated_at = now_iso()

        wrapper = REGISTRY[tool]
        progress.simulated = not wrapper.is_available()
        mode_label = "SIMULATED" if progress.simulated else "REAL ENGINE"
        job.add_log(tool, f"Scanner worker started in [{mode_label}] mode for target: {job.target} (profile: {job.profile})")

        def log_callback(msg: str) -> None:
            job.add_log(tool, msg)

        try:
            findings = await wrapper.run(
                job.target,
                job.profile,
                in_scope=job.in_scope,
                out_of_scope=job.out_of_scope,
                log_cb=log_callback,
            )

            # Strict perimeter enforcement: filter out any out-of-scope finding evidence/targets
            scoped_findings: list[ScannerFinding] = []
            excluded_count = 0
            for f in findings:
                eval_str = f"{f.target} {f.evidence or ''}"
                if is_item_in_scope(eval_str, job.in_scope, job.out_of_scope):
                    scoped_findings.append(f)
                else:
                    excluded_count += 1

            if excluded_count > 0:
                job.add_log(tool, f"Perimeter filter: Excluded {excluded_count} finding(s) matching out-of-scope rules.")

            job.findings.extend(scoped_findings)
            progress.findings_count = len(scoped_findings)
            progress.status = ScannerRunState.completed
            job.add_log(tool, f"Execution completed with {len(scoped_findings)} in-scope findings.")
        except Exception as exc:  # a single scanner failing must not sink the job
            progress.status = ScannerRunState.error
            progress.error = str(exc)
            job.add_log(tool, f"Error executing scanner: {exc}")
        finally:
            progress.finished_at = now_iso()
            job.updated_at = now_iso()

    def get(self, scan_id: str) -> ScanJob | None:
        return self._jobs.get(scan_id)


job_manager = JobManager()
