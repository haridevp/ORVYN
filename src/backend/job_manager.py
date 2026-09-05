"""Scan job management: launches scanners concurrently, tracks per-scanner
status, stores results, and never lets one scanner's failure sink the job.
"""

import asyncio
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


class ScanJob:
    def __init__(self, scan_id: str, request: ScanStartRequest):
        self.scan_id = scan_id
        self.target = request.target
        self.profile = request.profile
        self.created_at = now_iso()
        self.updated_at = self.created_at
        self.scanner_progress: dict[ScannerName, ScannerProgress] = {
            tool: ScannerProgress(tool=tool, status=ScannerRunState.queued)
            for tool in request.scanners
        }
        self.findings: list[ScannerFinding] = []

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
        )


class JobManager:
    def __init__(self):
        self._jobs: dict[str, ScanJob] = {}

    async def start_scan(self, request: ScanStartRequest) -> ScanJob:
        scan_id = f"scan-{uuid4().hex[:12]}"
        job = ScanJob(scan_id, request)
        self._jobs[scan_id] = job
        for tool in request.scanners:
            asyncio.create_task(self._run_scanner(job, tool))
        return job

    async def _run_scanner(self, job: ScanJob, tool: ScannerName) -> None:
        progress = job.scanner_progress[tool]
        progress.status = ScannerRunState.running
        progress.started_at = now_iso()
        job.updated_at = now_iso()
        try:
            wrapper = REGISTRY[tool]
            findings = await wrapper.run(job.target, job.profile)
            job.findings.extend(findings)
            progress.findings_count = len(findings)
            progress.status = ScannerRunState.completed
        except Exception as exc:  # a single scanner failing must not sink the job
            progress.status = ScannerRunState.error
            progress.error = str(exc)
        finally:
            progress.finished_at = now_iso()
            job.updated_at = now_iso()

    def get(self, scan_id: str) -> ScanJob | None:
        return self._jobs.get(scan_id)


job_manager = JobManager()
