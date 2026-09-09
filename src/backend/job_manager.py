"""Scan job management: launches scanners concurrently, tracks per-scanner
status, captures live verbose logs, stores results, and never lets one
scanner's failure sink the job.
"""

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

from typing import Optional

from correlation import correlate_findings, duplicate_group_count, severity_distribution
from scanners import REGISTRY
from schemas import (
    CorrelatedFinding,
    ScannerFinding,
    ScannerName,
    ScannerProgress,
    ScannerRunState,
    ScanResultsResponse,
    ScanStartRequest,
    ScanStatusResponse,
    now_iso,
)

try:
    from storage import scan_storage
except ImportError:
    from .storage import scan_storage


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
        self.template_id = request.template
        self.template_name: Optional[str] = None
        self.requested_by: str = getattr(request, "requested_by", "admin") or "admin"
        # Default in_scope to wildcard domain if not specified: e.g. *.target.com
        target_domain = request.target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        self.in_scope = request.in_scope if request.in_scope else [f"*.{target_domain}", request.target]
        self.out_of_scope = request.out_of_scope if request.out_of_scope else []
        self.created_at = now_iso()
        self.updated_at = self.created_at
        self.start_epoch = datetime.now(timezone.utc).timestamp()
        self.scanner_progress: dict[ScannerName, ScannerProgress] = {
            tool: ScannerProgress(tool=tool, status=ScannerRunState.queued)
            for tool in request.scanners
        }
        self.findings: list[ScannerFinding] = []
        self.logs: list[str] = []
        self.is_cancelled: bool = False
        self._tasks: list[asyncio.Task] = []
        self._correlated_cache: Optional[list[CorrelatedFinding]] = None

    def get_correlated_findings(self) -> list[CorrelatedFinding]:
        if self._correlated_cache is not None:
            return self._correlated_cache
        return correlate_findings(self.findings)

    def add_log(self, tool: ScannerName | str, message: str) -> None:
        tool_name = tool.value if hasattr(tool, "value") else str(tool)
        timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        self.logs.append(f"[{timestamp}] [{tool_name}] {message}")
        self.updated_at = now_iso()

    @property
    def elapsed_seconds(self) -> int:
        return max(0, int(datetime.now(timezone.utc).timestamp() - self.start_epoch))

    @property
    def expected_duration(self) -> int:
        num_scanners = max(1, len(self.scanner_progress))
        base = {"recon": 20, "web": 45, "full": 120, "deep": 360, "unlimited": 600}.get(self.profile, 45)
        if num_scanners == 1:
            base = int(base * 0.6)
        elif num_scanners == 2:
            base = int(base * 0.85)
        return max(10, base)

    @property
    def progress_percentage(self) -> int:
        status = self.overall_status
        if status in ("completed", "error", "cancelled"):
            return 100

        total_scanners = len(self.scanner_progress)
        if total_scanners == 0:
            return 0

        completed_count = sum(
            1 for p in self.scanner_progress.values()
            if p.status in (ScannerRunState.completed, ScannerRunState.error)
        )
        running_count = sum(
            1 for p in self.scanner_progress.values()
            if p.status == ScannerRunState.running
        )

        completed_portion = (completed_count / total_scanners) * 100
        time_ratio = min(0.90, self.elapsed_seconds / max(1, self.expected_duration))
        running_portion = (running_count / total_scanners) * 100 * time_ratio

        calculated = int(completed_portion + running_portion)
        return max(5, min(98, calculated))

    @property
    def estimated_time_remaining(self) -> int | None:
        if self.overall_status in ("completed", "error", "cancelled"):
            return 0
        if self.profile == "unlimited":
            return None

        total = len(self.scanner_progress)
        if total == 0:
            return 0

        completed = sum(
            1 for p in self.scanner_progress.values()
            if p.status in (ScannerRunState.completed, ScannerRunState.error, ScannerRunState.cancelled)
        )
        if completed == total:
            return 0

        remaining = self.expected_duration - self.elapsed_seconds
        if remaining > 0:
            return max(1, remaining)

        # Monotonic, graceful tail while scanners finalize without jumping
        overtime = self.elapsed_seconds - self.expected_duration
        if overtime < 4:
            return 3
        elif overtime < 8:
            return 2
        return 1

    @property
    def overall_status(self) -> str:
        if self.is_cancelled:
            return "cancelled"
        states = [p.status for p in self.scanner_progress.values()]
        if any(s in (ScannerRunState.error, ScannerRunState.cancelled) for s in states) and all(
            s in (ScannerRunState.completed, ScannerRunState.error, ScannerRunState.cancelled) for s in states
        ):
            return "error" if all(s in (ScannerRunState.error, ScannerRunState.cancelled) for s in states) else "completed"
        if all(s == ScannerRunState.completed for s in states):
            return "completed"
        if any(s == ScannerRunState.running for s in states):
            return "running"
        return "queued"

    def to_status_response(self) -> ScanStatusResponse:
        correlated = correlate_findings(self.findings)
        return ScanStatusResponse(
            scan_id=self.scan_id,
            target=self.target,
            profile=self.profile,
            template_id=self.template_id,
            template_name=self.template_name,
            overall_status=self.overall_status,
            progress_pct=self.progress_percentage,
            eta_seconds=self.estimated_time_remaining,
            elapsed_seconds=self.elapsed_seconds,
            scanners=list(self.scanner_progress.values()),
            live_findings=list(self.findings),
            findings_count=len(self.findings),
            correlated_count=len(correlated),
            duplicate_groups=duplicate_group_count(correlated),
            severity_distribution=severity_distribution(self.findings),
            in_scope=list(self.in_scope),
            out_of_scope=list(self.out_of_scope),
            logs=list(self.logs),
            created_at=self.created_at,
            updated_at=self.updated_at,
        )

    def to_results_response(self) -> ScanResultsResponse:
        correlated = self._correlated_cache if self._correlated_cache is not None else correlate_findings(self.findings)
        return ScanResultsResponse(
            scan_id=self.scan_id,
            target=self.target,
            profile=self.profile,
            template_id=self.template_id,
            template_name=self.template_name,
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
        # If a template is specified (and not 'auto'), apply its scanners and profile
        applied_template = None
        is_auto = request.template == "auto"

        if request.template and request.template != "auto":
            try:
                from templates.registry import template_registry
                applied_template = template_registry.get_template(request.template)
            except Exception:
                pass

        scan_id = f"scan-{uuid4().hex[:12]}"
        job = ScanJob(scan_id, request)
        if applied_template:
            job.template_id = applied_template.id
            job.template_name = applied_template.name
        elif is_auto:
            job.template_id = "auto"
            job.template_name = "🤖 AI Autonomous Mode"

        self._jobs[scan_id] = job
        scope_summary = f"In-Scope: [{', '.join(job.in_scope)}] | Out-of-Scope: [{', '.join(job.out_of_scope) if job.out_of_scope else 'None'}]"
        
        template_msg = f" [Template: {applied_template.name} ({applied_template.badge})]" if applied_template else (" [Mode: 🤖 AI Autonomous]" if is_auto else "")
        job.add_log("system", f"Job {scan_id} queued for target {request.target} (profile: {request.profile}){template_msg}. {scope_summary}")
        
        if applied_template:
            job.add_log("template", f"Applied vulnerability template '{applied_template.name}'. Focused on: {', '.join(applied_template.vulnerability_focus[:3])}")
        elif is_auto:
            job.add_log("ai-orchestrator", "🤖 AI Autonomous Mode active: Running Phase 1 Recon to inspect perimeter and select optimal vulnerability template...")

        # Persist initial job record immediately
        try:
            scan_storage.save_job(job)
        except Exception:
            pass

        for tool in request.scanners:
            t = asyncio.create_task(self._run_scanner(job, tool))
            job._tasks.append(t)

        async def _post_scan_triage():
            await asyncio.gather(*job._tasks, return_exceptions=True)

            # Phase 2: Autonomous LLM Template Selection & Secondary Tool Chain Execution
            if is_auto and not job.is_cancelled:
                try:
                    try:
                        from ai_orchestrator import select_template_with_llm
                        from templates.registry import template_registry
                    except ImportError:
                        from .ai_orchestrator import select_template_with_llm
                        from .templates.registry import template_registry

                    tech_list = []
                    open_ports = []
                    server_banner = None
                    for f in job.findings:
                        if f.tool == ScannerName.whatweb:
                            tech_list.append(f.description)
                        elif f.tool == ScannerName.nmap:
                            if "port" in f.vulnerability.lower() or "service" in f.vulnerability.lower():
                                tech_list.append(f.vulnerability)

                    decision = await select_template_with_llm(job.target, tech_list, open_ports, server_banner)
                    job.template_id = decision.selected_template_id
                    job.template_name = decision.template_name
                    job.add_log(
                        "ai-orchestrator",
                        f"🤖 AI Decision: Evaluated recon ({decision.confidence}% confidence) -> Selected template '{decision.template_name}'. Reasoning: {decision.reasoning}",
                    )

                    # Dynamically enqueue any secondary tools in the chosen template that haven't executed yet
                    chosen_tmpl = template_registry.get_template(decision.selected_template_id)
                    if chosen_tmpl:
                        new_tasks = []
                        for sec_tool in chosen_tmpl.scanners:
                            if sec_tool not in job.scanner_progress:
                                job.scanner_progress[sec_tool] = ScannerProgress(tool=sec_tool, status=ScannerRunState.queued)
                                job.add_log("ai-orchestrator", f"Enqueuing secondary targeted tool from template: {sec_tool.value}")
                                t = asyncio.create_task(self._run_scanner(job, sec_tool))
                                job._tasks.append(t)
                                new_tasks.append(t)
                        if new_tasks:
                            await asyncio.gather(*new_tasks, return_exceptions=True)
                except Exception as exc:
                    job.add_log("ai-orchestrator", f"Autonomous template selection note: {exc}")

            # Phase 3: AI RAG Post-Scan Triage & One-by-One Finding Verification
            if not job.is_cancelled and job.findings:
                try:
                    from rag_triage import triage_all_correlated
                    correlated = correlate_findings(job.findings)
                    def rag_log(msg: str):
                        job.add_log("ai-rag", msg)
                    job._correlated_cache = await triage_all_correlated(correlated, log_cb=rag_log)
                except Exception as e:
                    job.add_log("ai-rag", f"AI RAG triage encountered an error: {e}")

            # Final persistence update after all phases complete
            try:
                scan_storage.save_job(job)
            except Exception:
                pass

        asyncio.create_task(_post_scan_triage())
        return job

    def cancel_scan(self, scan_id: str) -> bool:
        job = self.get(scan_id)
        if not job:
            return False
        job.is_cancelled = True
        job.add_log("system", "Scan cancelled by user request.")
        for task in job._tasks:
            if not task.done():
                task.cancel()
        for p in job.scanner_progress.values():
            if p.status in (ScannerRunState.queued, ScannerRunState.running):
                p.status = ScannerRunState.cancelled
                p.error = "Aborted by user request"
                p.finished_at = now_iso()
        job.updated_at = now_iso()
        try:
            scan_storage.save_job(job)
        except Exception:
            pass
        return True

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

        def live_finding_callback(finding: ScannerFinding) -> None:
            eval_str = f"{finding.target} {finding.evidence or ''}"
            if is_item_in_scope(eval_str, job.in_scope, job.out_of_scope):
                # Avoid duplicates
                if not any(
                    existing.vulnerability == finding.vulnerability and existing.evidence == finding.evidence
                    for existing in job.findings
                ):
                    job.findings.append(finding)
                    progress.findings_count = len([f for f in job.findings if f.tool == tool])
                    job.updated_at = now_iso()
                    job.add_log(tool, f"🎯 Vulnerability detected live: [{finding.severity.upper()}] {finding.vulnerability}")
                    try:
                        scan_storage.save_job(job)
                    except Exception:
                        pass

        try:
            findings = await wrapper.run(
                job.target,
                job.profile,
                in_scope=job.in_scope,
                out_of_scope=job.out_of_scope,
                log_cb=log_callback,
                finding_cb=live_finding_callback,
            )

            # Strict perimeter enforcement & reconciliation: ensure any batch findings are captured
            excluded_count = 0
            for f in findings:
                eval_str = f"{f.target} {f.evidence or ''}"
                if is_item_in_scope(eval_str, job.in_scope, job.out_of_scope):
                    if not any(
                        existing.vulnerability == f.vulnerability and existing.evidence == f.evidence
                        for existing in job.findings
                    ):
                        job.findings.append(f)
                else:
                    excluded_count += 1

            if excluded_count > 0:
                job.add_log(tool, f"Perimeter filter: Excluded {excluded_count} finding(s) matching out-of-scope rules.")

            tool_findings = [f for f in job.findings if f.tool == tool]
            progress.findings_count = len(tool_findings)
            progress.status = ScannerRunState.completed
            job.add_log(tool, f"Execution completed with {len(tool_findings)} in-scope findings.")
        except Exception as exc:  # a single scanner failing must not sink the job
            progress.status = ScannerRunState.error
            progress.error = str(exc)
            job.add_log(tool, f"Error executing scanner: {exc}")
        finally:
            progress.finished_at = now_iso()
            job.updated_at = now_iso()
            try:
                scan_storage.save_job(job)
            except Exception:
                pass

    def get(self, scan_id: str) -> ScanJob | None:
        if scan_id in self._jobs:
            return self._jobs[scan_id]
        
        # Load from persistent SQLite storage
        job_data = scan_storage.get_scan(scan_id)
        if job_data:
            reconstituted = _reconstitute_job(job_data)
            self._jobs[scan_id] = reconstituted
            return reconstituted
        return None

    def list_scans(self, limit: int = 100, requested_by: Optional[str] = None) -> list[ScanStatusResponse]:
        # Sync in-memory jobs to storage
        for job in list(self._jobs.values()):
            try:
                scan_storage.save_job(job)
            except Exception:
                pass

        stored = scan_storage.list_scans(limit=limit, requested_by=requested_by)
        results: list[ScanStatusResponse] = []
        for s in stored:
            sid = s["scan_id"]
            if sid in self._jobs:
                results.append(self._jobs[sid].to_status_response())
            else:
                full_job = self.get(sid)
                if full_job:
                    results.append(full_job.to_status_response())
        return results

    def delete_scan(self, scan_id: str) -> bool:
        if scan_id in self._jobs:
            del self._jobs[scan_id]
        return scan_storage.delete_scan(scan_id)


def _reconstitute_job(job_data: dict) -> ScanJob:
    """Rebuild a live ScanJob instance from persisted SQLite scan record."""
    prog_dict = job_data.get("scanner_progress") or {}
    tools = []
    for t_str in prog_dict.keys():
        try:
            tools.append(ScannerName(t_str))
        except Exception:
            pass
    if not tools:
        tools = [ScannerName.nmap]

    req = ScanStartRequest(
        target=job_data["target"],
        profile=job_data.get("profile", "recon"),
        scanners=tools,
        template=job_data.get("template_id"),
        in_scope=job_data.get("in_scope") or [],
        out_of_scope=job_data.get("out_of_scope") or [],
    )
    job = ScanJob(job_data["scan_id"], req)
    job.template_id = job_data.get("template_id")
    job.template_name = job_data.get("template_name")
    job.created_at = job_data.get("created_at") or job.created_at
    job.updated_at = job_data.get("updated_at") or job.updated_at
    job.in_scope = job_data.get("in_scope") or job.in_scope
    job.out_of_scope = job_data.get("out_of_scope") or job.out_of_scope
    job.requested_by = job_data.get("requested_by", "admin")
    job.logs = job_data.get("logs") or []

    # Restore scanner progress
    restored_progress = {}
    for t_str, p_info in prog_dict.items():
        try:
            tool_enum = ScannerName(t_str)
            status_str = p_info.get("status", "completed")
            state_enum = ScannerRunState.completed
            for s in ScannerRunState:
                if s.value == status_str:
                    state_enum = s
                    break
            sp = ScannerProgress(
                tool=tool_enum,
                status=state_enum,
                started_at=p_info.get("started_at"),
                finished_at=p_info.get("finished_at"),
                findings_count=p_info.get("findings_count", 0),
                error=p_info.get("error"),
            )
            sp.simulated = p_info.get("simulated", False)
            restored_progress[tool_enum] = sp
        except Exception:
            pass
    if restored_progress:
        job.scanner_progress = restored_progress

    # Restore findings
    from schemas import Severity
    restored_findings = []
    for f in job_data.get("findings") or []:
        try:
            tool_enum = ScannerName(f["tool"])
        except Exception:
            tool_enum = ScannerName.nmap
        sev_val = Severity.info
        for s in Severity:
            if s.value == str(f["severity"]).lower():
                sev_val = s
                break
        restored_findings.append(ScannerFinding(
            tool=tool_enum,
            target=f["target"],
            vulnerability=f["vulnerability"],
            severity=sev_val,
            confidence=f.get("confidence", 50),
            description=f.get("description", ""),
            evidence=f.get("evidence"),
            reference=f.get("reference"),
        ))
    job.findings = restored_findings
    return job


job_manager = JobManager()
