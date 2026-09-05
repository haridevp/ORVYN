"""Result Correlation Engine (Module 2).

Groups findings reported by different scanners that describe the same
underlying vulnerability on the same target, flags disagreements between
scanners (e.g. different severity ratings), and raises confidence when
multiple independent tools corroborate a finding.
"""

import re
from difflib import SequenceMatcher
from uuid import uuid4

from schemas import SEVERITY_ORDER, CorrelatedFinding, ScannerFinding, SeverityDistribution

SIMILARITY_THRESHOLD = 0.55
BASE_CONFIDENCE = 45
CONFIDENCE_PER_EXTRA_TOOL = 25
MAX_CONFIDENCE = 97


def _normalize_title(title: str) -> str:
    title = title.lower()
    title = re.sub(r"\(cve-[\w.-]+\)", "", title)
    title = re.sub(r"[^a-z0-9 ]", " ", title)
    title = re.sub(r"\s+", " ", title).strip()
    return title


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, _normalize_title(a), _normalize_title(b)).ratio()


def _group_findings(findings: list[ScannerFinding]) -> list[list[ScannerFinding]]:
    groups: list[list[ScannerFinding]] = []
    for finding in findings:
        placed = False
        for group in groups:
            representative = group[0]
            if representative.target != finding.target:
                continue
            if _similarity(representative.vulnerability, finding.vulnerability) >= SIMILARITY_THRESHOLD:
                group.append(finding)
                placed = True
                break
        if not placed:
            groups.append([finding])
    return groups


def _highest_severity(items: list[ScannerFinding]):
    return max((f.severity for f in items), key=lambda s: SEVERITY_ORDER[s])


def correlate_findings(findings: list[ScannerFinding]) -> list[CorrelatedFinding]:
    groups = _group_findings(findings)
    correlated: list[CorrelatedFinding] = []

    for group in groups:
        tools = [f.tool for f in group]
        unique_tools = sorted(set(tools), key=lambda t: t.value)
        severities = {f.severity for f in group}
        conflicting = len(severities) > 1
        confidence = min(
            MAX_CONFIDENCE,
            BASE_CONFIDENCE + CONFIDENCE_PER_EXTRA_TOOL * (len(unique_tools) - 1),
        )
        representative = group[0]
        reference = next((f.reference for f in group if f.reference), None)

        correlated.append(
            CorrelatedFinding(
                correlation_id=f"corr-{uuid4().hex[:10]}",
                target=representative.target,
                vulnerability=representative.vulnerability,
                severity=_highest_severity(group),
                confidence=confidence,
                contributing_tools=unique_tools,
                conflicting_severity=conflicting,
                description=representative.description,
                evidence=[f.evidence for f in group if f.evidence],
                reference=reference,
                source_finding_ids=[f.id for f in group],
            )
        )

    correlated.sort(key=lambda c: SEVERITY_ORDER[c.severity], reverse=True)
    return correlated


def duplicate_group_count(correlated: list[CorrelatedFinding]) -> int:
    return sum(1 for c in correlated if len(c.contributing_tools) > 1)


def severity_distribution(findings: list[ScannerFinding]) -> SeverityDistribution:
    dist = SeverityDistribution()
    for f in findings:
        setattr(dist, f.severity.value, getattr(dist, f.severity.value) + 1)
    return dist
