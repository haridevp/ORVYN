"""
Enterprise Penetration Testing Executive PDF Report Generator.

Generates high-grade, standard-compliant PDF-1.4 documents without requiring
external binary dependencies or C-extensions.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any


def _sanitize(text: str) -> str:
    """Sanitize text for standard Type1 Helvetica PDF strings."""
    if text is None:
        return ""
    # Map common unicode glyphs to ASCII equivalents
    replacements = {
        "•": "*",
        "—": "-",
        "–": "-",
        "“": '"',
        "”": '"',
        "‘": "'",
        "’": "'",
        "✔": "[OK]",
        "✖": "[X]",
        "⚡": "*",
        "🛡": "",
        "🔍": "",
        "⚠️": "!",
        "→": "->",
        "←": "<-",
        "\t": "    ",
    }
    for k, v in replacements.items():
        text = text.replace(k, v)
    # Remove any non-ascii characters
    ascii_text = text.encode("ascii", "replace").decode("ascii")
    # Escape PDF string literals
    return ascii_text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap_text(text: str, max_chars: int) -> list[str]:
    """Simple greedy word wrapper."""
    if not text:
        return [""]
    words = text.split(" ")
    lines: list[str] = []
    current: list[str] = []
    current_len = 0

    for w in words:
        if current_len + len(w) + (1 if current else 0) <= max_chars:
            current.append(w)
            current_len += len(w) + (1 if current_len > 0 else 0)
        else:
            if current:
                lines.append(" ".join(current))
            # If a single word is longer than max_chars, chunk it
            while len(w) > max_chars:
                lines.append(w[:max_chars])
                w = w[max_chars:]
            current = [w] if w else []
            current_len = len(w)

    if current:
        lines.append(" ".join(current))
    return lines or [""]


class PDFPage:
    def __init__(self, width: int = 612, height: int = 792):
        self.width = width
        self.height = height
        self.commands: list[str] = []

    def rect(self, x: float, y: float, w: float, h: float, fill_color: tuple[float, float, float] | None = None, stroke_color: tuple[float, float, float] | None = None, line_width: float = 1.0):
        cmd = []
        if fill_color:
            r, g, b = fill_color
            cmd.append(f"{r:.3f} {g:.3f} {b:.3f} rg")
        if stroke_color:
            r, g, b = stroke_color
            cmd.append(f"{r:.3f} {g:.3f} {b:.3f} RG")
            cmd.append(f"{line_width:.2f} w")
        cmd.append(f"{x:.2f} {y:.2f} {w:.2f} {h:.2f} re")
        if fill_color and stroke_color:
            cmd.append("B")
        elif fill_color:
            cmd.append("f")
        elif stroke_color:
            cmd.append("S")
        self.commands.append(" ".join(cmd))

    def line(self, x1: float, y1: float, x2: float, y2: float, stroke_color: tuple[float, float, float] = (0.3, 0.3, 0.3), line_width: float = 1.0):
        r, g, b = stroke_color
        self.commands.append(f"{r:.3f} {g:.3f} {b:.3f} RG {line_width:.2f} w {x1:.2f} y1:.2f m {x2:.2f} {y2:.2f} l S".replace("y1:.2f", f"{y1:.2f}"))

    def text(self, x: float, y: float, string: str, font: str = "/F1", size: float = 10.0, color: tuple[float, float, float] = (0.1, 0.1, 0.1)):
        r, g, b = color
        safe = _sanitize(string)
        self.commands.append(f"BT {font} {size:.2f} Tf {r:.3f} {g:.3f} {b:.3f} rg {x:.2f} {y:.2f} Td ({safe}) Tj ET")

    def compile_stream(self) -> bytes:
        data = "\n".join(self.commands).encode("latin1")
        return b"<< /Length " + str(len(data)).encode("ascii") + b" >>\nstream\n" + data + b"\nendstream"


class PentestPDFBuilder:
    def __init__(self, target: str):
        self.target = target
        self.pages: list[PDFPage] = []
        self.current_page: PDFPage = self.new_page()
        self.margin_left = 40.0
        self.margin_right = 572.0
        self.content_width = self.margin_right - self.margin_left  # 532 pt
        self.y = 740.0  # Start position below header

    def new_page(self) -> PDFPage:
        page = PDFPage(612, 792)
        self.pages.append(page)
        self.current_page = page
        self.y = 720.0
        return page

    def ensure_space(self, height: float):
        if self.y - height < 60.0:
            self.new_page()

    def add_header_banner(self, target: str, profile: str, scan_id: str):
        p = self.current_page
        # Top banner background (Deep Dark Navy Slate)
        p.rect(0, 722, 612, 70, fill_color=(0.06, 0.09, 0.16))
        # Top accent bar (Cyan/Blue)
        p.rect(0, 788, 612, 4, fill_color=(0.20, 0.50, 0.95))

        # Brand / Suite Title (Professional Company Placeholders)
        p.text(40, 762, "[COMPANY NAME] CYBERSECURITY AUDIT SERVICES  //  PENETRATION TESTING DIVISION", font="/F2", size=8.5, color=(0.58, 0.65, 0.75))
        p.text(40, 742, "PENETRATION TESTING & SECURITY AUDIT REPORT", font="/F2", size=14, color=(1.0, 1.0, 1.0))
        p.text(40, 730, f"Client Scope: {target}   |   Profile: {profile.upper()}   |   Assessment ID: {scan_id[:16]}", font="/F1", size=8.0, color=(0.40, 0.70, 0.95))

        # Badge pill top right
        p.rect(420, 736, 150, 20, fill_color=(0.10, 0.15, 0.25), stroke_color=(0.25, 0.35, 0.50), line_width=1.0)
        p.text(428, 742, "STRICTLY CONFIDENTIAL", font="/F2", size=7.5, color=(0.90, 0.93, 0.98))

        self.y = 705.0

    def add_meta_table(self, metadata: dict[str, str]):
        self.ensure_space(65.0)
        p = self.current_page
        box_y = self.y - 52.0
        p.rect(self.margin_left, box_y, self.content_width, 52.0, fill_color=(0.96, 0.97, 0.99), stroke_color=(0.85, 0.88, 0.92), line_width=1.0)

        # 4-column layout
        col_w = self.content_width / 4.0
        keys = list(metadata.items())
        for idx, (label, val) in enumerate(keys[:4]):
            cx = self.margin_left + (idx * col_w) + 10.0
            p.text(cx, box_y + 34.0, label.upper(), font="/F2", size=7.0, color=(0.45, 0.50, 0.58))
            p.text(cx, box_y + 18.0, str(val)[:24], font="/F2", size=9.0, color=(0.10, 0.12, 0.18))
            if idx < 3:
                p.line(self.margin_left + ((idx + 1) * col_w), box_y + 8.0, self.margin_left + ((idx + 1) * col_w), box_y + 44.0, stroke_color=(0.85, 0.88, 0.92), line_width=0.8)

        self.y = box_y - 18.0

    def add_executive_summary(self, dist: dict[str, int], total_raw: int, dup_groups: int, overall_rating: str):
        self.ensure_space(110.0)
        p = self.current_page

        p.text(self.margin_left, self.y, "1. EXECUTIVE SUMMARY & POSTURE EVALUATION", font="/F2", size=12.0, color=(0.08, 0.12, 0.22))
        p.line(self.margin_left, self.y - 4.0, self.margin_right, self.y - 4.0, stroke_color=(0.80, 0.84, 0.90), line_width=1.0)
        self.y -= 18.0

        p.text(
            self.margin_left,
            self.y,
            f"Automated multi-engine security assessment identified {total_raw} raw findings consolidated into {dup_groups} correlated vulnerability vectors.",
            font="/F1",
            size=8.5,
            color=(0.30, 0.35, 0.42),
        )
        self.y -= 14.0

        # Severity cards: Critical, High, Medium, Low, Info
        card_w = (self.content_width - 24.0) / 5.0
        card_h = 46.0
        box_y = self.y - card_h

        sevs = [
            ("CRITICAL", dist.get("critical", 0), (0.60, 0.05, 0.05), (0.98, 0.90, 0.90)),
            ("HIGH", dist.get("high", 0), (0.75, 0.25, 0.05), (0.99, 0.93, 0.88)),
            ("MEDIUM", dist.get("medium", 0), (0.70, 0.45, 0.02), (0.99, 0.96, 0.88)),
            ("LOW", dist.get("low", 0), (0.12, 0.35, 0.75), (0.90, 0.94, 0.99)),
            ("INFO", dist.get("info", 0), (0.30, 0.35, 0.42), (0.93, 0.94, 0.96)),
        ]

        for i, (name, count, text_col, bg_col) in enumerate(sevs):
            cx = self.margin_left + i * (card_w + 6.0)
            p.rect(cx, box_y, card_w, card_h, fill_color=bg_col, stroke_color=text_col, line_width=1.0)
            p.text(cx + 8.0, box_y + 30.0, name, font="/F2", size=7.5, color=text_col)
            p.text(cx + 8.0, box_y + 10.0, str(count), font="/F2", size=16.0, color=text_col)

        self.y = box_y - 20.0

    def add_scope_section(self, in_scope: list[str], out_of_scope: list[str]):
        self.ensure_space(75.0)
        p = self.current_page
        p.text(self.margin_left, self.y, "2. SCOPE OF ASSESSMENT & PERIMETER BOUNDARIES", font="/F2", size=12.0, color=(0.08, 0.12, 0.22))
        p.line(self.margin_left, self.y - 4.0, self.margin_right, self.y - 4.0, stroke_color=(0.80, 0.84, 0.90), line_width=1.0)
        self.y -= 18.0

        in_str = ", ".join(in_scope) if in_scope else f"*.{self.target}"
        out_str = ", ".join(out_of_scope) if out_of_scope else "None declared (Standard strict target boundary)"

        p.text(self.margin_left, self.y, "Authorized Targets (In-Scope):", font="/F2", size=8.5, color=(0.15, 0.20, 0.28))
        p.text(self.margin_left + 140.0, self.y, in_str[:70], font="/F3", size=8.0, color=(0.10, 0.45, 0.20))
        self.y -= 13.0

        p.text(self.margin_left, self.y, "Explicit Deny (Out-of-Scope):", font="/F2", size=8.5, color=(0.15, 0.20, 0.28))
        p.text(self.margin_left + 140.0, self.y, out_str[:70], font="/F3", size=8.0, color=(0.65, 0.15, 0.15))
        self.y -= 20.0

    def add_findings_section(self, correlated: list[dict[str, Any]]):
        self.ensure_space(45.0)
        p = self.current_page
        p.text(self.margin_left, self.y, f"3. CORRELATED VULNERABILITY FINDINGS ({len(correlated)})", font="/F2", size=12.0, color=(0.08, 0.12, 0.22))
        p.line(self.margin_left, self.y - 4.0, self.margin_right, self.y - 4.0, stroke_color=(0.80, 0.84, 0.90), line_width=1.0)
        self.y -= 18.0

        if not correlated:
            p.rect(self.margin_left, self.y - 30.0, self.content_width, 30.0, fill_color=(0.92, 0.98, 0.94), stroke_color=(0.20, 0.65, 0.35), line_width=1.0)
            p.text(self.margin_left + 15.0, self.y - 18.0, "CLEAN PERIMETER: Zero active vulnerabilities discovered across designated scope.", font="/F2", size=9.0, color=(0.10, 0.45, 0.20))
            self.y -= 45.0
            return

        sev_colors = {
            "critical": ((0.65, 0.05, 0.05), (0.98, 0.90, 0.90)),
            "high": ((0.75, 0.25, 0.05), (0.99, 0.93, 0.88)),
            "medium": ((0.70, 0.45, 0.02), (0.99, 0.96, 0.88)),
            "low": ((0.12, 0.35, 0.75), (0.90, 0.94, 0.99)),
            "info": ((0.30, 0.35, 0.42), (0.93, 0.94, 0.96)),
        }

        for idx, item in enumerate(correlated, 1):
            vuln = item.get("vulnerability", "Security Finding")
            sev = (item.get("severity") or "info").lower()
            text_c, bg_c = sev_colors.get(sev, sev_colors["info"])
            tools = ", ".join(item.get("contributing_tools", [])) or "Multi-Engine"
            conf = item.get("confidence", 80)
            evidence = item.get("evidence") or []
            first_ev = evidence[0] if evidence else "N/A"
            remediation = item.get("remediation") or "Apply standard principle of least privilege, update component, and restrict access."
            ref = item.get("reference") or "OWASP / NIST Security Framework"

            # Estimate card height
            desc_lines = _wrap_text(vuln, 65)
            ev_lines = _wrap_text(first_ev, 70)
            rem_lines = _wrap_text(remediation, 72)
            card_h = 44.0 + (len(desc_lines) * 11.0) + (len(ev_lines) * 10.0) + (len(rem_lines) * 10.0) + 24.0

            self.ensure_space(card_h + 10.0)
            p = self.current_page
            card_top = self.y
            card_bottom = card_top - card_h

            # Card outer box
            p.rect(self.margin_left, card_bottom, self.content_width, card_h, fill_color=(0.98, 0.99, 1.0), stroke_color=(0.84, 0.87, 0.92), line_width=1.0)
            # Left accent severity strip
            p.rect(self.margin_left, card_bottom, 4.0, card_h, fill_color=text_c)

            # Header row in card
            # Severity Pill
            p.rect(self.margin_left + 12.0, card_top - 18.0, 52.0, 14.0, fill_color=bg_c, stroke_color=text_c, line_width=0.8)
            p.text(self.margin_left + 16.0, card_top - 14.0, sev.upper(), font="/F2", size=7.0, color=text_c)

            # Vulnerability Title
            p.text(self.margin_left + 72.0, card_top - 15.0, f"#{idx}  {desc_lines[0]}", font="/F2", size=9.0, color=(0.10, 0.12, 0.20))

            cur_y = card_top - 30.0

            # Telemetry: Engines & Confidence
            p.text(self.margin_left + 12.0, cur_y, "Engines:", font="/F2", size=7.5, color=(0.45, 0.50, 0.58))
            p.text(self.margin_left + 54.0, cur_y, tools, font="/F1", size=7.5, color=(0.15, 0.20, 0.30))

            p.text(self.margin_left + 220.0, cur_y, "Confidence:", font="/F2", size=7.5, color=(0.45, 0.50, 0.58))
            p.text(self.margin_left + 276.0, cur_y, f"{conf}% Verified", font="/F2", size=7.5, color=(0.10, 0.45, 0.20))

            p.text(self.margin_left + 360.0, cur_y, "Ref:", font="/F2", size=7.5, color=(0.45, 0.50, 0.58))
            p.text(self.margin_left + 382.0, cur_y, str(ref)[:28], font="/F1", size=7.0, color=(0.20, 0.40, 0.70))
            cur_y -= 14.0

            # Evidence
            p.text(self.margin_left + 12.0, cur_y, "Evidence / Payload:", font="/F2", size=7.5, color=(0.45, 0.50, 0.58))
            cur_y -= 10.0
            for eline in ev_lines[:3]:
                p.text(self.margin_left + 16.0, cur_y, eline, font="/F3", size=7.0, color=(0.20, 0.25, 0.35))
                cur_y -= 10.0

            # Remediation
            cur_y -= 2.0
            p.text(self.margin_left + 12.0, cur_y, "Recommended Remediation:", font="/F2", size=7.5, color=(0.10, 0.40, 0.20))
            cur_y -= 10.0
            for rline in rem_lines[:3]:
                p.text(self.margin_left + 16.0, cur_y, rline, font="/F1", size=7.5, color=(0.25, 0.30, 0.38))
                cur_y -= 10.0

            self.y = card_bottom - 12.0

    def add_disclaimer(self):
        self.ensure_space(70.0)
        p = self.current_page
        p.text(self.margin_left, self.y, "4. RULES OF ENGAGEMENT & ETHICAL DISCLAIMER", font="/F2", size=11.0, color=(0.08, 0.12, 0.22))
        p.line(self.margin_left, self.y - 4.0, self.margin_right, self.y - 4.0, stroke_color=(0.80, 0.84, 0.90), line_width=1.0)
        self.y -= 16.0

        disclaimer_text = (
            "This assessment report is generated via automated security testing engines strictly within "
            "the boundaries of the authorized target perimeter. Information contained herein is confidential "
            "and intended solely for remediation and defensive hardening by authorized personnel. "
            "Unauthorized distribution, modification, or weaponization of findings is strictly prohibited."
        )
        for dline in _wrap_text(disclaimer_text, 82):
            p.text(self.margin_left, self.y, dline, font="/F1", size=7.5, color=(0.45, 0.50, 0.58))
            self.y -= 10.0

    def finalize_decorations(self):
        """Add running header and footer across all pages."""
        total = len(self.pages)
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        for idx, p in enumerate(self.pages, 1):
            # If not page 1, add running top header
            if idx > 1:
                p.rect(0, 770, 612, 22, fill_color=(0.06, 0.09, 0.16))
                p.text(40, 776, "[COMPANY NAME] AUDIT SERVICES  //  PENETRATION TESTING REPORT", font="/F2", size=7.5, color=(0.60, 0.65, 0.75))
                p.text(420, 776, f"Scope: {self.target}", font="/F1", size=7.5, color=(0.40, 0.70, 0.95))

            # Running footer on every page
            p.line(40, 36, 572, 36, stroke_color=(0.85, 0.88, 0.92), line_width=0.8)
            p.text(40, 24, f"STRICTLY CONFIDENTIAL - [COMPANY NAME] ASSESSMENT | Generated {now_str}", font="/F1", size=7.0, color=(0.50, 0.55, 0.62))
            p.text(510, 24, f"Page {idx} of {total}", font="/F2", size=7.5, color=(0.35, 0.40, 0.48))

    def build_pdf(self) -> bytes:
        self.finalize_decorations()
        out = io.BytesIO()
        out.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

        # Objects layout:
        # 1: Catalog
        # 2: Pages
        # 3: Font F1 (Helvetica)
        # 4: Font F2 (Helvetica-Bold)
        # 5: Font F3 (Courier)
        # 6 .. 6+N-1: Page objects
        # 6+N .. 6+2N-1: Content stream objects

        num_pages = len(self.pages)
        catalog_id = 1
        pages_id = 2
        f1_id = 3
        f2_id = 4
        f3_id = 5

        page_ids = [6 + i for i in range(num_pages)]
        content_ids = [6 + num_pages + i for i in range(num_pages)]
        total_objs = 5 + (num_pages * 2)

        offsets: list[int] = [0] * (total_objs + 1)

        def write_obj(obj_id: int, content: bytes):
            offsets[obj_id] = out.tell()
            out.write(f"{obj_id} 0 obj\n".encode("ascii"))
            out.write(content)
            out.write(b"\nendobj\n")

        # 1: Catalog
        write_obj(catalog_id, f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("ascii"))

        # 2: Pages
        kids_str = " ".join(f"{pid} 0 R" for pid in page_ids)
        write_obj(pages_id, f"<< /Type /Pages /Kids [{kids_str}] /Count {num_pages} /MediaBox [0 0 612 792] >>".encode("ascii"))

        # 3: Fonts
        write_obj(f1_id, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        write_obj(f2_id, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
        write_obj(f3_id, b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")

        # Page Objects & Content Streams
        for i in range(num_pages):
            pid = page_ids[i]
            cid = content_ids[i]
            page_dict = (
                f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 612 792] "
                f"/Resources << /Font << /F1 {f1_id} 0 R /F2 {f2_id} 0 R /F3 {f3_id} 0 R >> >> "
                f"/Contents {cid} 0 R >>"
            ).encode("ascii")
            write_obj(pid, page_dict)

        for i in range(num_pages):
            cid = content_ids[i]
            stream_bytes = self.pages[i].compile_stream()
            write_obj(cid, stream_bytes)

        # Xref table
        xref_offset = out.tell()
        out.write(b"xref\n")
        out.write(f"0 {total_objs + 1}\n".encode("ascii"))
        out.write(b"0000000000 65535 f \n")
        for i in range(1, total_objs + 1):
            out.write(f"{offsets[i]:010d} 00000 n \n".encode("ascii"))

        # Trailer
        out.write(
            f"trailer\n<< /Size {total_objs + 1} /Root {catalog_id} 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii")
        )
        return out.getvalue()


def generate_pentest_pdf(data: dict[str, Any]) -> bytes:
    """Entry point: converts report data dictionary into an executive PDF document."""
    target = data.get("target", "Target Scope")
    profile = data.get("profile", "web")
    scan_id = data.get("scan_id", "audit-" + datetime.now(timezone.utc).strftime("%Y%m%d"))
    correlated = data.get("correlated_findings", [])
    raw_findings = data.get("raw_findings", [])
    dist = data.get("severity_distribution", {})
    dup_groups = data.get("duplicate_groups", len(correlated))
    in_scope = data.get("in_scope", [])
    out_of_scope = data.get("out_of_scope", [])

    builder = PentestPDFBuilder(target=target)
    builder.add_header_banner(target=target, profile=profile, scan_id=scan_id)

    # Metadata Grid
    meta = {
        "Target Perimeter": target,
        "Profile / Mode": profile.upper(),
        "Assessment ID": scan_id[:16],
        "Audit Date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }
    builder.add_meta_table(meta)

    # Executive Posture
    rating = "CRITICAL RISK" if dist.get("critical", 0) > 0 else ("HIGH RISK" if dist.get("high", 0) > 0 else "MODERATE POSTURE")
    builder.add_executive_summary(dist=dist, total_raw=len(raw_findings), dup_groups=dup_groups, overall_rating=rating)

    # Perimeter Scope
    builder.add_scope_section(in_scope=in_scope, out_of_scope=out_of_scope)

    # Findings
    builder.add_findings_section(correlated=correlated)

    # Disclaimer
    builder.add_disclaimer()

    return builder.build_pdf()
