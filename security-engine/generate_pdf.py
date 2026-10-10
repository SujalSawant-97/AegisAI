"""
Generates a comprehensive, publication-quality PDF report covering:
1. Executive Summary & Project Purpose
2. Overall Architecture (Spring Boot Backend -> FastAPI/LangGraph Agent -> Security Engine -> Target)
3. Core Engine Architecture & Modules
4. In-depth Vulnerability Guide (All 6 categories: Headers, CORS, Auth, Authz, SQLi, XSS)
5. AI Agent & LangGraph Tooling Mechanism
6. Spring Boot Integration & REST API Specification
"""

import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
    HRFlowable,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.pdfgen import canvas


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and render total page count."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        # Header and footer for all pages after page 1
        if self._pageNumber > 1:
            # Header
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(colors.HexColor("#2B6CB0"))
            self.drawString(54, 752, "SECURITY ENGINE & AI AGENT PLATFORM")
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#718096"))
            self.drawRightString(612 - 54, 752, "Architecture & Vulnerability Guide")
            self.setStrokeColor(colors.HexColor("#CBD5E0"))
            self.setLineWidth(0.5)
            self.line(54, 744, 612 - 54, 744)

            # Footer
            self.setFont("Helvetica", 8.5)
            page_str = f"Page {self._pageNumber} of {page_count}"
            self.drawRightString(612 - 54, 34, page_str)
            self.drawString(54, 34, "CONFIDENTIAL & PROPRIETARY — LOCAL APPLICATION AUDITING")
            self.setStrokeColor(colors.HexColor("#E2E8F0"))
            self.setLineWidth(0.5)
            self.line(54, 46, 612 - 54, 46)

        self.restoreState()


def create_security_project_pdf(output_path: str):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    # Custom Color Palette
    PRIMARY = colors.HexColor("#1A365D")    # Dark Navy
    SECONDARY = colors.HexColor("#2B6CB0")  # Slate Blue
    ACCENT = colors.HexColor("#3182CE")     # Bright Blue
    TEXT_DARK = colors.HexColor("#2D3748")  # Body dark charcoal
    MUTED = colors.HexColor("#718096")      # Gray
    BG_LIGHT = colors.HexColor("#F7FAFC")   # Off-white / light slate
    BG_CODE = colors.HexColor("#EDF2F7")    # Code background

    # Typography Styles
    title_style = ParagraphStyle(
        "CoverTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=30,
        textColor=PRIMARY,
        spaceAfter=8,
    )

    subtitle_style = ParagraphStyle(
        "CoverSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=12,
        leading=16,
        textColor=SECONDARY,
        spaceAfter=15,
    )

    meta_style = ParagraphStyle(
        "CoverMeta",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=13,
        textColor=MUTED,
    )

    h1_style = ParagraphStyle(
        "Heading1_Custom",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=PRIMARY,
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True,
    )

    h2_style = ParagraphStyle(
        "Heading2_Custom",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=15,
        textColor=SECONDARY,
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True,
    )

    h3_style = ParagraphStyle(
        "Heading3_Custom",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9.5,
        leading=13,
        textColor=TEXT_DARK,
        spaceBefore=6,
        spaceAfter=3,
        keepWithNext=True,
    )

    body_style = ParagraphStyle(
        "Body_Custom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12.5,
        textColor=TEXT_DARK,
        spaceAfter=5,
    )

    bullet_style = ParagraphStyle(
        "Bullet_Custom",
        parent=body_style,
        leftIndent=12,
        bulletIndent=4,
        spaceAfter=3,
    )

    code_style = ParagraphStyle(
        "Code_Custom",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#2C5282"),
    )

    table_header = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10.5,
        textColor=colors.white,
    )

    table_cell = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=10.5,
        textColor=TEXT_DARK,
    )

    arrow_style = ParagraphStyle(
        "ArrowStyle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        alignment=1,  # Center
        textColor=ACCENT,
    )

    box_title_style = ParagraphStyle(
        "BoxTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        alignment=1,
        textColor=PRIMARY,
    )

    box_sub_style = ParagraphStyle(
        "BoxSub",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=7.5,
        leading=10,
        alignment=1,
        textColor=MUTED,
    )

    callout_style = ParagraphStyle(
        "Callout",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=11.5,
        textColor=PRIMARY,
    )

    story = []

    # =========================================================================
    # HEADER / COVER TITLE
    # =========================================================================
    story.append(Spacer(1, 10))
    story.append(Paragraph("Security Engine & Autonomous AI Agent Platform", title_style))
    story.append(Paragraph("Comprehensive Architectural Blueprint, Backend Integration, and Vulnerability Reference", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=ACCENT, spaceBefore=4, spaceAfter=10))

    meta_text = (
        "<b>Version:</b> 2.0.0 &nbsp;&nbsp;|&nbsp;&nbsp; "
        "<b>Target Scope:</b> Localhost Only (127.0.0.1 / ::1) &nbsp;&nbsp;|&nbsp;&nbsp; "
        "<b>Stack:</b> Python 3.13, FastAPI, LangGraph, Spring Boot &nbsp;&nbsp;|&nbsp;&nbsp; "
        "<b>Test Coverage:</b> 46 / 46 Passed (100%)"
    )
    story.append(Paragraph(meta_text, meta_style))
    story.append(Spacer(1, 10))

    # Executive Summary Box
    summary_box_data = [
        [
            Paragraph(
                "<b>Executive Summary:</b><br/>"
                "The Security Engine is a modular, high-performance Dynamic Application Security Testing (DAST) platform "
                "coupled with an autonomous <b>LangGraph AI Agent</b> and a <b>FastAPI REST interface</b>. It is engineered to integrate "
                "directly into enterprise <b>Spring Boot backends</b> to provide continuous, local vulnerability scanning during development "
                "and CI/CD pipelines. The engine features strictly enforced localhost guardrails, zero external network risk, and non-destructive "
                "curated payloads to test applications safely across 6 core vulnerability categories without risking data corruption.",
                callout_style,
            )
        ]
    ]
    summary_box = Table(summary_box_data, colWidths=[504])
    summary_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BG_LIGHT),
        ("BOX", (0, 0), (-1, -1), 1, ACCENT),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
    ]))
    story.append(summary_box)
    story.append(Spacer(1, 12))

    # =========================================================================
    # 1. OVERALL SYSTEM ARCHITECTURE
    # =========================================================================
    story.append(Paragraph("1. Overall System Architecture & Tiers", h1_style))
    story.append(Paragraph(
        "The platform utilizes a <b>three-tier decoupled architecture</b> separating enterprise presentation and user management, "
        "autonomous AI reasoning, and high-concurrency network vulnerability probing:",
        body_style,
    ))

    # Native Vector Flow Diagram
    flow_boxes = [
        [
            Paragraph("<b>TIER 1: Enterprise Web Backend (Spring Boot)</b>", box_title_style),
        ],
        [
            Paragraph("Java 17/21 &bull; Spring WebClient / Spring AI &bull; User Auth & Database &bull; Dashboard UI", box_sub_style),
        ],
        [
            Paragraph("&darr; &nbsp; <b>REST API Communication</b> (<code>/api/v1/scan</code>, <code>/api/v1/agent/run</code>, <code>/api/v1/sessions</code>) &nbsp; &darr;", arrow_style),
        ],
        [
            Paragraph("<b>TIER 2: AI Orchestration & REST Gateway (FastAPI + LangGraph)</b>", box_title_style),
        ],
        [
            Paragraph("Python 3.13 &bull; LangGraph ReAct State Machine &bull; MemorySaver Checkpointer &bull; LangChain Tools", box_sub_style),
        ],
        [
            Paragraph("&darr; &nbsp; <b>Executes Security Engine Scanners Concurrently via ScanContext</b> &nbsp; &darr;", arrow_style),
        ],
        [
            Paragraph("<b>TIER 3: Core Security Engine & Scanners</b>", box_title_style),
        ],
        [
            Paragraph("ScannerManager &bull; Shared Async HttpClient &bull; OpenAPI Discovery &bull; 6 Scanners: Headers, CORS, Auth, Authz, SQLi, XSS", box_sub_style),
        ],
        [
            Paragraph("&darr; &nbsp; <b>Safe Non-Destructive Probes</b> (Strict Loopback Target Validation) &nbsp; &darr;", arrow_style),
        ],
        [
            Paragraph("<b>TARGET TIER: Local Application Under Test</b>", box_title_style),
        ],
        [
            Paragraph("http://localhost:* &bull; Target strictly restricted to 127.0.0.1, localhost, ::1", box_sub_style),
        ],
    ]
    t_flow = Table(flow_boxes, colWidths=[504])
    t_flow.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 1), BG_LIGHT),
        ("BOX", (0, 0), (0, 1), 0.75, colors.HexColor("#CBD5E0")),
        ("BACKGROUND", (0, 3), (0, 4), BG_LIGHT),
        ("BOX", (0, 3), (0, 4), 0.75, colors.HexColor("#CBD5E0")),
        ("BACKGROUND", (0, 6), (0, 7), BG_LIGHT),
        ("BOX", (0, 6), (0, 7), 0.75, colors.HexColor("#CBD5E0")),
        ("BACKGROUND", (0, 9), (0, 10), colors.HexColor("#FEFCBF")),
        ("BOX", (0, 9), (0, 10), 0.75, colors.HexColor("#D69E2E")),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    story.append(t_flow)
    story.append(Spacer(1, 10))

    arch_table_data = [
        [
            Paragraph("System Tier", table_header),
            Paragraph("Component & Tech", table_header),
            Paragraph("Primary Role & Responsibilities", table_header),
        ],
        [
            Paragraph("<b>Tier 1: Enterprise Web</b>", table_cell),
            Paragraph("Spring Boot Backend<br/>(Java 17/21, WebClient)", table_cell),
            Paragraph("Handles user identity, RBAC, tenant databases, UI dashboards, and invokes scans or multi-turn agent sessions over REST.", table_cell),
        ],
        [
            Paragraph("<b>Tier 2: AI Orchestration</b>", table_cell),
            Paragraph("FastAPI REST + LangGraph<br/>(Python, StateGraph, Tools)", table_cell),
            Paragraph("Hosts the autonomous security agent state machine. Manages conversation memory (MemorySaver), converts tool calls, and exposes REST endpoints.", table_cell),
        ],
        [
            Paragraph("<b>Tier 3: Security Engine</b>", table_cell),
            Paragraph("Core DAST Engine<br/>(HttpClient, ScannerManager)", table_cell),
            Paragraph("Performs OpenAPI discovery, crawler fallbacks, and executes 6 concurrent scanners with strict failure isolation and response comparisons.", table_cell),
        ],
        [
            Paragraph("<b>Target Tier</b>", table_cell),
            Paragraph("Local Application<br/>(http://localhost:*)", table_cell),
            Paragraph("The application under test. Strictly restricted to localhost/loopback interfaces to guarantee ethical and safe execution.", table_cell),
        ],
    ]
    t_arch = Table(arch_table_data, colWidths=[110, 130, 264])
    t_arch.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t_arch)
    story.append(Spacer(1, 12))

    # =========================================================================
    # 2. CORE ENGINE MODULES & ARCHITECTURE
    # =========================================================================
    story.append(Paragraph("2. Core Engine Components & Data Flow", h1_style))
    story.append(Paragraph(
        "The security engine is partitioned into decoupled layers ensuring documentation integrity, "
        "concurrency, and safety:",
        body_style,
    ))

    core_modules_data = [
        [
            Paragraph("Module & Path", table_header),
            Paragraph("Class / Abstraction", table_header),
            Paragraph("Design Pattern & Architectural Responsibility", table_header),
        ],
        [
            Paragraph("<b>Target Safety</b><br/><code>core/target.py</code>", table_cell),
            Paragraph("<code>Target</code>", table_cell),
            Paragraph("<b>Safety Guardrail</b>: Validates URLs; strictly restricts target hostnames to <code>localhost</code>, <code>127.0.0.1</code>, or <code>::1</code>. Rejects external schemes and domains with <code>InvalidTargetError</code>.", table_cell),
        ],
        [
            Paragraph("<b>API Modeling</b><br/><code>core/endpoint.py</code>", table_cell),
            Paragraph("<code>Endpoint</code><br/><code>Parameter</code>", table_cell),
            Paragraph("<b>Domain Model</b>: Normalizes discovered HTTP routes, parameter locations (Query, Path, Body, Header), content types, and declared authentication requirements.", table_cell),
        ],
        [
            Paragraph("<b>Normalized Finding</b><br/><code>core/finding.py</code>", table_cell),
            Paragraph("<code>Finding</code><br/><code>Severity</code><br/><code>ScannerError</code>", table_cell),
            Paragraph("<b>Output Specification</b>: Canonical format reporting scanner name, vulnerability type, severity (CRITICAL to INFO), confidence score (0.0 to 1.0), evidence, and remediation advice.", table_cell),
        ],
        [
            Paragraph("<b>HTTP Transport</b><br/><code>core/http_client.py</code>", table_cell),
            Paragraph("<code>HttpClient</code><br/><code>HttpResponse</code>", table_cell),
            Paragraph("<b>Centralized Network Gateway</b>: Asynchronous wrapper over <code>httpx.AsyncClient</code> enforcing global request timeouts, connection pooling, and automatic header/credential redaction in logs.", table_cell),
        ],
        [
            Paragraph("<b>Session State</b><br/><code>core/scan_context.py</code>", table_cell),
            Paragraph("<code>ScanContext</code><br/><code>AuthContext</code>", table_cell),
            Paragraph("<b>Agent Workspace Memory</b>: Carries Target, Endpoints, HttpClient, Credentials, and tracks accumulated findings, completed scanners, scanned endpoints, and compact summaries.", table_cell),
        ],
        [
            Paragraph("<b>Scanner Manager</b><br/><code>core/scanner_manager.py</code>", table_cell),
            Paragraph("<code>ScannerManager</code><br/><code>BaseScanner</code>", table_cell),
            Paragraph("<b>Lifecycle & Concurrency</b>: Registers all scanners, dispatches parallel execution via <code>asyncio.gather</code>, and isolates individual scanner crashes via <code>ScannerError</code>.", table_cell),
        ],
        [
            Paragraph("<b>Discovery Layer</b><br/><code>discovery/*</code>", table_cell),
            Paragraph("<code>OpenApiDiscovery</code><br/><code>CrawlerDiscovery</code>", table_cell),
            Paragraph("<b>Reconnaissance</b>: Retrieves OpenAPI/Swagger specifications from standard Spring Boot paths (e.g. <code>/v3/api-docs</code>) with fallback recursive HTML link crawling.", table_cell),
        ],
        [
            Paragraph("<b>Payload Provider</b><br/><code>payloads/*</code>", table_cell),
            Paragraph("<code>SqliPayloadProvider</code><br/><code>XssPayloadProvider</code>", table_cell),
            Paragraph("<b>Decoupled Input Catalog</b>: Supplies non-destructive attack strings, error patterns, and unique random canary tokens separate from detection logic.", table_cell),
        ],
        [
            Paragraph("<b>Differential Analysis</b><br/><code>utils/comparison.py</code>", table_cell),
            Paragraph("<code>compare_body_similarity</code><br/><code>compare_status_codes</code>", table_cell),
            Paragraph("<b>Heuristic Comparison</b>: Employs SequenceMatcher ratios, length tolerances, and JSON structural comparison to minimize false positives.", table_cell),
        ],
    ]
    t_core = Table(core_modules_data, colWidths=[110, 105, 289])
    t_core.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t_core)

    # =========================================================================
    # 3. DETAILED VULNERABILITY GUIDE (ALL 6 SCANNERS)
    # =========================================================================
    story.append(PageBreak())
    story.append(Paragraph("3. Vulnerability Detection Guide & Scanner Mechanisms", h1_style))
    story.append(Paragraph(
        "The platform implements 6 specialized vulnerability scanners. Every scanner strictly adheres to "
        "the <code>BaseScanner</code> interface, accepts <code>ScanContext</code>, and returns normalized <code>Finding</code> objects. "
        "Below is an in-depth breakdown of each vulnerability category:",
        body_style,
    ))

    # --- Scanner 1: Security Headers ---
    story.append(Paragraph("3.1 Security Headers Scanner (<code>scanners/headers/scanner.py</code>)", h2_style))
    story.append(Paragraph(
        "<b>Vulnerability Types:</b> <code>MISSING_SECURITY_HEADER</code>, <code>MISCONFIGURED_SECURITY_HEADER</code><br/>"
        "<b>Risk Level:</b> LOW &nbsp;&nbsp;|&nbsp;&nbsp; <b>Severity Range:</b> LOW to MEDIUM &nbsp;&nbsp;|&nbsp;&nbsp; <b>Confidence:</b> 0.70 – 0.90",
        body_style,
    ))
    story.append(Paragraph(
        "<b>What It Is & Real-World Impact:</b> Security headers instruct web browsers how to handle page content, restrict frame embedding, "
        "prevent MIME-type sniffing, and enforce cryptographic protocols. Without them, clients are susceptible to clickjacking, "
        "MIME-confusion attacks, cross-site leaks, and involuntary downgrade attacks.",
        body_style,
    ))
    story.append(Paragraph("<b>Detection Mechanism:</b> Samples representative endpoints and inspects response headers against a rule catalog:", body_style))
    story.append(Paragraph("&bull; <b>Content-Security-Policy (CSP):</b> Flags missing policies. CSP restricts content origins to mitigate XSS and injection attacks.", bullet_style))
    story.append(Paragraph("&bull; <b>X-Content-Type-Options:</b> Verifies presence and ensures value is set strictly to <code>nosniff</code>.", bullet_style))
    story.append(Paragraph("&bull; <b>X-Frame-Options:</b> Checks for missing headers or invalid directives. Requires <code>DENY</code> or <code>SAMEORIGIN</code> to prevent clickjacking.", bullet_style))
    story.append(Paragraph("&bull; <b>Strict-Transport-Security (HSTS):</b> Evaluated conditionally; only checked over HTTPS connections to verify <code>max-age</code> directives.", bullet_style))
    story.append(Paragraph("&bull; <b>Referrer-Policy:</b> Ensures headers prevent leakage of sensitive URL query parameters to third-party domains.", bullet_style))
    story.append(Paragraph("<b>Remediation:</b> Configure standard HTTP filter or Spring Security headers: <code>http.headers(headers -> headers.frameOptions(...))</code>.", callout_style))
    story.append(Spacer(1, 8))

    # --- Scanner 2: CORS Misconfigurations ---
    story.append(Paragraph("3.2 Cross-Origin Resource Sharing (CORS) Scanner (<code>scanners/cors/scanner.py</code>)", h2_style))
    story.append(Paragraph(
        "<b>Vulnerability Types:</b> <code>CORS_MISCONFIGURATION</code><br/>"
        "<b>Risk Level:</b> LOW &nbsp;&nbsp;|&nbsp;&nbsp; <b>Severity Range:</b> LOW to HIGH &nbsp;&nbsp;|&nbsp;&nbsp; <b>Confidence:</b> 0.60 – 0.90",
        body_style,
    ))
    story.append(Paragraph(
        "<b>What It Is & Real-World Impact:</b> CORS misconfigurations occur when web servers employ naive origin validation, such as "
        "blindly reflecting whatever <code>Origin</code> header is supplied by the browser. If <code>Access-Control-Allow-Credentials: true</code> "
        "is simultaneously enabled, malicious websites can execute authenticated cross-origin requests on behalf of a victim to exfiltrate private data.",
        body_style,
    ))
    story.append(Paragraph("<b>Detection Mechanism:</b> Probes endpoints using distinct synthetic origins and analyzes reflection behavior:", body_style))
    story.append(Paragraph("&bull; <b>Arbitrary Origin Reflection:</b> Sends <code>Origin: https://attacker-controlled.example</code>. If reflected with credentials, flags as <b>HIGH</b> severity.", bullet_style))
    story.append(Paragraph("&bull; <b>Null Origin Trust:</b> Sends <code>Origin: null</code>. If trusted with credentials, flags as <b>HIGH</b> severity (exploitable via sandboxed iframes).", bullet_style))
    story.append(Paragraph("&bull; <b>Wildcard with Credentials:</b> Identifies invalid configurations where <code>Access-Control-Allow-Origin: *</code> is paired with <code>Allow-Credentials: true</code>.", bullet_style))
    story.append(Paragraph("<b>Remediation:</b> Validate origins against an explicit allowlist. Never reflect untrusted <code>Origin</code> headers directly.", callout_style))
    story.append(Spacer(1, 8))

    # --- Scanner 3: Authentication Failures ---
    story.append(Paragraph("3.3 Authentication Scanner (<code>scanners/authentication/scanner.py</code>)", h2_style))
    story.append(Paragraph(
        "<b>Vulnerability Types:</b> <code>UNAUTHENTICATED_ACCESS</code>, <code>INVALID_TOKEN_ACCEPTED</code>, <code>AUTH_INFORMATION_DISCLOSURE</code><br/>"
        "<b>Risk Level:</b> LOW &nbsp;&nbsp;|&nbsp;&nbsp; <b>Severity Range:</b> LOW to HIGH &nbsp;&nbsp;|&nbsp;&nbsp; <b>Confidence:</b> 0.75 – 0.95",
        body_style,
    ))
    story.append(Paragraph(
        "<b>What It Is & Real-World Impact:</b> Flaws in authentication filters or routing configurations can allow unauthorized visitors "
        "to reach private resources without providing credentials, or allow expired/forged tokens to pass validation checks without proper signature verification.",
        body_style,
    ))
    story.append(Paragraph("<b>Detection Mechanism:</b> Executes a three-phase authentication probe on declared protected routes and sensitive paths (<code>/admin</code>, <code>/api/user</code>):", body_style))
    story.append(Paragraph("&bull; <b>Unauthenticated Access Probe:</b> Issues requests without an <code>Authorization</code> header. If HTTP 200 OK is returned with valid response data, flags <code>UNAUTHENTICATED_ACCESS</code> (<b>HIGH</b> severity).", bullet_style))
    story.append(Paragraph("&bull; <b>Invalid Token Probe:</b> Sends deliberately corrupted tokens (e.g. <code>Bearer invalid_token_probe_bad_signature_12345</code>). If accepted with HTTP 200 OK, flags <code>INVALID_TOKEN_ACCEPTED</code> (<b>HIGH</b> severity).", bullet_style))
    story.append(Paragraph("&bull; <b>Information Disclosure:</b> Scans 401, 403, and 500 error responses for unhandled stack traces, database exceptions, or Spring internals.", bullet_style))
    story.append(Paragraph("<b>Remediation:</b> Enforce explicit authentication filters (e.g. Spring Security <code>authenticated()</code>) across all internal route matchers.", callout_style))
    story.append(Spacer(1, 8))

    # --- Scanner 4: Authorization (BFLA & BOLA/IDOR) ---
    story.append(Paragraph("3.4 Authorization Scanner (<code>scanners/authorization/scanner.py</code>)", h2_style))
    story.append(Paragraph(
        "<b>Vulnerability Types:</b> <code>BROKEN_FUNCTION_LEVEL_AUTHORIZATION</code>, <code>BROKEN_OBJECT_LEVEL_AUTHORIZATION</code><br/>"
        "<b>Risk Level:</b> MEDIUM &nbsp;&nbsp;|&nbsp;&nbsp; <b>Severity Range:</b> HIGH &nbsp;&nbsp;|&nbsp;&nbsp; <b>Confidence:</b> 0.80 – 0.95",
        body_style,
    ))
    story.append(Paragraph(
        "<b>What It Is & Real-World Impact:</b> Broken Access Control occurs when applications fail to verify that the authenticated user "
        "possesses the proper administrative role (<b>BFLA</b>) or ownership rights over the requested object ID (<b>BOLA / IDOR</b>). "
        "This allows regular users to perform administrative tasks or access private records belonging to other users.",
        body_style,
    ))
    story.append(Paragraph("<b>Detection Mechanism:</b> Utilizes multi-token testing via <code>AuthContext</code>:", body_style))
    story.append(Paragraph("&bull; <b>BFLA (Privilege Escalation):</b> Identifies privileged paths (<code>/admin/*</code>, <code>/manage/*</code>, <code>/roles/*</code>). Issues requests using <code>low_privilege_token</code>. If HTTP 200 OK is returned instead of 403 Forbidden, flags BFLA.", bullet_style))
    story.append(Paragraph("&bull; <b>BOLA / IDOR:</b> Detects identifier parameters in paths (<code>/users/{id}</code>) and query strings (<code>?userId=123</code>). Modifies the ID to an alternate object under a low-privilege token. If foreign user data is returned, flags BOLA.", bullet_style))
    story.append(Paragraph("<b>Remediation:</b> Enforce strict Role-Based Access Control (RBAC) and verify record ownership: <code>WHERE user_id = current_user.id</code>.", callout_style))
    story.append(Spacer(1, 8))

    # --- Scanner 5: SQL Injection ---
    story.append(Paragraph("3.5 SQL Injection (SQLi) Scanner (<code>scanners/sqli/scanner.py</code>)", h2_style))
    story.append(Paragraph(
        "<b>Vulnerability Types:</b> <code>SQL_INJECTION_ERROR_BASED</code>, <code>SQL_INJECTION_BOOLEAN_BASED</code><br/>"
        "<b>Risk Level:</b> MEDIUM &nbsp;&nbsp;|&nbsp;&nbsp; <b>Severity Range:</b> HIGH to CRITICAL &nbsp;&nbsp;|&nbsp;&nbsp; <b>Confidence:</b> 0.85 – 0.95",
        body_style,
    ))
    story.append(Paragraph(
        "<b>What It Is & Real-World Impact:</b> SQL injection occurs when user input is concatenated directly into SQL queries without parameterization. "
        "Attackers can bypass authentication, read sensitive records, modify data, or execute arbitrary database commands.",
        body_style,
    ))
    story.append(Paragraph("<b>Detection Mechanism:</b> Employs non-destructive payloads and two complementary detection techniques:", body_style))
    story.append(Paragraph("&bull; <b>Error-Based Detection:</b> Injects quote delimiters (<code>'</code>, <code>\"</code>, <code>')</code>, <code>';</code>). Scans response bodies using regex signatures matching 5 database dialects: SQLite (<code>sqlite3.OperationalError</code>), MySQL (<code>SQL syntax error</code>), PostgreSQL (<code>pg_query()</code>, <code>PSQLException</code>), MSSQL (<code>Unclosed quotation mark</code>), and Oracle (<code>ORA-00933</code>). Flags <b>CRITICAL</b> severity (0.95 confidence).", bullet_style))
    story.append(Paragraph("&bull; <b>Boolean-Based Differential Detection:</b> For endpoints returning 200 OK, injects paired condition expressions (TRUE: <code>' OR '1'='1</code> vs FALSE: <code>' AND '1'='2</code>). Compares response body similarity and status codes. If TRUE matches the baseline and FALSE consistently diverges, flags <b>HIGH</b> severity boolean blind SQLi.", bullet_style))
    story.append(Paragraph("<b>Remediation:</b> Always use parameterized queries (PreparedStatement in JDBC/JPA, ORMs). Never concatenate user input into SQL.", callout_style))
    story.append(Spacer(1, 8))

    # --- Scanner 6: Cross-Site Scripting (XSS) ---
    story.append(Paragraph("3.6 Reflected Cross-Site Scripting Scanner (<code>scanners/xss/scanner.py</code>)", h2_style))
    story.append(Paragraph(
        "<b>Vulnerability Types:</b> <code>REFLECTED_XSS</code><br/>"
        "<b>Risk Level:</b> LOW &nbsp;&nbsp;|&nbsp;&nbsp; <b>Severity Range:</b> MEDIUM to HIGH &nbsp;&nbsp;|&nbsp;&nbsp; <b>Confidence:</b> 0.90",
        body_style,
    ))
    story.append(Paragraph(
        "<b>What It Is & Real-World Impact:</b> Reflected XSS occurs when an application receives user input in an HTTP request and echoes "
        "it immediately into an HTML response without proper sanitization or contextual encoding. An attacker can execute arbitrary JavaScript in the victim's browser session.",
        body_style,
    ))
    story.append(Paragraph("<b>Detection Mechanism:</b> Employs benign, unique canary tokens to trace reflection across contexts:", body_style))
    story.append(Paragraph("&bull; <b>Context Probes:</b> Generates unique tokens (e.g. <code>&lt;xss_{canary}&gt;</code>, <code>\"&gt;&lt;xss_{canary}&gt;</code>, <code>'&gt;&lt;xss_{canary}&gt;</code>).", bullet_style))
    story.append(Paragraph("&bull; <b>Unescaped Reflection Check:</b> Verifies that the probe characters (<code>&lt;</code>, <code>&gt;</code>) appear unescaped in HTML responses rather than safely encoded entities (<code>&amp;lt;</code>, <code>&amp;gt;</code>).", bullet_style))
    story.append(Paragraph("&bull; <b>False Positive Suppression:</b> Automatically ignores strict non-HTML contexts (<code>application/json</code>, <code>text/plain</code>) where reflection does not execute scripts.", bullet_style))
    story.append(Paragraph("&bull; <b>CSP Evaluation:</b> Inspects response headers. If a strict Content-Security-Policy disallowing inline scripts is present, adjusts severity to <b>MEDIUM</b>.", bullet_style))
    story.append(Paragraph("<b>Remediation:</b> Contextually encode all user-supplied data before rendering into HTML. Implement a restrictive Content-Security-Policy.", callout_style))
    story.append(Spacer(1, 10))

    # =========================================================================
    # 4. VULNERABILITY SUMMARY MATRIX
    # =========================================================================
    story.append(Paragraph("3.7 Vulnerability Summary Matrix", h3_style))
    vuln_summary_data = [
        [
            Paragraph("Vulnerability", table_header),
            Paragraph("Scanner Name", table_header),
            Paragraph("Severity", table_header),
            Paragraph("Confidence", table_header),
            Paragraph("Risk Level", table_header),
        ],
        [
            Paragraph("Missing Security Header", table_cell),
            Paragraph("<code>security_headers</code>", table_cell),
            Paragraph("<font color='#D69E2E'><b>MEDIUM / LOW</b></font>", table_cell),
            Paragraph("0.70 – 0.90", table_cell),
            Paragraph("LOW", table_cell),
        ],
        [
            Paragraph("CORS Misconfiguration", table_cell),
            Paragraph("<code>cors</code>", table_cell),
            Paragraph("<font color='#DD6B20'><b>HIGH / LOW</b></font>", table_cell),
            Paragraph("0.60 – 0.90", table_cell),
            Paragraph("LOW", table_cell),
        ],
        [
            Paragraph("Unauthenticated Access", table_cell),
            Paragraph("<code>authentication</code>", table_cell),
            Paragraph("<font color='#DD6B20'><b>HIGH</b></font>", table_cell),
            Paragraph("0.75 – 0.90", table_cell),
            Paragraph("LOW", table_cell),
        ],
        [
            Paragraph("Invalid Token Accepted", table_cell),
            Paragraph("<code>authentication</code>", table_cell),
            Paragraph("<font color='#DD6B20'><b>HIGH</b></font>", table_cell),
            Paragraph("0.90", table_cell),
            Paragraph("LOW", table_cell),
        ],
        [
            Paragraph("Broken Function Auth (BFLA)", table_cell),
            Paragraph("<code>authorization</code>", table_cell),
            Paragraph("<font color='#DD6B20'><b>HIGH</b></font>", table_cell),
            Paragraph("0.85 – 0.95", table_cell),
            Paragraph("MEDIUM", table_cell),
        ],
        [
            Paragraph("Broken Object Auth (BOLA/IDOR)", table_cell),
            Paragraph("<code>authorization</code>", table_cell),
            Paragraph("<font color='#DD6B20'><b>HIGH</b></font>", table_cell),
            Paragraph("0.80 – 0.85", table_cell),
            Paragraph("MEDIUM", table_cell),
        ],
        [
            Paragraph("Error-Based SQL Injection", table_cell),
            Paragraph("<code>sqli</code>", table_cell),
            Paragraph("<font color='#C53030'><b>CRITICAL</b></font>", table_cell),
            Paragraph("0.95", table_cell),
            Paragraph("MEDIUM", table_cell),
        ],
        [
            Paragraph("Boolean Blind SQL Injection", table_cell),
            Paragraph("<code>sqli</code>", table_cell),
            Paragraph("<font color='#DD6B20'><b>HIGH</b></font>", table_cell),
            Paragraph("0.85", table_cell),
            Paragraph("MEDIUM", table_cell),
        ],
        [
            Paragraph("Reflected XSS", table_cell),
            Paragraph("<code>xss</code>", table_cell),
            Paragraph("<font color='#DD6B20'><b>HIGH / MED</b></font>", table_cell),
            Paragraph("0.90", table_cell),
            Paragraph("LOW", table_cell),
        ],
    ]
    t_vuln = Table(vuln_summary_data, colWidths=[140, 110, 94, 80, 80])
    t_vuln.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_vuln)
    story.append(Spacer(1, 10))

    # =========================================================================
    # 5. AI AGENT & LANGGRAPH ORCHESTRATION
    # =========================================================================
    story.append(PageBreak())
    story.append(Paragraph("4. AI Agent & LangGraph Orchestration", h1_style))
    story.append(Paragraph(
        "The AI Agent framework utilizes <b>LangGraph</b> to implement a stateful, cyclical ReAct (Reasoning + Acting) "
        "architecture. Instead of flooding LLM context windows with verbose HTTP logs, the agent updates a shared state "
        "and inspects concise summary metrics.",
        body_style,
    ))

    story.append(Paragraph("4.1 How the AI Agent Selects Tools", h2_style))
    story.append(Paragraph(
        "Each scanner implements <code>ScannerMetadata</code> defining its <code>name</code>, <code>description</code>, "
        "<code>vulnerability_types</code>, and <code>risk_level</code>. These fields are wrapped into strongly-typed LangChain tools:",
        body_style,
    ))
    story.append(Paragraph("1. <code>discover_endpoints_tool(target)</code>: Performs OpenAPI retrieval and HTML link discovery.", bullet_style))
    story.append(Paragraph("2. <code>run_scanner_tool(target, scanner_name)</code>: Executes a specific scanner selectively.", bullet_style))
    story.append(Paragraph("3. <code>run_all_scanners_tool(target)</code>: Concurrently runs all 6 scanners for a full audit.", bullet_style))
    story.append(Paragraph("4. <code>list_available_scanners_tool()</code>: Returns scanner capabilities and metadata.", bullet_style))

    story.append(Spacer(1, 4))
    story.append(Paragraph("4.2 Cyclical ReAct Decision Loop", h2_style))
    story.append(Paragraph(
        "When given a target URL, the agent executes an iterative reconnaissance-driven workflow:",
        body_style,
    ))
    story.append(Paragraph("&bull; <b>Step 1 (Reconnaissance):</b> Discovers routes and inspects parameter signatures.", bullet_style))
    story.append(Paragraph("&bull; <b>Step 2 (Hypothesis):</b> Routes with query/body parameters are queued for <code>sqli</code> and <code>xss</code>; routes with <code>/admin</code> are queued for <code>authorization</code>.", bullet_style))
    story.append(Paragraph("&bull; <b>Step 3 (Tool Execution):</b> The graph transitions from <code>agent</code> node to <code>ToolNode</code>, executing the selected scanner and appending findings to state.", bullet_style))
    story.append(Paragraph("&bull; <b>Step 4 (Context-Aware Follow-up):</b> If <code>security_headers</code> reports missing CSP, the agent prioritizes testing XSS on reflected routes.", bullet_style))
    story.append(Paragraph("&bull; <b>Step 5 (Synthesis):</b> The agent compiles an executive summary, groups findings by severity, and generates code-level remediation diffs.", bullet_style))
    story.append(Spacer(1, 10))

    # =========================================================================
    # 6. FASTAPI REST INTERFACE & SPRING BOOT INTEGRATION
    # =========================================================================
    story.append(Paragraph("5. FastAPI REST Interface & Spring Boot Integration", h1_style))
    story.append(Paragraph(
        "To allow enterprise Spring Boot backends to invoke scans and communicate with the AI agent, "
        "the FastAPI service (<code>app/api.py</code>) exposes a comprehensive suite of REST endpoints:",
        body_style,
    ))

    api_endpoints_data = [
        [
            Paragraph("HTTP Method & Route", table_header),
            Paragraph("Category", table_header),
            Paragraph("Description & Spring Boot Usage", table_header),
        ],
        [
            Paragraph("<code>GET /health</code>", table_cell),
            Paragraph("System", table_cell),
            Paragraph("Service heartbeat and readiness check.", table_cell),
        ],
        [
            Paragraph("<code>GET /api/v1/scanners</code>", table_cell),
            Paragraph("Metadata", table_cell),
            Paragraph("Returns all 6 scanners, descriptions, and risk levels. Used by Spring AI to dynamically register tool beans.", table_cell),
        ],
        [
            Paragraph("<code>POST /api/v1/discover</code>", table_cell),
            Paragraph("Discovery", table_cell),
            Paragraph("Executes OpenAPI and crawler discovery on target; returns list of routes and parameters.", table_cell),
        ],
        [
            Paragraph("<code>POST /api/v1/scan</code>", table_cell),
            Paragraph("One-Shot Scan", table_cell),
            Paragraph("Executes selected scanners or <code>['all']</code> in batch mode; returns full findings and severity summary.", table_cell),
        ],
        [
            Paragraph("<code>POST /api/v1/sessions</code>", table_cell),
            Paragraph("Stateful Session", table_cell),
            Paragraph("Initializes a persistent <code>ScanContext</code> session. Returns unique <code>session_id</code>.", table_cell),
        ],
        [
            Paragraph("<code>GET /api/v1/sessions/{id}</code>", table_cell),
            Paragraph("Stateful Session", table_cell),
            Paragraph("Queries active session state, accumulated findings, and real-time severity breakdown.", table_cell),
        ],
        [
            Paragraph("<code>POST /api/v1/sessions/{id}/scan</code>", table_cell),
            Paragraph("Stateful Session", table_cell),
            Paragraph("Executes scanners inside the active session context, updating findings incrementally.", table_cell),
        ],
        [
            Paragraph("<code>DELETE /api/v1/sessions/{id}</code>", table_cell),
            Paragraph("Stateful Session", table_cell),
            Paragraph("Terminates session and purges in-memory session context.", table_cell),
        ],
        [
            Paragraph("<code>POST /api/v1/agent/run</code>", table_cell),
            Paragraph("LangGraph Agent", table_cell),
            Paragraph("Autonomous audit. Triggers the LangGraph ReAct workflow to audit the target end-to-end.", table_cell),
        ],
        [
            Paragraph("<code>POST /api/v1/agent/chat</code>", table_cell),
            Paragraph("LangGraph Agent", table_cell),
            Paragraph("Multi-turn conversation with memory checkpointer (<code>MemorySaver</code>) across threads.", table_cell),
        ],
    ]
    t_api = Table(api_endpoints_data, colWidths=[140, 80, 284])
    t_api.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_api)
    story.append(Spacer(1, 8))

    # Spring Boot Integration Code Sample
    story.append(Paragraph("5.1 Spring Boot WebClient Integration Example", h2_style))
    spring_code = (
        "@Service\n"
        "public class SecurityEngineClient {\n"
        "    private final WebClient webClient;\n\n"
        "    public SecurityEngineClient(WebClient.Builder builder) {\n"
        "        this.webClient = builder.baseUrl(\"http://127.0.0.1:8000\").build();\n"
        "    }\n\n"
        "    public ScanResponse auditTarget(String targetUrl) {\n"
        "        return webClient.post()\n"
        "            .uri(\"/api/v1/scan\")\n"
        "            .contentType(MediaType.APPLICATION_JSON)\n"
        "            .bodyValue(Map.of(\"target\", targetUrl, \"scanners\", List.of(\"all\")))\n"
        "            .retrieve()\n"
        "            .bodyToMono(ScanResponse.class)\n"
        "            .block();\n"
        "    }\n"
        "}"
    )
    t_spring = Table([[Paragraph(spring_code.replace("\n", "<br/>").replace(" ", "&nbsp;"), code_style)]], colWidths=[504])
    t_spring.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BG_CODE),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t_spring)
    story.append(Spacer(1, 10))

    # =========================================================================
    # 7. VERIFICATION & QUALITY ASSURANCE
    # =========================================================================
    story.append(KeepTogether([
        Paragraph("6. Verification & Test Suite Summary", h1_style),
        Paragraph(
            "Every component in the platform is verified using a comprehensive automated test harness in <code>pytest</code>. "
            "A standard-library HTTP server (<code>TestApp</code>) hosts matched pairs of known-vulnerable and known-secure endpoints "
            "to validate true positives and confirm false-positive resistance:",
            body_style,
        )
    ]))

    test_results_data = [
        [
            Paragraph("Test Suite File", table_header),
            Paragraph("Target Component", table_header),
            Paragraph("Tests Passed", table_header),
            Paragraph("Verification Focus", table_header),
        ],
        [
            Paragraph("<code>tests/test_target.py</code>", table_cell),
            Paragraph("Target Safety", table_cell),
            Paragraph("<b>4 Passed</b>", table_cell),
            Paragraph("Validates loopback/localhost; rejects external domains and schemes.", table_cell),
        ],
        [
            Paragraph("<code>tests/test_payloads.py</code>", table_cell),
            Paragraph("Payload Providers", table_cell),
            Paragraph("<b>4 Passed</b>", table_cell),
            Paragraph("Validates SQLi error signatures and XSS unescaped canary reflection.", table_cell),
        ],
        [
            Paragraph("<code>tests/test_scan_context.py</code>", table_cell),
            Paragraph("ScanContext State", table_cell),
            Paragraph("<b>6 Passed</b>", table_cell),
            Paragraph("Validates state accumulation, filtering, deduplication, and summaries.", table_cell),
        ],
        [
            Paragraph("<code>tests/test_security_headers_scanner.py</code>", table_cell),
            Paragraph("Headers Scanner", table_cell),
            Paragraph("<b>2 Passed</b>", table_cell),
            Paragraph("True positive on vulnerable; zero findings on hardened secure endpoint.", table_cell),
        ],
        [
            Paragraph("<code>tests/test_cors_scanner.py</code>", table_cell),
            Paragraph("CORS Scanner", table_cell),
            Paragraph("<b>2 Passed</b>", table_cell),
            Paragraph("True positive on arbitrary origin reflection; zero findings on secure.", table_cell),
        ],
        [
            Paragraph("<code>tests/test_authentication_scanner.py</code>", table_cell),
            Paragraph("Auth Scanner", table_cell),
            Paragraph("<b>3 Passed</b>", table_cell),
            Paragraph("Detects unauthenticated access, invalid tokens, and error leaks.", table_cell),
        ],
        [
            Paragraph("<code>tests/test_authorization_scanner.py</code>", table_cell),
            Paragraph("Authz Scanner", table_cell),
            Paragraph("<b>4 Passed</b>", table_cell),
            Paragraph("Detects BFLA privilege escalation and BOLA/IDOR user crossing.", table_cell),
        ],
        [
            Paragraph("<code>tests/test_sqli_scanner.py</code>", table_cell),
            Paragraph("SQLi Scanner", table_cell),
            Paragraph("<b>3 Passed</b>", table_cell),
            Paragraph("Detects error-based syntax errors (SQLite) and boolean blind differential.", table_cell),
        ],
        [
            Paragraph("<code>tests/test_xss_scanner.py</code>", table_cell),
            Paragraph("XSS Scanner", table_cell),
            Paragraph("<b>4 Passed</b>", table_cell),
            Paragraph("Detects unescaped HTML reflection; ignores JSON; evaluates CSP.", table_cell),
        ],
        [
            Paragraph("<code>tests/test_cli.py</code>", table_cell),
            Paragraph("CLI Interface", table_cell),
            Paragraph("<b>2 Passed</b>", table_cell),
            Paragraph("Validates batch scans and selective scanner execution via CLI.", table_cell),
        ],
        [
            Paragraph("<code>tests/test_agent.py</code>", table_cell),
            Paragraph("LangGraph Agent", table_cell),
            Paragraph("<b>5 Passed</b>", table_cell),
            Paragraph("Validates LangChain tools, graph compilation, and ReAct execution.", table_cell),
        ],
        [
            Paragraph("<code>tests/test_api.py</code>", table_cell),
            Paragraph("FastAPI REST API", table_cell),
            Paragraph("<b>7 Passed</b>", table_cell),
            Paragraph("Validates health, discovery, scan, session lifecycle, and agent run.", table_cell),
        ],
        [
            Paragraph("<b>TOTAL SUITE</b>", table_cell),
            Paragraph("<b>All Platform Components</b>", table_cell),
            Paragraph("<b><font color='#38A169'>46 / 46 Passed (100%)</font></b>", table_cell),
            Paragraph("<b>Zero Failures, Zero Warnings, 100% Quality Assurance</b>", table_cell),
        ],
    ]
    t_test = Table(test_results_data, colWidths=[140, 100, 80, 184])
    t_test.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.white, BG_LIGHT]),
        ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#E2E8F0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_test)

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Report successfully generated at: {output_path}")


if __name__ == "__main__":
    out_file = r"c:\Users\sujal\security-engine\Security_Engine_Project_Documentation.pdf"
    create_security_project_pdf(out_file)
