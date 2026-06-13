#!/usr/bin/env python3
"""Student-run script for the local LLM red team agent (OWASP Juice Shop)"""
import sys
import os
import inspect

# Add the red-team-agent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'canary', 'red-team-agent'))

# Import the local agent
from agent_local import activate_agent


def main():
    print("=" * 80)
    print("RED TEAM AGENT - LOCAL LLM VERSION")
    print("Target Profile: OWASP Juice Shop (Local)")
    print("=" * 80)
    print()

    # ✅ Juice Shop base URL (IMPORTANT: base origin, not SPA hash routes)
    test_url = "http://localhost:8082"

    model = "llama3.2:latest"

    print(f"🎯 Target: {test_url}")
    print(f"🤖 Model: {model}")
    print()
    print("This run is expected to:")
    print("  - Enumerate common endpoints/paths (REST, swagger, robots, etc.)")
    print("  - Detect Juice Shop XSS via search route (alert-based proof)")
    print("  - Detect Juice Shop SQLi admin login bypass (JWT proof)")
    print()
    print("Starting security test...")
    print()

    try:
        # Some versions of activate_agent accept extra args (like a scenario/instructions).
        # We'll only pass them if the function signature supports it.
        kwargs = dict(
            website_url=test_url,
            model=model,
            include_hints=False,  # ✅ keep runs consistent; hints can encourage extra tool calls
        )

        # Optional: if your activate_agent supports something like "task" or "instructions",
        # pass a focused directive that makes the agent run the expected tools and STOP.
        sig = inspect.signature(activate_agent)
        for candidate_arg in ("instructions", "task", "objective", "scenario"):
            if candidate_arg in sig.parameters:
                kwargs[candidate_arg] = (
                    "Test OWASP Juice Shop specifically. "
                    "Run exactly these tools in order, once each: "
                    "scan_website, discover_api_endpoints, enumerate_directories, check_admin_endpoints, "
                    "juiceshop_xss_search_alert, juiceshop_sqli_admin_login_bypass. "
                    "After they complete, STOP calling tools and write the final report. "
                    "Do NOT take screenshots, navigate pages, search page content, or repeat tools unless a required tool errors."
                )
                break

        result = activate_agent(**kwargs)

        print("\n" + "=" * 80)
        print("✅ TEST COMPLETE")
        print("=" * 80)

        # Report outputs (depends on your implementation)
        if isinstance(result, dict):
            report_file = result.get("report_file")
            run_id = result.get("run_id")

            if report_file:
                print(f"\n📊 Report saved to: {report_file}")
            if run_id:
                print(f"🆔 Run ID: {run_id}")

            # If you have structured output, summarize it (only if present and shaped as expected)
            structured = result.get("structured")
            if isinstance(structured, dict):
                vulns = structured.get("vulnerabilities") or []
                sev = structured.get("severity")
                if vulns:
                    print(f"   - Vulnerabilities found: {len(vulns)}")
                if sev:
                    print(f"   - Severity: {sev}")
        else:
            # If activate_agent returns a string or something else
            print("\nAgent output:")
            print(result)

        return 0

    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\nTroubleshooting:")
        print("  1. Make sure Juice Shop is running on localhost:8082")
        print("  2. Make sure Ollama is running: ollama serve")
        print("  3. Pull the model: ollama pull llama3.2:latest")
        print("  4. If tools fail, verify Playwright is installed and browsers are installed:")
        print("     pip install playwright && playwright install")
        return 1


if __name__ == "__main__":
    sys.exit(main())

