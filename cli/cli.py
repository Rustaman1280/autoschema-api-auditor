"""
Command Line Interface for AutoSchema & API Auditor.
Provides commands for running audits on schema/API files, running end-to-end demos,
and configuring audit workflows.
"""

import sys
import os
import argparse
from pathlib import Path

# Ensure cli directory is on sys.path
BASE_DIR = Path(__file__).parent.resolve()
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from config import Config
from agent import AutoSchemaAuditorAgent
from system_prompt import MASTER_SYSTEM_PROMPT

def print_banner():
    print("""
================================================================================
           AUTOSCHEMA & API AUDITOR - AUTONOMOUS SECURITY & PERF AGENT          
================================================================================
    """)

def run_audit(file_path: str, output_path: str = None, mock: bool = False, verbose: bool = False):
    p = Path(file_path)
    if not p.exists():
        print(f"[-] Error: Target file '{file_path}' does not exist.")
        sys.exit(1)

    with open(p, "r", encoding="utf-8") as f:
        content = f.read()

    print(f"[*] Target Component File: {file_path} ({len(content)} bytes)")
    print(f"[*] Mode: {'Simulation / Dry-Run' if mock or not Config.is_nebius_configured() else 'Live Nebius Token Factory'}")
    if Config.is_nebius_configured() and not mock:
        print(f"[*] Engine: {Config.MODEL_NAME} @ {Config.NEBIUS_BASE_URL}")
        print(f"[*] Search Provider: {'Live Tavily API' if Config.is_tavily_configured() else 'Internal Intelligence Cache'}")

    print("\n[*] Initializing Autonomous Agent Loop...\n")

    def step_callback(event: str, data: dict):
        if event == "step_start":
            print(f"  --> [Turn {data.get('iteration')}] Analyzing AST & Triage...")
        elif event == "tool_call":
            print(f"  --> [Tool Invocation] {data.get('name')}: {data.get('args')}")
        elif event == "tool_result":
            res_preview = str(data.get('output'))[:140].replace('\n', ' ')
            print(f"      [Verified Intelligence] {res_preview}...")
        elif event == "completed":
            print("  --> [Synthesis Complete] Final production remediation synthesized.")

    agent = AutoSchemaAuditorAgent()
    report = agent.audit(content, on_step_callback=step_callback, force_simulation=mock)

    print("\n" + "=" * 80)
    print("                              AUDIT REPORT                              ")
    print("=" * 80 + "\n")
    print(report)

    # Save output if specified or default to reports directory
    if not output_path:
        reports_dir = Path(Config.REPORTS_DIR)
        reports_dir.mkdir(parents=True, exist_ok=True)
        base_name = p.stem
        output_path = str(reports_dir / f"audit_report_{base_name}.md")

    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(report)

    print("\n" + "=" * 80)
    print(f"[+] Report successfully saved to: {out_file.resolve()}")
    print("=" * 80)

def main():
    parser = argparse.ArgumentParser(
        description="AutoSchema & API Auditor: Autonomous Security Engineer & Database Performance Architect"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command: audit
    audit_parser = subparsers.add_parser("audit", help="Audit a database schema or API controller file")
    audit_parser.add_argument("--file", "-f", required=True, help="Path to schema (.sql, .prisma) or API file (.ts, .js, .py)")
    audit_parser.add_argument("--output", "-o", help="Custom output path for the generated markdown report")
    audit_parser.add_argument("--mock", "-m", action="store_true", help="Force simulation mode without calling live APIs")
    audit_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose debug logging")

    # Command: demo
    demo_parser = subparsers.add_parser("demo", help="Run end-to-end audit demonstration on bundled test cases")
    demo_parser.add_argument("--mock", "-m", action="store_true", default=True, help="Run in mock/simulation mode (default: True)")

    # Command: prompt
    prompt_parser = subparsers.add_parser("prompt", help="Display the active Master System Prompt")

    args = parser.parse_args()

    print_banner()

    if args.command == "audit":
        run_audit(args.file, args.output, mock=args.mock, verbose=args.verbose)
    elif args.command == "demo":
        print("[*] Running End-to-End Auditor Demonstration on Sample Inputs...\n")
        sample_sql = BASE_DIR.parent / "sample_inputs" / "ecommerce_schema.sql"
        if not sample_sql.exists():
            sample_sql = BASE_DIR / "sample_inputs" / "ecommerce_schema.sql"

        sample_api = BASE_DIR.parent / "sample_inputs" / "order_controller.ts"
        if not sample_api.exists():
            sample_api = BASE_DIR / "sample_inputs" / "order_controller.ts"

        print("\n--- TEST CASE 1: E-Commerce Database Schema ---")
        run_audit(str(sample_sql), mock=True)

        print("\n--- TEST CASE 2: Order Controller API ---")
        run_audit(str(sample_api), mock=True)
    elif args.command == "prompt":
        print(MASTER_SYSTEM_PROMPT)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
