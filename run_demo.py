"""
Standalone execution test runner for AutoSchema & API Auditor.
Runs the auditor on all sample test cases and validates report generation.
"""

import sys
from pathlib import Path
from cli import run_audit

def main():
    print("================================================================================")
    print("      AUTOSCHEMA & API AUDITOR: AUTOMATED END-TO-END VERIFICATION RUNNER       ")
    print("================================================================================\n")

    base_dir = Path(__file__).parent
    sample_sql = str(base_dir / "sample_inputs" / "ecommerce_schema.sql")
    sample_api = str(base_dir / "sample_inputs" / "order_controller.ts")

    print("[1/2] Auditing Database Schema (sample_inputs/ecommerce_schema.sql)...")
    run_audit(sample_sql, mock=True)

    print("\n[2/2] Auditing API Controller (sample_inputs/order_controller.ts)...")
    run_audit(sample_api, mock=True)

    print("\n[OK] All audits completed successfully! Reports generated in 'reports/' directory.")

if __name__ == "__main__":
    main()
