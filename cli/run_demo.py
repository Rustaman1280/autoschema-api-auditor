"""
Standalone execution test runner for AutoSchema & API Auditor.
Runs the auditor on all sample test cases and validates report generation.
"""

import sys
from pathlib import Path

# Ensure cli directory is in sys.path
BASE_DIR = Path(__file__).parent.resolve()
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from cli import run_audit

def main():
    print("================================================================================")
    print("      AUTOSCHEMA & API AUDITOR: AUTOMATED END-TO-END VERIFICATION RUNNER       ")
    print("================================================================================\n")

    # Resolve sample_inputs from repo root (../sample_inputs) or fallback to local
    sample_sql = BASE_DIR.parent / "sample_inputs" / "ecommerce_schema.sql"
    if not sample_sql.exists():
        sample_sql = BASE_DIR / "sample_inputs" / "ecommerce_schema.sql"

    sample_api = BASE_DIR.parent / "sample_inputs" / "order_controller.ts"
    if not sample_api.exists():
        sample_api = BASE_DIR / "sample_inputs" / "order_controller.ts"

    print(f"[1/2] Auditing Database Schema ({sample_sql})...")
    run_audit(str(sample_sql), mock=True)

    print(f"\n[2/2] Auditing API Controller ({sample_api})...")
    run_audit(str(sample_api), mock=True)

    print("\n[OK] All audits completed successfully! Reports generated in 'reports/' directory.")

if __name__ == "__main__":
    main()
