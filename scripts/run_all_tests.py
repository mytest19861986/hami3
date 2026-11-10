"""
Master Automated Test Runner for HamiCard (حامی‌کارت)
Runs all test suites sequentially and provides consolidated results.
"""

import subprocess
import sys
import time

SUITES = [
    ("Phase 1 Database Foundation", "tests/test_phase1_database.py"),
    ("Phase 1 Remediation & Invariants", "tests/test_phase1_remediation.py"),
    ("Phase 2 Auth & 6-Role RBAC", "tests/test_auth_rbac.py"),
    ("Phase 2 Session Concurrency & Rotation", "tests/test_session_concurrency.py"),
    ("Phase 3 Mathematical Validators", "tests/test_validators.py"),
    ("Phase 3 Profiles & Geography Reference", "tests/test_profiles.py"),
    ("Phase 3 Doctors Network & Discount Plans", "tests/test_doctors_and_plans.py"),
    ("Phase 3 CMS & Content Pages", "tests/test_content.py"),
    ("Phase 3 Medical Visits & Quotas", "tests/test_visits.py"),
    ("Phase 3 Wallet & Financial Ledger", "tests/test_wallets.py"),
]

def main():
    print("=" * 80)
    print("HAMICARD (حامی‌کارت) MASTER AUTOMATED TEST SUITE")
    print("Mission: M-HAMICARD-ZERO-TO-PROD | Baseline: BL-HAMICARD-PRD-V1")
    print("=" * 80)

    total_suites = len(SUITES)
    passed_suites = 0
    start_time = time.time()

    for idx, (title, script_path) in enumerate(SUITES, 1):
        print(f"\n[{idx}/{total_suites}] RUNNING SUITE: {title} ({script_path})...")
        res = subprocess.run(
            [sys.executable, script_path],
            capture_output=True,
            text=True,
            env={**subprocess.os.environ, "PYTHONPATH": "."}
        )

        if res.returncode == 0:
            passed_suites += 1
            print(f"  ✓ SUITE {idx} PASSED")
        else:
            print(f"  ✗ SUITE {idx} FAILED (exit code {res.returncode})")
            print("--- STDOUT ---")
            print(res.stdout)
            print("--- STDERR ---")
            print(res.stderr)

    elapsed = time.time() - start_time
    print("\n" + "=" * 80)
    print(f"TEST SUMMARY: {passed_suites}/{total_suites} SUITES PASSED ({passed_suites/total_suites*100:.1f}%) in {elapsed:.2f}s")
    print("=" * 80)

    if passed_suites == total_suites:
        print("ALL TESTS GREEN! ZERO FAILURES!")
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
