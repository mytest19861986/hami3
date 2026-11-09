# تصمیم و فرامین اجرایی فرمانده حامی‌کارت (HC-COMMANDER-003)

# فرمانده حامی‌کارت — تصمیم اجرایی `HC-COMMANDER-003`

FIX_REQUIRED — اصلاح پیش از پذیرش نهایی

نتیجه: انتقال کنترل‌شده شاخه `develop` به GitHub مجاز است. پیاده‌سازی فاز ۲ نیز در محیط محلی مجاز است، مشروط به رعایت اصلاحات امنیتی و مالی گزارش‌شده.

بررسی مجدد مستقیم GitHub نشان می‌دهد مخزن `mytest19861986/hami3` همچنان خالی است و شاخه `develop` یا کامیت `198c4eb96e48629bbf10926066f7cacc8ec89aca` روی Remote قابل مشاهده نیست. بنابراین شواهد تست و بازبینی‌های Qwen و GLM فعلاً در سطح گزارش Executor هستند، نه شواهدی که من مستقلاً خوانده و راستی‌آزمایی کرده باشم.

## تصمیم‌ها

| موضوع                        | حکم فرمانده                                           |
| ---------------------------- | ----------------------------------------------------- |
| Push کامیت محلی به `develop` | مجاز، با بررسی Secret، تطبیق Remote و بدون Force Push |
| پذیرش نهایی فاز ۱            | رد فعلی؛ تا رفع Findings حیاتی                        |
| اصلاح AC-07 و AC-12          | اولویت بحرانی پیاده‌سازی                              |
| طراحی فاز ۲                  | آماده ورود به پیاده‌سازی مشروط                        |
| هسته Auth و RBAC             | مجاز در شاخه ایزوله                                   |
| نشست رقابتی AC-15            | مجاز با تست هم‌زمانی و Replay                         |
| Merge به `main`              | فعلاً ممنوع                                           |
| Tag رسمی Release             | فعلاً ممنوع                                           |
| Production Deploy            | نیازمند تأیید جداگانه مدیر                            |

یک مغایرت دیگر باید بررسی شود: گزارش فاز ۲ از ماتریس پنج نقش صحبت می‌کند، درحالی‌که PRD شش نقش کدگذاری‌شده `USER`، `DOCTOR`، `AGENT`، `SUPPORT`، `ADMIN` و `SUPER_ADMIN` دارد و اختیارات همکار معرفی نیز باید جداگانه مدل شود. هیچ نقش یا اختیار P0 نباید حذف شود.

مسیر اجرای موازی: ابتدا Git و شواهد منتشر شوند؛ اصلاحات فاز ۱ و پیاده‌سازی فاز ۲ می‌توانند در شاخه‌های ایزوله و بدون تداخل پیش بروند. بازبینی مستقل مجدد باید بر روی نسخه‌های دقیق اصلاح‌شده انجام شود.

## فرمان عملیاتی `commander.v2`

```
{
  "schema": "commander.v2",
  "turn_id": "HC-COMMANDER-003",
  "decision": "FIX_REQUIRED",
  "decision_reason": "Git push to the nonprotected develop branch is conditionally authorized. Independent reviewers reportedly found issues requiring fixes. Phase 2 local implementation is authorized with security gates; Phase 1 and Phase 2 are not yet accepted.",
  "confidence": "HIGH",
  "state_update": {
    "phase": "PHASE_1_REMEDIATION_AND_PHASE_2_IMPLEMENTATION",
    "status": "GIT_PUSH_AUTHORIZED_CONDITIONALLY | PHASE_1_FIX_REQUIRED | PHASE_2_LOCAL_IMPLEMENTATION_AUTHORIZED | FINAL_ACCEPTANCE_PENDING",
    "completed": [],
    "in_progress": [],
    "blocked": [
      "Phase 1 acceptance until review findings are resolved and verified",
      "Merge into main until technical and product acceptance",
      "Release tags until verified milestones",
      "Production deployment until owner approval and release gates"
    ],
    "decisions": [
      {
        "id": "HC-D08",
        "text": "Allow normal non-force push of exact verified local develop commit to origin/develop.",
        "reason": "The manager requested GitHub version tracking, and the remote is currently empty. Pre-push inspection and post-push verification are mandatory."
      },
      {
        "id": "HC-D09",
        "text": "Remediate Phase 1 database and security findings before acceptance.",
        "reason": "Qwen and GLM reportedly returned NEEDS_FIXES."
      },
      {
        "id": "HC-D10",
        "text": "Authorize isolated local implementation of Auth, RBAC and session rotation.",
        "reason": "The Phase 2 design is reported ready. Implementation may proceed under explicit acceptance and verification contracts."
      },
      {
        "id": "HC-D11",
        "text": "Require all six coded PRD roles and separately modeled referral permissions.",
        "reason": "The reported five-role matrix may omit required permission boundaries."
      }
    ],
    "assumptions": [
      {
        "text": "Local commit 198c4eb96e48629bbf10926066f7cacc8ec89aca exists as reported.",
        "confidence": "MEDIUM",
        "impact_if_wrong": "Stop push and investigate source identity."
      },
      {
        "text": "Qwen and GLM reviews exist locally with the reported findings.",
        "confidence": "MEDIUM",
        "impact_if_wrong": "Independent acceptance remains unverified and requires fresh review evidence."
      }
    ],
    "risks": [
      "REMOTE_COMMIT_NOT_YET_AVAILABLE",
      "PHASE_1_REVIEW_FINDINGS_OPEN",
      "INDEPENDENT_REVIEW_PROVENANCE_NOT_DIRECTLY_VERIFIED",
      "RBAC_ROLE_COVERAGE_POSSIBLY_INCOMPLETE",
      "OPEN_01_TO_18_AWAIT_OWNER_APPROVAL",
      "PRODUCTION_APPROVAL_NOT_GRANTED"
    ],
    "open_questions": [
      "Approval or amendment of the 18 configurable business defaults remains pending."
    ],
    "next_best_action": "Dispatch HC-T08, HC-T09 and HC-T10 in parallel with isolated scopes. Run HC-T11 after HC-T10. Run HC-T12 after HC-T09 and HC-T11. Verify each evidence package before acceptance."
  },
  "commands": [
    {
      "command_id": "HC-CMD-009",
      "task_id": "HC-T08",
      "level": "L2",
      "target": {
        "agent": "Codex",
        "role": "Git Release Integrity Executor",
        "model_hint": "Antigravity Gemini"
      },
      "objective": "Securely publish the verified local develop commit to GitHub without changing main or rewriting history.",
      "context": "MISSION_ID=M-HAMICARD-ZERO-TO-PROD; LOCAL_COMMIT=198c4eb96e48629bbf10926066f7cacc8ec89aca; REPOSITORY=mytest19861986/hami3; remote repository observed empty. Product Baseline BL-HAMICARD-PRD-V1 is partial.",
      "scope": "Verify origin URL, local HEAD, full commit SHA, branch state, remote refs, tracked files and sensitive content. Push only the verified develop commit using normal non-force Git push. Verify the remote commit afterward. Report whether evidence and review documents are included in the published commit.",
      "out_of_scope": "Force push, branch deletion, reset, merge, release tags, production deployment, new unapproved commits or modifications to main.",
      "constraints": [
        "MAX_ATTEMPTS=3",
        "Push only if origin resolves to the specified repository",
        "Require exact source commit match",
        "Check for secrets and real personal data before public push",
        "Stop if remote has unexpected commits or non-fast-forward divergence",
        "Never overwrite or discard local changes",
        "Do not claim publication of untracked documents"
      ],
      "tools_allowed": [
        "git",
        "github-cli",
        "read-only-source-inspection",
        "secret-scanner",
        "normal-develop-push"
      ],
      "tools_forbidden": [
        "force-push",
        "reset",
        "clean",
        "delete",
        "merge-main",
        "production-access"
      ],
      "risk_level": "MEDIUM",
      "expected_output": "GITHUB_PUSH_REPORT, REMOTE_COMMIT_VERIFICATION, SOURCE_FINGERPRINT, ARTIFACT_PUBLICATION_MATRIX",
      "success_criteria": [
        {
          "id": "T08-AC1",
          "text": "Origin repository, branch and exact local SHA are verified before push.",
          "critical": true
        },
        {
          "id": "T08-AC2",
          "text": "Publicly pushed content is checked for secrets and private data.",
          "critical": true
        },
        {
          "id": "T08-AC3",
          "text": "Remote develop resolves to the intended commit after push.",
          "critical": true
        },
        {
          "id": "T08-AC4",
          "text": "Main and historical source remain unchanged.",
          "critical": true
        }
      ],
      "verification": "Compare git rev-parse HEAD, git ls-remote origin refs/heads/develop and GitHub commit identity. Attach command results and identify unpublished artifacts.",
      "return_format": "STATUS, LOCAL_SHA, REMOTE_SHA, BRANCH, PUSH_COMMAND, EXIT_CODE, SECRET_SCAN_RESULT, PUBLISHED_FILES, UNPUBLISHED_FILES, EVIDENCE, MISMATCH_STATUS",
      "priority": "HIGH",
      "depends_on": [],
      "budget": {
        "max_attempts": 3,
        "max_time": "NOT_SPECIFIED",
        "max_cost": "NOT_SPECIFIED"
      }
    },
    {
      "command_id": "HC-CMD-010",
      "task_id": "HC-T09",
      "level": "L3",
      "target": {
        "agent": "Codex",
        "role": "Database Integrity and Security Remediation Executor",
        "model_hint": "Antigravity Gemini"
      },
      "objective": "Resolve confirmed Phase 1 independent review findings and demonstrate financial and concurrency correctness.",
      "context": "MISSION_ID=M-HAMICARD-ZERO-TO-PROD; BASELINE_REF=BL-HAMICARD-PRD-V1. Read exact local qwen_review.md, glm_review.md and synthesis before changing code. Reported issues include AC-07 atomic visit consumption, AC-12 settlement uniqueness, SQLSTATE 23505 handling, applicable PROCESSING lease recovery, PII masking, audit and fail-closed behavior.",
      "scope": "Verify each reviewer finding against code, fix valid findings within isolated development scope, add database concurrency and negative security tests, maintain a finding-to-fix matrix.",
      "out_of_scope": "Production migrations, deleting existing data, unrelated refactors, activating settlements or payments, unapproved policy changes.",
      "constraints": [
        "MAX_ATTEMPTS=3",
        "Use a separate feature branch or isolated worktree",
        "Use isolated test databases only",
        "Use database-enforced atomicity, not application-only checks",
        "No float-based financial calculations",
        "Preserve auditability and idempotency",
        "Apply lease or heartbeat only to an actual applicable processing workflow",
        "Do not claim fixes for findings that have not been inspected"
      ],
      "tools_allowed": [
        "local-source",
        "git-feature-branch",
        "postgresql-test-db",
        "docker-local",
        "pytest",
        "security-tests"
      ],
      "tools_forbidden": [
        "production-db",
        "destructive-production-migration",
        "force-push",
        "secret-extraction"
      ],
      "risk_level": "MEDIUM",
      "expected_output": "REMEDIATED_SCHEMA, REVIEW_FINDING_MATRIX, REGRESSION_TESTS, CONCURRENCY_EVIDENCE",
      "success_criteria": [
        {
          "id": "T09-AC1",
          "text": "AC-07: concurrent attempts against one remaining visit allowance cannot create more than one valid consumption.",
          "critical": true
        },
        {
          "id": "T09-AC2",
          "text": "AC-12: concurrent settlement requests cannot create multiple open requests or reserve balance twice.",
          "critical": true
        },
        {
          "id": "T09-AC3",
          "text": "Relevant SQL uniqueness violations are handled with explicit safe transaction outcomes.",
          "critical": true
        },
        {
          "id": "T09-AC4",
          "text": "Every applicable critical Qwen and GLM finding has a verified fix and regression test, or is explicitly escalated as unresolved.",
          "critical": true
        },
        {
          "id": "T09-AC5",
          "text": "Changes remain isolated, reproducible and traceable to exact files and commits.",
          "critical": true
        }
      ],
      "verification": "Run actual PostgreSQL parallel-transaction tests and failure-injection tests; inspect final schema and review findings. Report isolation level, lock strategy, exit codes and evidence references.",
      "return_format": "STATUS, SOURCE_SHA, REVIEW_FINDING_MATRIX, FILES_CHANGED, TESTS_RUN, CONCURRENCY_RESULTS, EVIDENCE, REMAINING_FINDINGS, NEXT_ACTION",
      "priority": "HIGH",
      "depends_on": [],
      "budget": {
        "max_attempts": 3,
        "max_time": "NOT_SPECIFIED",
        "max_cost": "NOT_SPECIFIED"
      }
    },
    {
      "command_id": "HC-CMD-011",
      "task_id": "HC-T10",
      "level": "L3",
      "target": {
        "agent": "Codex",
        "role": "Phase 2 Auth and RBAC Implementation Executor",
        "model_hint": "Antigravity Gemini"
      },
      "objective": "Implement the local authentication and multi-role authorization foundation according to PRD v1.0.",
      "context": "MISSION_ID=M-HAMICARD-ZERO-TO-PROD; BASELINE_REF=BL-HAMICARD-PRD-V1. First inspect the complete Phase 2 design and independent GLM findings. Include USER, DOCTOR, AGENT, SUPPORT, ADMIN, SUPER_ADMIN plus distinct referral permissions and holder identity relationships. Local implementation only.",
      "scope": "Implement account identity, unique verified mobile policy, OTP lifecycle, authorized password login with Argon2id, account-state checks, role grants, approval workflows, permission enforcement, ownership guards, sensitive-data masking, audit events and automated tests.",
      "out_of_scope": "Production SMS, real personal data, production authentication activation, financial operations, final product release and unapproved role delegation.",
      "constraints": [
        "MAX_ATTEMPTS=3",
        "Use isolated feature branch or worktree",
        "No hardcoded credentials or public OTP display",
        "OTP provider must fail closed when unavailable",
        "Use secure test doubles only in isolated test environments",
        "Account suspension and revocation must invalidate affected access",
        "Enforce authorization on the server, not only in menus",
        "No logging plaintext passwords, OTPs or tokens",
        "Treat business-policy defaults as unapproved until owner confirmation",
        "Keep design compatible with the Phase 1 approved transaction model"
      ],
      "tools_allowed": [
        "local-source",
        "git-feature-branch",
        "docker-local",
        "postgresql-test-db",
        "redis-local",
        "automated-tests",
        "local-browser-tests"
      ],
      "tools_forbidden": [
        "production-deploy",
        "real-user-data",
        "real-sms",
        "force-push",
        "protected-branch-write"
      ],
      "risk_level": "MEDIUM",
      "expected_output": "AUTH_IMPLEMENTATION, RBAC_IMPLEMENTATION, PERMISSION_MATRIX, SECURITY_TEST_SUITE, LOCAL_BUILD_EVIDENCE",
      "success_criteria": [
        {
          "id": "T10-AC1",
          "text": "OTP-based registration creates exactly one USER account for a verified mobile number.",
          "critical": true
        },
        {
          "id": "T10-AC2",
          "text": "Doctor and agent operational permissions remain disabled until authorized approval.",
          "critical": true
        },
        {
          "id": "T10-AC3",
          "text": "All required PRD roles and referral permission boundaries are covered by explicit positive and negative tests.",
          "critical": true
        },
        {
          "id": "T10-AC4",
          "text": "Blocked, suspended, deleted or unauthorized accounts cannot bypass account checks through alternate login methods.",
          "critical": true
        },
        {
          "id": "T10-AC5",
          "text": "IDOR, privilege escalation, OTP replay and confidential-data exposure tests pass.",
          "critical": true
        }
      ],
      "verification": "Execute integration, permission-matrix, OTP lifecycle, state-transition and negative security tests in isolated local environments. Collect reproducible commands, test logs and source fingerprints.",
      "return_format": "STATUS, SOURCE_SHA, FILES_CHANGED, RBAC_MATRIX, TEST_RESULTS, SECURITY_FINDINGS, EVIDENCE, MISMATCH_STATUS, NEXT_ACTION",
      "priority": "HIGH",
      "depends_on": [],
      "budget": {
        "max_attempts": 3,
        "max_time": "NOT_SPECIFIED",
        "max_cost": "NOT_SPECIFIED"
      }
    },
    {
      "command_id": "HC-CMD-012",
      "task_id": "HC-T11",
      "level": "L3",
      "target": {
        "agent": "Codex",
        "role": "Session Security and Concurrency Executor",
        "model_hint": "Antigravity Gemini"
      },
      "objective": "Implement AC-14 and AC-15 session revocation, refresh-token rotation and replay resistance.",
      "context": "MISSION_ID=M-HAMICARD-ZERO-TO-PROD; BASELINE_REF=BL-HAMICARD-PRD-V1; Requires HC-T10 identity and authentication interfaces. Use PostgreSQL as session authority and verify the actual security design before implementation.",
      "scope": "Implement protected session storage, atomic single-use refresh rotation, replay detection, family revocation, effective logout, expiry, account blocking and protection from stale private browser caches.",
      "out_of_scope": "Production rollout, unrelated financial features, storing raw refresh credentials in logs or readable public application storage.",
      "constraints": [
        "MAX_ATTEMPTS=3",
        "One refresh credential must create at most one valid successor",
        "Failed rotation must not resurrect a revoked session",
        "Use real database concurrency tests",
        "Session authority must not depend solely on an evictable Redis cache",
        "Cookie and browser-cache policies must protect private data",
        "No shared source mutations with another concurrent executor"
      ],
      "tools_allowed": [
        "local-source",
        "postgresql-test-db",
        "redis-local",
        "pytest",
        "local-browser-tests",
        "isolated-git-worktree"
      ],
      "tools_forbidden": [
        "production-deploy",
        "real-user-data",
        "force-push",
        "secret-logging"
      ],
      "risk_level": "MEDIUM",
      "expected_output": "SESSION_IMPLEMENTATION, REFRESH_ROTATION_TESTS, REPLAY_TESTS, REVOCATION_EVIDENCE",
      "success_criteria": [
        {
          "id": "T11-AC1",
          "text": "Concurrent refresh requests using the same credential produce at most one valid successor.",
          "critical": true
        },
        {
          "id": "T11-AC2",
          "text": "Replay, expiry and revocation cannot restore unauthorized access.",
          "critical": true
        },
        {
          "id": "T11-AC3",
          "text": "Logout and account suspension invalidate relevant subsequent authenticated requests.",
          "critical": true
        },
        {
          "id": "T11-AC4",
          "text": "Protected content cannot reappear after logout through stale pages, shared caching or offline state.",
          "critical": true
        }
      ],
      "verification": "Run simultaneous refresh requests against the actual PostgreSQL-backed implementation, inspect token successor uniqueness, test revocation and verify browser cache behavior using reproducible evidence.",
      "return_format": "STATUS, BUILD_ID, SOURCE_SHA, TEST_CASES, PARALLEL_TEST_RESULTS, TOKEN_ROTATION_EVIDENCE, SECURITY_FINDINGS, NEXT_ACTION",
      "priority": "HIGH",
      "depends_on": [
        "HC-T10"
      ],
      "budget": {
        "max_attempts": 3,
        "max_time": "NOT_SPECIFIED",
        "max_cost": "NOT_SPECIFIED"
      }
    },
    {
      "command_id": "HC-CMD-013",
      "task_id": "HC-T12",
      "level": "L3",
      "target": {
        "agent": "Codex",
        "role": "Independent Acceptance Review Coordinator",
        "model_hint": "Antigravity Gemini"
      },
      "objective": "Obtain independent verification of the remediated database layer and implemented Phase 2 security features.",
      "context": "MISSION_ID=M-HAMICARD-ZERO-TO-PROD; BASELINE_REF=BL-HAMICARD-PRD-V1. Review exact immutable artifact references from HC-T09 and HC-T11. Keep Qwen and GLM assessments independent from the builder and from each other.",
      "scope": "Qwen reviews SQL, idempotency, concurrency and refresh rotation. GLM reviews PRD compliance, role boundaries, ownership enforcement, privacy, Auth flows and RTL behavior. Record independent findings with artifact identities.",
      "out_of_scope": "Changing code, fabricating reviewer results, bypassing browser authentication, submitting private user data, approving release.",
      "constraints": [
        "MAX_ATTEMPTS=3",
        "Review exact pinned source and build artifacts",
        "Use separate reviewer prompts and preserve provenance",
        "Treat critical findings as blocking",
        "Reviewer unavailable must not be reported as PASS",
        "Review must cover actual implementation, not only architecture documents"
      ],
      "tools_allowed": [
        "authorized-qwen-browser",
        "authorized-glm-browser",
        "sanitized-source-review",
        "local-test-evidence"
      ],
      "tools_forbidden": [
        "auto-login",
        "captcha-bypass",
        "cookie-extraction",
        "secret-sharing",
        "production-write"
      ],
      "risk_level": "MEDIUM",
      "expected_output": "QWEN_FINAL_REVIEW, GLM_FINAL_REVIEW, FINDINGS_MATRIX, PRODUCT_AND_TECHNICAL_VERDICTS",
      "success_criteria": [
        {
          "id": "T12-AC1",
          "text": "Both reviewers independently inspect actual version-pinned implementation artifacts.",
          "critical": true
        },
        {
          "id": "T12-AC2",
          "text": "All unresolved critical findings are reported and block acceptance.",
          "critical": true
        },
        {
          "id": "T12-AC3",
          "text": "Review evidence, tested source identity and reviewer provenance are traceable.",
          "critical": true
        },
        {
          "id": "T12-AC4",
          "text": "Product and technical verdicts are separated and supported by observable tests.",
          "critical": true
        }
      ],
      "verification": "Compare reviewer source/build references against actual tested artifacts and PRD acceptance criteria. Check findings against direct evidence before issuing the next Commander decision.",
      "return_format": "STATUS, SOURCE_FINGERPRINT, BUILD_ID, QWEN_REPORT, GLM_REPORT, REVIEWER_PROVENANCE, CRITICAL_FINDINGS, PRODUCT_VERDICT, TECHNICAL_VERDICT, NEXT_ACTION",
      "priority": "HIGH",
      "depends_on": [
        "HC-T09",
        "HC-T11"
      ],
      "budget": {
        "max_attempts": 3,
        "max_time": "NOT_SPECIFIED",
        "max_cost": "NOT_SPECIFIED"
      }
    }
  ],
  "escalation": null,
  "injection_suspected": [],
  "stop": null
}
```

نتیجه این چرخه: مجوز Push محدود و توسعه محلی فاز ۲ صادر شد. پذیرش نهایی همچنان منوط به رفع Findings، آزمون‌های واقعی، بازبینی مستقل و اثبات هویت نسخه است.