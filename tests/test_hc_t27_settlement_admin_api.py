"""
Automated Verification Suite for HC-T27 (M-2 | SETTLE-007..017, OPEN-04/06/18, T27-AC1..AC4)
Target DB: Isolated `hamicard_t20` (or DATABASE_URL override) + Redis DB 6 (or REDIS_URL override)

Verifies:
1. T27-AC1: Strict RBAC & OPEN-04 enforcement across /approve, /reject, /mark-paid, /settlements.
   Unauthorized roles (USER, DOCTOR, AGENT, SUPPORT, spoofed users.roles) -> 403;
   standard ADMIN cannot call /mark-paid (SUPER_ADMIN only per RBAC + OPEN-04).
2. T27-AC2: Documented external payout evidence verification via BasePayoutProofVerifier;
   self-asserted strings, cross-settlement refs, mismatched amount/Sheba/date, and duplicate
   refs are rejected; production environment fails closed without real verifier; PII masked.
3. T27-AC3: Concurrent/replayed mark-paid & reject calls yield AT MOST ONE wallet debit or
   refund (both idempotent-key retries and non-key concurrent races).
4. T27-AC4: Unapproved/BLOCKED OPEN-04/06/18 fail closed with 403; all 18 OPEN-* policies
   restore cleanly to PROPOSED after tests.
"""

import asyncio
import json
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

os.environ.setdefault(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_t20",
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/6")

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import asyncpg  # noqa: E402
import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402

from src.api.deps import close_pool, close_redis, init_pool, init_redis  # noqa: E402
from src.api.main import app  # noqa: E402
from src.auth.session_service import SessionService  # noqa: E402
from src.core.policy import set_policy_approval  # noqa: E402
from src.wallets.service import (  # noqa: E402
    SandboxPayoutProofVerifier,
    WalletService,
    get_runtime_payout_verifier,
    reset_runtime_payout_verifier,
)

DEFAULT_POLICIES = {
    "OPEN_04_FINANCIAL_PERMISSIONS_MATRIX": {
        "record_sale_payment": ["ADMIN", "SUPER_ADMIN"],
        "mark_settlement_paid": ["SUPER_ADMIN"],
        "edit_financial_settings": ["SUPER_ADMIN"],
    },
    "OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN": {"min_amount_toman": 100000, "lock_on_request": True},
    "OPEN_18_CURRENCY_AND_ROUNDING": {
        "currency_stored": "TOMAN",
        "currency_display": "TOMAN",
        "rounding_mode": "FLOOR",
    },
}

VALID_CARD = "6037991199999990"
VALID_SHEBA = "IR630170000000100412345678"
ALT_SHEBA = "IR062960000000100324200001"


async def _reset_policies(conn: asyncpg.Connection) -> None:
    await conn.execute(
        """
        UPDATE system_settings
        SET approval_status = 'PROPOSED',
            approved_by = NULL,
            approved_at = NULL,
            updated_at = NOW()
        WHERE key LIKE 'OPEN\\_%' ESCAPE '\\';
        """
    )
    for k, v in DEFAULT_POLICIES.items():
        await conn.execute(
            "UPDATE system_settings SET value_json = $2::jsonb WHERE key = $1;",
            k,
            json.dumps(v),
        )


@pytest_asyncio.fixture
async def db_pool():
    reset_runtime_payout_verifier()
    await close_pool()
    close_redis()
    pool = await init_pool()
    init_redis()
    async with pool.acquire() as conn:
        await _reset_policies(conn)
    try:
        yield pool
    finally:
        reset_runtime_payout_verifier()
        async with pool.acquire() as conn:
            await _reset_policies(conn)
        await close_pool()
        close_redis()


async def _create_user_session(
    pool: asyncpg.Pool,
    prefix: str,
    roles: list[str],
    *,
    spoofed_legacy_roles: list[str] | None = None,
):
    mobile = f"{prefix}{uuid.uuid4().int % 10000000:07d}"
    legacy_roles = spoofed_legacy_roles if spoofed_legacy_roles is not None else roles
    async with pool.acquire() as conn:
        uid = await conn.fetchval(
            "INSERT INTO users (mobile, status, roles, is_mobile_verified) VALUES ($1, 'ACTIVE', $2, TRUE) RETURNING id;",
            mobile,
            legacy_roles,
        )
        for r in roles:
            await conn.execute(
                "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING;",
                uid,
                r,
            )
    sess = await SessionService(pool).create_session(
        user_id=uid, device_info="t27-test", ip_address="127.0.0.1"
    )
    return uid, {"Authorization": f"Bearer {sess['refresh_token']}"}


async def _seed_pending_settlement(
    client: httpx.AsyncClient,
    pool: asyncpg.Pool,
    user_id: uuid.UUID,
    user_headers: dict,
    *,
    credit_toman: int = 1000000,
    settle_toman: int = 250000,
    sheba: str = VALID_SHEBA,
) -> dict:
    await WalletService(pool).credit_commission(
        user_id=user_id,
        amount_toman=credit_toman,
        reference_id=f"T27-CRED-{uuid.uuid4().hex[:8]}",
        idempotency_key=f"T27-CRED-{uuid.uuid4().hex}",
        description="تست موجودی تسویه HC-T27",
    )
    r = await client.post(
        "/api/v1/wallet/settle",
        json={
            "amount_toman": settle_toman,
            "bank_card_number": VALID_CARD,
            "bank_sheba_number": sheba,
            "bank_account_holder_name": "سارا رضایی",
        },
        headers=user_headers,
    )
    assert r.status_code == 200, r.text
    return r.json()


@pytest.mark.asyncio
async def test_t27_ac1_rbac_and_open04_financial_permissions(db_pool: asyncpg.Pool):
    async with db_pool.acquire() as conn:
        await set_policy_approval(conn, "OPEN_04_FINANCIAL_PERMISSIONS_MATRIX", "APPROVED")
        await set_policy_approval(conn, "OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN", "APPROVED")
        await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")

    beneficiary_id, bene_hdrs = await _create_user_session(db_pool, "0960", ["USER"])
    other_user_id, other_hdrs = await _create_user_session(db_pool, "0961", ["USER"])
    _, doc_hdrs = await _create_user_session(db_pool, "0962", ["DOCTOR"])
    _, agent_hdrs = await _create_user_session(db_pool, "0963", ["AGENT"])
    _, support_hdrs = await _create_user_session(db_pool, "0964", ["SUPPORT"])
    # Legacy column spoofed with SUPER_ADMIN while authoritative user_roles is ONLY USER
    _, spoof_hdrs = await _create_user_session(
        db_pool, "0965", ["USER"], spoofed_legacy_roles=["SUPER_ADMIN"]
    )
    admin_id, admin_hdrs = await _create_user_session(db_pool, "0966", ["ADMIN"])
    super_id, super_hdrs = await _create_user_session(db_pool, "0967", ["SUPER_ADMIN"])

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        s_data = await _seed_pending_settlement(client, db_pool, beneficiary_id, bene_hdrs, settle_toman=250000)
        s_id = s_data["id"]

        pay_body = {
            "external_payment_ref": "PAYA-UNAUTH-TEST-001",
            "external_payment_date": datetime.now(UTC).isoformat(),
            "amount_toman": 250000,
        }

        # Unauthorized roles (USER owner, other USER, DOCTOR, AGENT, SUPPORT, spoofed legacy SUPER_ADMIN) -> 403
        for hdrs in (bene_hdrs, other_hdrs, doc_hdrs, agent_hdrs, support_hdrs, spoof_hdrs):
            assert (await client.post(f"/api/v1/wallet/settlements/{s_id}/approve", headers=hdrs)).status_code == 403
            assert (
                await client.post(
                    f"/api/v1/wallet/settlements/{s_id}/reject",
                    json={"reason": "تست عدم دسترسی"},
                    headers=hdrs,
                )
            ).status_code == 403
            assert (
                await client.post(
                    f"/api/v1/wallet/settlements/{s_id}/mark-paid",
                    json=pay_body,
                    headers=hdrs,
                )
            ).status_code == 403

        # Privacy / IDOR: SUPPORT & unrelated user cannot view detail or query other user's list
        for hdrs in (other_hdrs, support_hdrs, spoof_hdrs):
            assert (await client.get(f"/api/v1/wallet/settlements/{s_id}", headers=hdrs)).status_code == 403
            assert (
                await client.get(
                    f"/api/v1/wallet/settlements?user_id={beneficiary_id}",
                    headers=hdrs,
                )
            ).status_code == 403
            assert (
                await client.get("/api/v1/wallet/settlements?search=سارا", headers=hdrs)
            ).status_code == 403

        # Standard ADMIN approves PENDING -> APPROVED (has settlements:process)
        r_app = await client.post(
            f"/api/v1/wallet/settlements/{s_id}/approve",
            json={"notes": "تایید مدارک بانکی توسط مدیر مالی"},
            headers=admin_hdrs,
        )
        assert r_app.status_code == 200, r_app.text
        assert r_app.json()["status"] == "APPROVED"

        # Register confirmed payout, then prove standard ADMIN STILL CANNOT mark PAID (SUPER_ADMIN only!)
        now_utc = datetime.now(UTC)
        verifier = get_runtime_payout_verifier()
        assert isinstance(verifier, SandboxPayoutProofVerifier)
        valid_ref = f"PAYA-T27-{uuid.uuid4().hex[:10].upper()}"
        verifier.register_verified_payout(
            external_payment_ref=valid_ref,
            settlement_id=uuid.UUID(s_id),
            amount_toman=250000,
            destination_sheba=VALID_SHEBA,
            transfer_date=now_utc,
        )

        r_admin_pay = await client.post(
            f"/api/v1/wallet/settlements/{s_id}/mark-paid",
            json={
                "external_payment_ref": valid_ref,
                "external_payment_date": now_utc.isoformat(),
                "amount_toman": 250000,
            },
            headers=admin_hdrs,
        )
        assert r_admin_pay.status_code == 403, r_admin_pay.text

        # SUPER_ADMIN succeeds with verified proof -> PAID
        r_super_pay = await client.post(
            f"/api/v1/wallet/settlements/{s_id}/mark-paid",
            json={
                "external_payment_ref": valid_ref,
                "external_payment_date": now_utc.isoformat(),
                "amount_toman": 250000,
                "notes": "پرداخت نهایی پایا تایید شد",
            },
            headers=super_hdrs,
        )
        assert r_super_pay.status_code == 200, r_super_pay.text
        paid_json = r_super_pay.json()
        assert paid_json["status"] == "PAID"
        assert paid_json["paid_by"] == str(super_id)
        assert paid_json["external_payment_ref"] == valid_ref
        assert paid_json["bank_card_number"] == "6037********9990"
        assert paid_json["bank_sheba_number"] == "IR** **** **** **** **** **78"

        # Owner can inspect own paid settlement & masked listing (`SETTLE-013`, `SETTLE-015`)
        r_own_detail = await client.get(f"/api/v1/wallet/settlements/{s_id}", headers=bene_hdrs)
        assert r_own_detail.status_code == 200
        assert r_own_detail.json()["external_payment_ref"] == valid_ref
        assert r_own_detail.json()["bank_sheba_number"].startswith("IR**")
        assert r_own_detail.json()["bank_sheba_number"] != VALID_SHEBA

        # Admin list search filters (`SETTLE-014`, `SETTLE-015`) remain masked
        r_list = await client.get(
            "/api/v1/wallet/settlements?status=PAID&search=سارا",
            headers=admin_hdrs,
        )
        assert r_list.status_code == 200
        matching = [item for item in r_list.json()["items"] if item["id"] == s_id]
        assert len(matching) == 1
        assert matching[0]["bank_card_number"] == "6037********9990"
        assert matching[0]["bank_sheba_number"] == "IR** **** **** **** **** **78"

    async with db_pool.acquire() as conn:
        w = await conn.fetchrow(
            "SELECT withdrawable_balance_toman, locked_balance_toman FROM wallets WHERE user_id = $1;",
            beneficiary_id,
        )
        assert w["withdrawable_balance_toman"] == 750000
        assert w["locked_balance_toman"] == 0
        audit_actions = await conn.fetch(
            "SELECT action FROM audit_logs WHERE entity_name = 'settlements' AND entity_id = $1;",
            s_id,
        )
        actions = {r["action"] for r in audit_actions}
        assert {"SETTLEMENT_APPROVED", "SETTLEMENT_MARKED_PAID"}.issubset(actions)


@pytest.mark.asyncio
async def test_t27_ac2_external_payout_evidence_state_transitions_and_production_guard(
    db_pool: asyncpg.Pool, monkeypatch
):
    async with db_pool.acquire() as conn:
        await set_policy_approval(conn, "OPEN_04_FINANCIAL_PERMISSIONS_MATRIX", "APPROVED")
        await set_policy_approval(conn, "OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN", "APPROVED")
        await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")

    u1, u1_hdrs = await _create_user_session(db_pool, "0968", ["AGENT"])
    u2, u2_hdrs = await _create_user_session(db_pool, "0969", ["DOCTOR"])
    _, admin_hdrs = await _create_user_session(db_pool, "0970", ["ADMIN"])
    _, super_hdrs = await _create_user_session(db_pool, "0971", ["SUPER_ADMIN"])

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        s1 = await _seed_pending_settlement(client, db_pool, u1, u1_hdrs, settle_toman=200000)
        s2 = await _seed_pending_settlement(client, db_pool, u2, u2_hdrs, settle_toman=300000)
        s1_id, s2_id = s1["id"], s2["id"]
        now_utc = datetime.now(UTC)

        verifier = get_runtime_payout_verifier()
        assert isinstance(verifier, SandboxPayoutProofVerifier)
        ref_s1 = f"PAYA-S1-{uuid.uuid4().hex[:8].upper()}"
        verifier.register_verified_payout(
            external_payment_ref=ref_s1,
            settlement_id=uuid.UUID(s1_id),
            amount_toman=200000,
            destination_sheba=VALID_SHEBA,
            transfer_date=now_utc,
        )

        # 1. Invalid transition: PENDING cannot skip straight to PAID -> 409 Conflict
        r_skip = await client.post(
            f"/api/v1/wallet/settlements/{s1_id}/mark-paid",
            json={
                "external_payment_ref": ref_s1,
                "external_payment_date": now_utc.isoformat(),
                "amount_toman": 200000,
            },
            headers=super_hdrs,
        )
        assert r_skip.status_code == 409, r_skip.text

        # Approve both s1 and s2 cleanly
        assert (await client.post(f"/api/v1/wallet/settlements/{s1_id}/approve", headers=admin_hdrs)).status_code == 200
        assert (await client.post(f"/api/v1/wallet/settlements/{s2_id}/approve", headers=admin_hdrs)).status_code == 200
        # Duplicate approve must fail 409
        assert (await client.post(f"/api/v1/wallet/settlements/{s1_id}/approve", headers=admin_hdrs)).status_code == 409

        # 2. Unverified self-asserted reference string fails 400 (cannot confuse admin assertion with proof)
        r_forged = await client.post(
            f"/api/v1/wallet/settlements/{s1_id}/mark-paid",
            json={
                "external_payment_ref": "PAYA-FAKE-ASSERTED-9999",
                "external_payment_date": now_utc.isoformat(),
                "amount_toman": 200000,
            },
            headers=super_hdrs,
        )
        assert r_forged.status_code == 400, r_forged.text

        # 3. Cross-settlement receipt (ref_s1 used for s2) fails 400
        r_cross = await client.post(
            f"/api/v1/wallet/settlements/{s2_id}/mark-paid",
            json={
                "external_payment_ref": ref_s1,
                "external_payment_date": now_utc.isoformat(),
                "amount_toman": 300000,
            },
            headers=super_hdrs,
        )
        assert r_cross.status_code == 400, r_cross.text

        # 4. Mismatched Sheba / Amount proof checks -> 400
        bad_amt_ref = f"PAYA-BADAMT-{uuid.uuid4().hex[:6]}"
        verifier.register_verified_payout(
            external_payment_ref=bad_amt_ref,
            settlement_id=uuid.UUID(s2_id),
            amount_toman=299000,
            destination_sheba=VALID_SHEBA,
            transfer_date=now_utc,
        )
        r_bad_amt = await client.post(
            f"/api/v1/wallet/settlements/{s2_id}/mark-paid",
            json={
                "external_payment_ref": bad_amt_ref,
                "external_payment_date": now_utc.isoformat(),
                "amount_toman": 300000,
            },
            headers=super_hdrs,
        )
        assert r_bad_amt.status_code == 400, r_bad_amt.text

        bad_sheba_ref = f"PAYA-BADSHB-{uuid.uuid4().hex[:6]}"
        verifier.register_verified_payout(
            external_payment_ref=bad_sheba_ref,
            settlement_id=uuid.UUID(s2_id),
            amount_toman=300000,
            destination_sheba=ALT_SHEBA,
            transfer_date=now_utc,
        )
        r_bad_sheba = await client.post(
            f"/api/v1/wallet/settlements/{s2_id}/mark-paid",
            json={
                "external_payment_ref": bad_sheba_ref,
                "external_payment_date": now_utc.isoformat(),
                "amount_toman": 300000,
            },
            headers=super_hdrs,
        )
        assert r_bad_sheba.status_code == 400, r_bad_sheba.text

        # Future or pre-creation external_payment_date -> 400
        r_future = await client.post(
            f"/api/v1/wallet/settlements/{s1_id}/mark-paid",
            json={
                "external_payment_ref": ref_s1,
                "external_payment_date": (now_utc + timedelta(hours=2)).isoformat(),
                "amount_toman": 200000,
            },
            headers=super_hdrs,
        )
        assert r_future.status_code == 400

        r_past = await client.post(
            f"/api/v1/wallet/settlements/{s1_id}/mark-paid",
            json={
                "external_payment_ref": ref_s1,
                "external_payment_date": (now_utc - timedelta(hours=1)).isoformat(),
                "amount_toman": 200000,
            },
            headers=super_hdrs,
        )
        assert r_past.status_code == 400

        # 5. Production fail-closed guard -> 503 Service Unavailable
        monkeypatch.setenv("APP_ENV", "production")
        r_prod = await client.post(
            f"/api/v1/wallet/settlements/{s1_id}/mark-paid",
            json={
                "external_payment_ref": ref_s1,
                "external_payment_date": now_utc.isoformat(),
                "amount_toman": 200000,
            },
            headers=super_hdrs,
        )
        assert r_prod.status_code == 503, r_prod.text
        monkeypatch.delenv("APP_ENV", raising=False)

        # 6. Mark s1 PAID validly, then duplicate external_payment_ref on s2 -> 409 Conflict
        assert (
            await client.post(
                f"/api/v1/wallet/settlements/{s1_id}/mark-paid",
                json={
                    "external_payment_ref": ref_s1,
                    "external_payment_date": now_utc.isoformat(),
                    "amount_toman": 200000,
                },
                headers=super_hdrs,
            )
        ).status_code == 200

        # Even if verifier had an entry, DB external_payment_ref uniqueness blocks reuse -> 409
        verifier.register_verified_payout(
            external_payment_ref=ref_s1,
            settlement_id=uuid.UUID(s2_id),
            amount_toman=300000,
            destination_sheba=VALID_SHEBA,
            transfer_date=now_utc,
        )
        r_dup_ref = await client.post(
            f"/api/v1/wallet/settlements/{s2_id}/mark-paid",
            json={
                "external_payment_ref": ref_s1,
                "external_payment_date": now_utc.isoformat(),
                "amount_toman": 300000,
            },
            headers=super_hdrs,
        )
        assert r_dup_ref.status_code == 409, r_dup_ref.text


@pytest.mark.asyncio
async def test_t27_ac3_concurrent_and_replayed_mark_paid_and_reject_single_financial_effect(
    db_pool: asyncpg.Pool,
):
    async with db_pool.acquire() as conn:
        await set_policy_approval(conn, "OPEN_04_FINANCIAL_PERMISSIONS_MATRIX", "APPROVED")
        await set_policy_approval(conn, "OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN", "APPROVED")
        await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")

    u_pay, u_pay_hdrs = await _create_user_session(db_pool, "0972", ["AGENT"])
    u_idem, u_idem_hdrs = await _create_user_session(db_pool, "0973", ["AGENT"])
    u_rej, u_rej_hdrs = await _create_user_session(db_pool, "0974", ["DOCTOR"])
    _, admin_hdrs = await _create_user_session(db_pool, "0975", ["ADMIN"])
    _, super_hdrs = await _create_user_session(db_pool, "0976", ["SUPER_ADMIN"])

    verifier = get_runtime_payout_verifier()
    assert isinstance(verifier, SandboxPayoutProofVerifier)
    now_utc = datetime.now(UTC)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Part A: 8 concurrent mark-paid WITHOUT Idempotency-Key -> exact 1x 200, 7x 409
        s_pay = await _seed_pending_settlement(
            client, db_pool, u_pay, u_pay_hdrs, credit_toman=1000000, settle_toman=400000
        )
        s_pay_id = s_pay["id"]
        assert (await client.post(f"/api/v1/wallet/settlements/{s_pay_id}/approve", headers=admin_hdrs)).status_code == 200
        ref_a = f"PAYA-CONC-{uuid.uuid4().hex[:8].upper()}"
        verifier.register_verified_payout(
            external_payment_ref=ref_a,
            settlement_id=uuid.UUID(s_pay_id),
            amount_toman=400000,
            destination_sheba=VALID_SHEBA,
            transfer_date=now_utc,
        )

        resps_a = await asyncio.gather(
            *[
                client.post(
                    f"/api/v1/wallet/settlements/{s_pay_id}/mark-paid",
                    json={
                        "external_payment_ref": ref_a,
                        "external_payment_date": now_utc.isoformat(),
                        "amount_toman": 400000,
                    },
                    headers=super_hdrs,
                )
                for _ in range(8)
            ]
        )
        codes_a = [r.status_code for r in resps_a]
        assert codes_a.count(200) == 1, codes_a
        assert codes_a.count(409) == 7, codes_a
        # Rejecting an already-PAID settlement MUST fail 409 with zero refund
        r_rej_after_paid = await client.post(
            f"/api/v1/wallet/settlements/{s_pay_id}/reject",
            json={"reason": "تلاش برای رد کردن پس از پرداخت"},
            headers=admin_hdrs,
        )
        assert r_rej_after_paid.status_code == 409

        # Part B: 8 concurrent mark-paid WITH shared Idempotency-Key -> all 200, 1 False / 7 True, conflict on diff key payload
        s_idem = await _seed_pending_settlement(
            client, db_pool, u_idem, u_idem_hdrs, credit_toman=900000, settle_toman=350000
        )
        s_idem_id = s_idem["id"]
        assert (await client.post(f"/api/v1/wallet/settlements/{s_idem_id}/approve", headers=admin_hdrs)).status_code == 200
        ref_b = f"PAYA-IDEM-{uuid.uuid4().hex[:8].upper()}"
        verifier.register_verified_payout(
            external_payment_ref=ref_b,
            settlement_id=uuid.UUID(s_idem_id),
            amount_toman=350000,
            destination_sheba=VALID_SHEBA,
            transfer_date=now_utc,
        )
        idem_pay_key = f"pay-key-{uuid.uuid4().hex}"
        resps_b = await asyncio.gather(
            *[
                client.post(
                    f"/api/v1/wallet/settlements/{s_idem_id}/mark-paid",
                    json={
                        "external_payment_ref": ref_b,
                        "external_payment_date": now_utc.isoformat(),
                        "amount_toman": 350000,
                    },
                    headers={**super_hdrs, "Idempotency-Key": idem_pay_key},
                )
                for _ in range(8)
            ]
        )
        assert all(r.status_code == 200 for r in resps_b), [(r.status_code, r.text) for r in resps_b]
        replays_b = [r.json()["idempotent_replay"] for r in resps_b]
        assert replays_b.count(False) == 1 and replays_b.count(True) == 7

        r_b_conf = await client.post(
            f"/api/v1/wallet/settlements/{s_idem_id}/mark-paid",
            json={
                "external_payment_ref": f"{ref_b}-DIFF",
                "external_payment_date": now_utc.isoformat(),
                "amount_toman": 350000,
            },
            headers={**super_hdrs, "Idempotency-Key": idem_pay_key},
        )
        assert r_b_conf.status_code == 409

        # Part C: 8 concurrent /reject without Idempotency-Key -> exact 1 refund, 7x 409, then user can open new settlement
        s_rej = await _seed_pending_settlement(
            client, db_pool, u_rej, u_rej_hdrs, credit_toman=500000, settle_toman=200000
        )
        s_rej_id = s_rej["id"]
        assert (await client.post(f"/api/v1/wallet/settlements/{s_rej_id}/approve", headers=admin_hdrs)).status_code == 200

        resps_c = await asyncio.gather(
            *[
                client.post(
                    f"/api/v1/wallet/settlements/{s_rej_id}/reject",
                    json={"reason": "اختلال در اطلاعات حساب مقصد"},
                    headers=admin_hdrs,
                )
                for _ in range(8)
            ]
        )
        codes_c = [r.status_code for r in resps_c]
        assert codes_c.count(200) == 1, codes_c
        assert codes_c.count(409) == 7, codes_c

        # After rejection, user's balance was refunded ONCE (500,000 withdrawable, 0 locked) & can create a new request!
        r_new_after_rej = await client.post(
            "/api/v1/wallet/settle",
            json={
                "amount_toman": 200000,
                "bank_card_number": VALID_CARD,
                "bank_sheba_number": VALID_SHEBA,
                "bank_account_holder_name": "دکتر رضایی",
            },
            headers=u_rej_hdrs,
        )
        assert r_new_after_rej.status_code == 200, r_new_after_rej.text

        # Rejecting the new PENDING settlement WITH Idempotency-Key across 6 concurrent calls -> 1 False, 5 True, single refund
        s_rej2_id = r_new_after_rej.json()["id"]
        rej_key = f"rej-key-{uuid.uuid4().hex}"
        resps_d = await asyncio.gather(
            *[
                client.post(
                    f"/api/v1/wallet/settlements/{s_rej2_id}/reject",
                    json={"reason": "عدم تطابق مالکیت شبا"},
                    headers={**admin_hdrs, "Idempotency-Key": rej_key},
                )
                for _ in range(6)
            ]
        )
        assert all(r.status_code == 200 for r in resps_d)
        replays_d = [r.json()["idempotent_replay"] for r in resps_d]
        assert replays_d.count(False) == 1 and replays_d.count(True) == 5

    async with db_pool.acquire() as conn:
        for uid, expected_w, expected_l, debits, refunds in (
            (u_pay, 600000, 0, 1, 0),
            (u_idem, 550000, 0, 1, 0),
            (u_rej, 500000, 0, 0, 2),
        ):
            w = await conn.fetchrow(
                "SELECT id, withdrawable_balance_toman, locked_balance_toman FROM wallets WHERE user_id = $1;",
                uid,
            )
            assert w["withdrawable_balance_toman"] == expected_w
            assert w["locked_balance_toman"] == expected_l
            d_cnt = await conn.fetchval(
                "SELECT count(*) FROM wallet_ledger_entries WHERE wallet_id = $1 AND entry_type = 'SETTLEMENT_DEBIT';",
                w["id"],
            )
            r_cnt = await conn.fetchval(
                "SELECT count(*) FROM wallet_ledger_entries WHERE wallet_id = $1 AND entry_type = 'SETTLEMENT_REFUND';",
                w["id"],
            )
            assert d_cnt == debits and r_cnt == refunds


@pytest.mark.asyncio
async def test_t27_ac4_unapproved_or_blocked_open_policies_return_403(db_pool: asyncpg.Pool):
    async with db_pool.acquire() as conn:
        stats = await conn.fetchrow(
            "SELECT count(*) AS total, count(*) FILTER (WHERE approval_status = 'PROPOSED') AS proposed FROM system_settings WHERE key LIKE 'OPEN\\_%' ESCAPE '\\';"
        )
        assert stats["total"] == 18 and stats["proposed"] == 18

        await set_policy_approval(conn, "OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN", "APPROVED")
        await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")

    beneficiary_id, bene_hdrs = await _create_user_session(db_pool, "0977", ["AGENT"])
    _, super_hdrs = await _create_user_session(db_pool, "0978", ["SUPER_ADMIN"])

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        s_data = await _seed_pending_settlement(client, db_pool, beneficiary_id, bene_hdrs, settle_toman=250000)
        s_id = s_data["id"]

        # With OPEN_04 still PROPOSED -> approve & reject return 403
        r_prop_app = await client.post(
            f"/api/v1/wallet/settlements/{s_id}/approve",
            headers=super_hdrs,
        )
        assert r_prop_app.status_code == 403 and "OPEN_04" in r_prop_app.json()["detail"]

        r_prop_rej = await client.post(
            f"/api/v1/wallet/settlements/{s_id}/reject",
            json={"reason": "تست قفل سیاست پیشنهادی"},
            headers=super_hdrs,
        )
        assert r_prop_rej.status_code == 403 and "OPEN_04" in r_prop_rej.json()["detail"]

        # Approve OPEN_04 so we can test approve -> then revert OPEN_06 / BLOCK OPEN_18 before mark-paid
        async with db_pool.acquire() as conn:
            await set_policy_approval(conn, "OPEN_04_FINANCIAL_PERMISSIONS_MATRIX", "APPROVED")

        assert (await client.post(f"/api/v1/wallet/settlements/{s_id}/approve", headers=super_hdrs)).status_code == 200

        verifier = get_runtime_payout_verifier()
        assert isinstance(verifier, SandboxPayoutProofVerifier)
        now_utc = datetime.now(UTC)
        ref = f"PAYA-POL-{uuid.uuid4().hex[:8].upper()}"
        verifier.register_verified_payout(
            external_payment_ref=ref,
            settlement_id=uuid.UUID(s_id),
            amount_toman=250000,
            destination_sheba=VALID_SHEBA,
            transfer_date=now_utc,
        )

        # Toggle each required policy individually to PROPOSED / BLOCKED -> mark-paid returns 403 with zero mutation
        for key, state in (
            ("OPEN_04_FINANCIAL_PERMISSIONS_MATRIX", "PROPOSED"),
            ("OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN", "BLOCKED"),
            ("OPEN_18_CURRENCY_AND_ROUNDING", "PROPOSED"),
        ):
            async with db_pool.acquire() as conn:
                await set_policy_approval(conn, key, state)

            r_blk = await client.post(
                f"/api/v1/wallet/settlements/{s_id}/mark-paid",
                json={
                    "external_payment_ref": ref,
                    "external_payment_date": now_utc.isoformat(),
                    "amount_toman": 250000,
                },
                headers=super_hdrs,
            )
            assert r_blk.status_code == 403, f"Expected 403 for {key}={state}: {r_blk.status_code} {r_blk.text}"

            async with db_pool.acquire() as conn:
                await set_policy_approval(conn, key, "APPROVED")

        # Confirm settlement is still APPROVED and locked balance untouched
        async with db_pool.acquire() as conn:
            st = await conn.fetchval("SELECT status FROM settlements WHERE id = $1;", uuid.UUID(s_id))
            assert st == "APPROVED"
            locked = await conn.fetchval(
                "SELECT locked_balance_toman FROM wallets WHERE user_id = $1;",
                beneficiary_id,
            )
            assert locked == 250000
