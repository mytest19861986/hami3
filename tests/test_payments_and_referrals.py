"""
Automated Verification Suite for Payments, Fulfillment & Referrals (PAY-001..011, REF-001..012, AC-06)
Baseline: BL-HAMICARD-PRD-V1 | Updated for HC-T17 verified gateway flow
Tests:
1. Order creation and idempotency key protection.
2. Trusted gateway initiation, isolated provider settlement, verification & membership activation.
3. Referral code linking and self-referral prevention.
4. Referral commission calculation (Decimal exact) and automatic wallet credit upon fulfillment.
"""

import asyncio
import os
import pathlib
import sys
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import asyncpg  # noqa: E402

from src.adapters.payment import MockPaymentGateway  # noqa: E402
from src.core.policy import PolicyNotApprovedError, set_policy_approval  # noqa: E402
from src.payments.service import PaymentService, UnverifiedPaymentError  # noqa: E402
from src.referrals.service import ReferralService, SelfReferralNotAllowedError  # noqa: E402
from src.wallets.service import WalletService  # noqa: E402

PG_URI = os.getenv(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_t17",
)


async def _insert_user(conn: asyncpg.Connection, mobile: str, role: str = "USER") -> uuid.UUID:
    uid = await conn.fetchval(
        "INSERT INTO users (mobile, roles) VALUES ($1, $2) RETURNING id",
        mobile,
        [role],
    )
    await conn.execute(
        "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        uid,
        role,
    )
    return uid


async def test_order_creation_and_idempotency(pool: asyncpg.Pool):
    print("\n[PAYMENT TEST 1/4] Testing Order Creation & Idempotency Key...")
    pay_svc = PaymentService(pool)

    async with pool.acquire() as conn:
        buyer_id = await _insert_user(conn, f"0945{uuid.uuid4().int % 10000000:07d}")
        holder = await conn.fetchrow(
            "INSERT INTO plan_holders (first_name, last_name, national_code, mobile) VALUES ('رضا', 'محمدی', $1, $2) RETURNING id",
            f"{uuid.uuid4().int % 1000000000:010d}",
            f"0946{uuid.uuid4().int % 10000000:07d}",
        )
        plan = await conn.fetchrow(
            "INSERT INTO discount_plans (title, price_toman, discount_percent, validity_days) VALUES ('طرح تست', 500000, 20.0, 30) RETURNING id"
        )

    idem_key = f"ORD-IDEM-{uuid.uuid4().hex}"
    order = await pay_svc.create_order(
        buyer_user_id=buyer_id,
        holder_id=holder["id"],
        plan_id=plan["id"],
        idempotency_key=idem_key,
    )
    assert order["id"] is not None
    assert order["status"] == "PENDING"
    assert order["amount_toman"] == 500000

    order_replay = await pay_svc.create_order(
        buyer_user_id=buyer_id,
        holder_id=holder["id"],
        plan_id=plan["id"],
        idempotency_key=idem_key,
    )
    assert order_replay["id"] == order["id"]
    print("  ✓ Order Idempotency PASS.")


async def test_payment_fulfillment_and_membership_activation(pool: asyncpg.Pool):
    print("\n[PAYMENT TEST 2/4] Testing Gateway Initiate -> Verify -> Membership Activation...")
    pay_svc = PaymentService(pool)
    gateway = MockPaymentGateway(require_explicit_confirmation=True)

    async with pool.acquire() as conn:
        buyer_id = await _insert_user(conn, f"0947{uuid.uuid4().int % 10000000:07d}")
        holder = await conn.fetchrow(
            "INSERT INTO plan_holders (first_name, last_name, national_code, mobile) VALUES ('سارا', 'احمدی', $1, $2) RETURNING id",
            f"{uuid.uuid4().int % 1000000000:010d}",
            f"0948{uuid.uuid4().int % 10000000:07d}",
        )
        plan = await conn.fetchrow(
            "INSERT INTO discount_plans (title, price_toman, discount_percent, validity_days, max_visits) VALUES ('طرح ۳ ماهه', 750000, 30.0, 90, 6) RETURNING id"
        )

    order = await pay_svc.create_order(
        buyer_user_id=buyer_id,
        holder_id=holder["id"],
        plan_id=plan["id"],
        idempotency_key=f"ORD-{uuid.uuid4().hex}",
    )

    init_res = await pay_svc.initiate_gateway_payment(
        order_id=order["id"],
        actor_user_id=buyer_id,
        callback_url="https://hamicard.local/callback",
        gateway=gateway,
    )
    authority = init_res["authority"]

    # Blocked while OPEN_18 is PROPOSED
    pay_blocked = False
    try:
        await pay_svc.verify_and_fulfill_payment(
            order_id=order["id"],
            actor_user_id=buyer_id,
            gateway=gateway,
            authority=authority,
        )
    except PolicyNotApprovedError:
        pay_blocked = True
    assert pay_blocked, "Payment fulfillment succeeded while OPEN-18 is PROPOSED!"

    async with pool.acquire() as conn:
        await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")

    # Even with OPEN-18 approved, unconfirmed authority MUST FAIL
    unconfirmed_blocked = False
    try:
        await pay_svc.verify_and_fulfill_payment(
            order_id=order["id"],
            actor_user_id=buyer_id,
            gateway=gateway,
            authority=authority,
        )
    except UnverifiedPaymentError:
        unconfirmed_blocked = True
    assert unconfirmed_blocked, "Unconfirmed gateway authority was mistakenly accepted!"

    # Simulate bank-side payment completion in isolated test gateway
    ref_id = gateway.confirm_payment(authority)
    fulfill_res = await pay_svc.verify_and_fulfill_payment(
        order_id=order["id"],
        actor_user_id=buyer_id,
        gateway=gateway,
        authority=authority,
    )
    assert fulfill_res["order"]["status"] == "SUCCESS"
    assert fulfill_res["order"]["gateway_tracking_code"] == ref_id
    mem = fulfill_res["membership"]
    assert mem["status"] == "ACTIVE"
    assert mem["max_visits"] == 6
    assert mem["remaining_visits"] == 6
    assert mem["holder_id"] == holder["id"]
    print("  ✓ Gateway Initiate -> Bank Confirm -> Verify -> Membership Activated PASS.")


async def test_referral_linking_and_self_referral_guard(pool: asyncpg.Pool):
    print("\n[REFERRAL TEST 3/4] Testing Referral Linking & Self-Referral Guard...")
    ref_svc = ReferralService(pool)

    async with pool.acquire() as conn:
        user_a_id = await _insert_user(conn, f"0949{uuid.uuid4().int % 10000000:07d}")
        user_b_id = await _insert_user(conn, f"0950{uuid.uuid4().int % 10000000:07d}")

    code_a = await ref_svc.get_or_create_referral_code(user_a_id)
    assert code_a.startswith("HAMI-")

    self_ref_blocked = False
    try:
        await ref_svc.create_user_referral_link(user_a_id, user_a_id)
    except SelfReferralNotAllowedError:
        self_ref_blocked = True
    assert self_ref_blocked, "Self referral was allowed!"

    link = await ref_svc.create_user_referral_link(user_a_id, user_b_id)
    assert link["referrer_user_id"] == user_a_id
    assert link["referred_user_id"] == user_b_id
    print("  ✓ Referral Linking & Self-Referral Guard PASS.")


async def test_referral_commission_credit_on_order(pool: asyncpg.Pool):
    print("\n[REFERRAL TEST 4/4] Testing Referral Commission Payout on Verified Fulfillment...")
    ref_svc = ReferralService(pool)
    pay_svc = PaymentService(pool)
    wallet_svc = WalletService(pool)
    gateway = MockPaymentGateway(require_explicit_confirmation=True)

    async with pool.acquire() as conn:
        referrer_id = await _insert_user(conn, f"0951{uuid.uuid4().int % 10000000:07d}")
        buyer_id = await _insert_user(conn, f"0952{uuid.uuid4().int % 10000000:07d}")
        holder = await conn.fetchrow(
            "INSERT INTO plan_holders (first_name, last_name, national_code, mobile) VALUES ('نیما', 'فروغی', $1, $2) RETURNING id",
            f"{uuid.uuid4().int % 1000000000:010d}",
            f"0953{uuid.uuid4().int % 10000000:07d}",
        )
        plan = await conn.fetchrow(
            """
            INSERT INTO discount_plans (title, price_toman, discount_percent, validity_days, referrer_commission_percent)
            VALUES ('طرح معرف ویژه', 1000000, 30.0, 365, 8.0)
            RETURNING id
            """
        )

    ref_code = f"HAMI-REF-{uuid.uuid4().hex[:4].upper()}"
    await ref_svc.create_user_referral_link(referrer_id, buyer_id, custom_code=ref_code)

    order = await pay_svc.create_order(
        buyer_user_id=buyer_id,
        holder_id=holder["id"],
        plan_id=plan["id"],
        idempotency_key=f"ORD-REF-{uuid.uuid4().hex}",
    )
    init_res = await pay_svc.initiate_gateway_payment(
        order_id=order["id"],
        actor_user_id=buyer_id,
        callback_url="https://hamicard.local/callback",
        gateway=gateway,
    )
    gateway.confirm_payment(init_res["authority"])

    async with pool.acquire() as conn:
        await set_policy_approval(conn, "OPEN_05_COMBINED_COMMISSION_POLICY", "APPROVED")
        await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")

    fulfill_res = await pay_svc.verify_and_fulfill_payment(
        order_id=order["id"],
        actor_user_id=buyer_id,
        gateway=gateway,
        authority=init_res["authority"],
        referral_code=ref_code,
    )
    ref_comm = fulfill_res["referral_commission"]
    assert ref_comm is not None
    assert ref_comm["amount_toman"] == 80000

    referrer_wallet = await wallet_svc.get_wallet_by_user_id(referrer_id)
    assert referrer_wallet["withdrawable_balance_toman"] == 80000
    stats = await ref_svc.get_referral_stats(referrer_id)
    assert stats["total_referred_users"] == 1
    assert stats["total_earned_toman"] == 80000
    print("  ✓ Referral commission 80,000 Toman PASS.")


async def main():
    pool = await asyncpg.create_pool(PG_URI, min_size=2, max_size=5)
    try:
        await test_order_creation_and_idempotency(pool)
        await test_payment_fulfillment_and_membership_activation(pool)
        await test_referral_linking_and_self_referral_guard(pool)
        await test_referral_commission_credit_on_order(pool)
        print("\nALL 4 PAYMENTS & REFERRALS TEST SUITES PASSED!")
    finally:
        async with pool.acquire() as conn:
            await set_policy_approval(conn, "OPEN_05_COMBINED_COMMISSION_POLICY", "PROPOSED")
            await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "PROPOSED")
        await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
