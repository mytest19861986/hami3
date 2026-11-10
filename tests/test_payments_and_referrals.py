"""
Automated Verification Suite for Payments, Fulfillment & Referrals (PAY-001..011, REF-001..012, AC-06)
Baseline: BL-HAMICARD-PRD-V1
Tests:
1. Order creation and idempotency key protection.
2. Payment fulfillment and automatic membership activation.
3. Referral code linking and self-referral prevention.
4. Referral commission calculation and automatic wallet credit upon order fulfillment.
5. Marketer/referral analytics and commission statistics.
"""

import asyncio
import os
import uuid

import asyncpg

from src.payments.service import PaymentService
from src.referrals.service import ReferralService, SelfReferralNotAllowedError
from src.wallets.service import WalletService

PG_URI = os.getenv(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_dev"
)


async def test_order_creation_and_idempotency(pool: asyncpg.Pool):
    print("\n[PAYMENT TEST 1/4] Testing Order Creation & Idempotency Key...")
    pay_svc = PaymentService(pool)

    async with pool.acquire() as conn:
        buyer = await conn.fetchrow("INSERT INTO users (mobile) VALUES ($1) RETURNING id", f"0945{uuid.uuid4().int % 10000000:07d}")
        holder = await conn.fetchrow("INSERT INTO plan_holders (first_name, last_name, national_code, mobile) VALUES ('رضا', 'محمدی', $1, $2) RETURNING id", f"{uuid.uuid4().int % 1000000000:010d}", f"0946{uuid.uuid4().int % 10000000:07d}")
        plan = await conn.fetchrow("INSERT INTO discount_plans (title, price_toman, discount_percent, validity_days) VALUES ('طرح تست', 500000, 20.0, 30) RETURNING id")

    idem_key = f"ORD-IDEM-{uuid.uuid4().hex}"

    # 1. Create order
    order = await pay_svc.create_order(
        buyer_user_id=buyer["id"],
        holder_id=holder["id"],
        plan_id=plan["id"],
        idempotency_key=idem_key
    )
    assert order["id"] is not None
    assert order["status"] == "PENDING"
    assert order["amount_toman"] == 500000
    print("  ✓ Order created with status PENDING.")

    # 2. Replay order creation with same idempotency key -> Must return same order
    order_replay = await pay_svc.create_order(
        buyer_user_id=buyer["id"],
        holder_id=holder["id"],
        plan_id=plan["id"],
        idempotency_key=idem_key
    )
    assert order_replay["id"] == order["id"]
    print("  ✓ Order Idempotency PASS: Replay returned exact same order.")


async def test_payment_fulfillment_and_membership_activation(pool: asyncpg.Pool):
    print("\n[PAYMENT TEST 2/4] Testing Payment Fulfillment & Automatic Membership Activation...")
    pay_svc = PaymentService(pool)

    async with pool.acquire() as conn:
        buyer = await conn.fetchrow("INSERT INTO users (mobile) VALUES ($1) RETURNING id", f"0947{uuid.uuid4().int % 10000000:07d}")
        holder = await conn.fetchrow("INSERT INTO plan_holders (first_name, last_name, national_code, mobile) VALUES ('سارا', 'احمدی', $1, $2) RETURNING id", f"{uuid.uuid4().int % 1000000000:010d}", f"0948{uuid.uuid4().int % 10000000:07d}")
        plan = await conn.fetchrow("INSERT INTO discount_plans (title, price_toman, discount_percent, validity_days, max_visits) VALUES ('طرح ۳ ماهه', 750000, 30.0, 90, 6) RETURNING id")

    order = await pay_svc.create_order(
        buyer_user_id=buyer["id"],
        holder_id=holder["id"],
        plan_id=plan["id"],
        idempotency_key=f"ORD-{uuid.uuid4().hex}"
    )

    # Fulfill payment
    fulfill_res = await pay_svc.verify_and_fulfill_payment(
        order_id=order["id"],
        gateway_transaction_id="TXN-12345678",
        gateway_tracking_code="TRACK-98765432"
    )

    # 1. Order status is SUCCESS
    assert fulfill_res["order"]["status"] == "SUCCESS"
    assert fulfill_res["order"]["gateway_tracking_code"] == "TRACK-98765432"
    print("  ✓ Order status transitioned to SUCCESS.")

    # 2. Membership automatically activated
    mem = fulfill_res["membership"]
    assert mem["status"] == "ACTIVE"
    assert mem["max_visits"] == 6
    assert mem["remaining_visits"] == 6
    assert mem["holder_id"] == holder["id"]
    print("  ✓ Membership activated atomically: status=ACTIVE, visits=6.")


async def test_referral_linking_and_self_referral_guard(pool: asyncpg.Pool):
    print("\n[REFERRAL TEST 3/4] Testing Referral Linking & Self-Referral Guard...")
    ref_svc = ReferralService(pool)

    async with pool.acquire() as conn:
        user_a = await conn.fetchrow("INSERT INTO users (mobile) VALUES ($1) RETURNING id", f"0949{uuid.uuid4().int % 10000000:07d}")
        user_b = await conn.fetchrow("INSERT INTO users (mobile) VALUES ($1) RETURNING id", f"0950{uuid.uuid4().int % 10000000:07d}")

    # 1. User A gets referral code
    code_a = await ref_svc.get_or_create_referral_code(user_a["id"])
    assert code_a.startswith("HAMI-")
    print(f"  ✓ User A referral code generated: {code_a}")

    # 2. Self-referral guard
    self_ref_blocked = False
    try:
        await ref_svc.create_user_referral_link(user_a["id"], user_a["id"])
    except SelfReferralNotAllowedError:
        self_ref_blocked = True
    assert self_ref_blocked, "Self referral was allowed!"
    print("  ✓ Self-Referral Guard PASS: User cannot refer themselves.")

    # 3. User B refers to User A
    link = await ref_svc.create_user_referral_link(user_a["id"], user_b["id"])
    assert link["id"] is not None
    assert link["referrer_user_id"] == user_a["id"]
    assert link["referred_user_id"] == user_b["id"]
    print("  ✓ User B successfully linked to User A.")


async def test_referral_commission_credit_on_order(pool: asyncpg.Pool):
    print("\n[REFERRAL TEST 4/4] Testing Referral Commission Payout on Order Fulfillment...")
    ref_svc = ReferralService(pool)
    pay_svc = PaymentService(pool)
    wallet_svc = WalletService(pool)

    async with pool.acquire() as conn:
        referrer = await conn.fetchrow("INSERT INTO users (mobile) VALUES ($1) RETURNING id", f"0951{uuid.uuid4().int % 10000000:07d}")
        buyer = await conn.fetchrow("INSERT INTO users (mobile) VALUES ($1) RETURNING id", f"0952{uuid.uuid4().int % 10000000:07d}")
        holder = await conn.fetchrow("INSERT INTO plan_holders (first_name, last_name, national_code, mobile) VALUES ('نیما', 'فروغی', $1, $2) RETURNING id", f"{uuid.uuid4().int % 1000000000:010d}", f"0953{uuid.uuid4().int % 10000000:07d}")
        # Plan: 1,000,000 Toman with 8% referrer commission = 80,000 Toman
        plan = await conn.fetchrow(
            """
            INSERT INTO discount_plans (title, price_toman, discount_percent, validity_days, referrer_commission_percent)
            VALUES ('طرح معرف ویژه', 1000000, 30.0, 365, 8.0)
            RETURNING id
            """
        )

    # 1. Link Buyer to Referrer
    ref_code = f"HAMI-REF-{uuid.uuid4().hex[:4].upper()}"
    await ref_svc.create_user_referral_link(referrer["id"], buyer["id"], custom_code=ref_code)

    # 2. Buyer creates order
    order = await pay_svc.create_order(
        buyer_user_id=buyer["id"],
        holder_id=holder["id"],
        plan_id=plan["id"],
        idempotency_key=f"ORD-REF-{uuid.uuid4().hex}"
    )

    # 3. Fulfill payment with referral code
    fulfill_res = await pay_svc.verify_and_fulfill_payment(
        order_id=order["id"],
        gateway_transaction_id="GATEWAY-TXN-999",
        gateway_tracking_code="GATEWAY-TRK-999",
        referral_code=ref_code
    )

    # 4. Verify referral commission
    ref_comm = fulfill_res["referral_commission"]
    assert ref_comm is not None
    assert ref_comm["amount_toman"] == 80000  # 8% of 1,000,000
    print("  ✓ Referral commission calculated: 80,000 Toman (8% of 1,000,000).")

    # 5. Verify referrer wallet was credited
    referrer_wallet = await wallet_svc.get_wallet_by_user_id(referrer["id"])
    assert referrer_wallet["withdrawable_balance_toman"] == 80000
    print("  ✓ Referrer wallet balance confirmed: 80,000 Toman withdrawable.")

    # 6. Check referral stats
    stats = await ref_svc.get_referral_stats(referrer["id"])
    assert stats["total_referred_users"] == 1
    assert stats["total_earned_toman"] == 80000
    print("  ✓ Marketer/referral analytics confirmed: 1 user, 80,000 Toman earned.")


async def main():
    pool = await asyncpg.create_pool(PG_URI, min_size=2, max_size=5)
    try:
        await test_order_creation_and_idempotency(pool)
        await test_payment_fulfillment_and_membership_activation(pool)
        await test_referral_linking_and_self_referral_guard(pool)
        await test_referral_commission_credit_on_order(pool)
        print("\n" + "=" * 70)
        print("ALL 4 PAYMENTS & REFERRALS TEST SUITES PASSED (100% SUCCESS)!")
        print("=" * 70)
    finally:
        await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
