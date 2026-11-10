"""
Automated Verification Suite for Sales Cases & Agent Dual State Machine (SALE-001..013, AC-09, AC-10)
Baseline: BL-HAMICARD-PRD-V1
Tests:
1. Unapproved agent sales guard (Fail-Closed).
2. Sales case creation with initial dual states.
3. Logistic state transition invariants (CARD_ISSUED and SHIPPED guards).
4. Financial finalization, commission computation, and wallet credit.
"""

import asyncio
import os
import uuid
import asyncpg

from src.sales.service import (
    SalesCaseService, SalesCaseError, InvalidStateTransitionError, AgentNotApprovedError
)
from src.wallets.service import WalletService

PG_URI = os.getenv(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_dev"
)


async def test_unapproved_agent_sales_guard(pool: asyncpg.Pool):
    print("\n[SALES TEST 1/4] Testing Unapproved Agent Sales Guard (Fail-Closed)...")
    sales_svc = SalesCaseService(pool)

    async with pool.acquire() as conn:
        agent_user = await conn.fetchrow("INSERT INTO users (mobile, roles) VALUES ($1, '{\"AGENT\"}') RETURNING id", f"0935{uuid.uuid4().int % 10000000:07d}")
        # Agent in PENDING status
        agent = await conn.fetchrow(
            """
            INSERT INTO agents (user_id, business_name, province_id, city_id, verification_status)
            VALUES ($1, 'نمایندگی پیشتاز', 1, 1, 'PENDING')
            RETURNING id
            """, agent_user["id"]
        )
        holder = await conn.fetchrow(
            "INSERT INTO plan_holders (first_name, last_name, national_code, mobile) VALUES ('احمد', 'رضایی', $1, $2) RETURNING id",
            f"{uuid.uuid4().int % 1000000000:010d}", f"0936{uuid.uuid4().int % 10000000:07d}"
        )
        plan = await conn.fetchrow(
            "INSERT INTO discount_plans (title, price_toman, discount_percent, validity_days, agent_commission_percent) VALUES ('طرح پایه', 500000, 20.0, 30, 10.0) RETURNING id"
        )

    # Attempt to create sales case by pending agent -> Must FAIL
    blocked = False
    try:
        await sales_svc.create_sales_case(
            agent_id=agent["id"],
            holder_id=holder["id"],
            plan_id=plan["id"]
        )
    except AgentNotApprovedError:
        blocked = True

    assert blocked, "Pending agent was allowed to create sales case!"
    print("  ✓ Unapproved agent blocked from creating sales cases (Fail-Closed PASS).")


async def test_sales_case_creation_and_initial_states(pool: asyncpg.Pool):
    print("\n[SALES TEST 2/4] Testing Sales Case Creation & Initial Dual States...")
    sales_svc = SalesCaseService(pool)

    async with pool.acquire() as conn:
        agent_user = await conn.fetchrow("INSERT INTO users (mobile, roles) VALUES ($1, '{\"AGENT\"}') RETURNING id", f"0937{uuid.uuid4().int % 10000000:07d}")
        agent = await conn.fetchrow(
            """
            INSERT INTO agents (user_id, business_name, province_id, city_id, verification_status)
            VALUES ($1, 'نمایندگی نوین', 1, 1, 'APPROVED')
            RETURNING id
            """, agent_user["id"]
        )
        holder = await conn.fetchrow(
            "INSERT INTO plan_holders (first_name, last_name, national_code, mobile) VALUES ('حسین', 'اکبری', $1, $2) RETURNING id",
            f"{uuid.uuid4().int % 1000000000:010d}", f"0938{uuid.uuid4().int % 10000000:07d}"
        )
        plan = await conn.fetchrow(
            "INSERT INTO discount_plans (title, price_toman, discount_percent, validity_days, agent_commission_percent) VALUES ('طرح نقره‌ای', 1000000, 30.0, 180, 15.0) RETURNING id"
        )

    case = await sales_svc.create_sales_case(
        agent_id=agent["id"],
        holder_id=holder["id"],
        plan_id=plan["id"],
        notes="مشتری معرفی شده از بازاریابی تلفنی"
    )

    assert case["id"] is not None
    assert case["logistic_status"] == "PENDING_REVIEW"
    assert case["financial_status"] == "UNPAID"
    print("  ✓ Sales case created with exact initial states: PENDING_REVIEW and UNPAID.")


async def test_logistic_state_machine_invariants(pool: asyncpg.Pool):
    print("\n[SALES TEST 3/4] Testing Logistic State Machine Invariants (AC-09)...")
    sales_svc = SalesCaseService(pool)

    async with pool.acquire() as conn:
        admin_user = await conn.fetchrow("INSERT INTO users (mobile, roles) VALUES ($1, '{\"ADMIN\"}') RETURNING id", f"0939{uuid.uuid4().int % 10000000:07d}")
        agent_user = await conn.fetchrow("INSERT INTO users (mobile, roles) VALUES ($1, '{\"AGENT\"}') RETURNING id", f"0940{uuid.uuid4().int % 10000000:07d}")
        agent = await conn.fetchrow("INSERT INTO agents (user_id, business_name, province_id, city_id, verification_status) VALUES ($1, 'نمایندگی مهر', 1, 1, 'APPROVED') RETURNING id", agent_user["id"])
        holder = await conn.fetchrow("INSERT INTO plan_holders (first_name, last_name, national_code, mobile) VALUES ('مینا', 'طاهری', $1, $2) RETURNING id", f"{uuid.uuid4().int % 1000000000:010d}", f"0941{uuid.uuid4().int % 10000000:07d}")
        plan = await conn.fetchrow("INSERT INTO discount_plans (title, price_toman, discount_percent, validity_days) VALUES ('طرح پایه', 500000, 20.0, 30) RETURNING id")

    case = await sales_svc.create_sales_case(agent_id=agent["id"], holder_id=holder["id"], plan_id=plan["id"])
    case_id = case["id"]

    # 1. Invariant: Cannot issue card directly from PENDING_REVIEW
    card_issued_blocked = False
    try:
        await sales_svc.update_logistic_status(case_id, "CARD_ISSUED", actor_user_id=admin_user["id"])
    except InvalidStateTransitionError:
        card_issued_blocked = True
    assert card_issued_blocked, "CARD_ISSUED allowed before APPROVED!"
    print("  ✓ Guard PASS: CARD_ISSUED rejected before logistics approval.")

    # 2. Approve case
    approved_case = await sales_svc.update_logistic_status(case_id, "APPROVED", actor_user_id=admin_user["id"])
    assert approved_case["logistic_status"] == "APPROVED"

    # 3. Now issue card
    card_case = await sales_svc.update_logistic_status(case_id, "CARD_ISSUED", actor_user_id=admin_user["id"])
    assert card_case["logistic_status"] == "CARD_ISSUED"
    print("  ✓ Card successfully issued after approval.")

    # 4. Invariant: Cannot SHIPPED without tracking code
    ship_blocked = False
    try:
        await sales_svc.update_logistic_status(case_id, "SHIPPED", actor_user_id=admin_user["id"], shipping_tracking_code=None)
    except InvalidStateTransitionError:
        ship_blocked = True
    assert ship_blocked, "SHIPPED allowed without tracking code!"
    print("  ✓ Guard PASS: SHIPPED rejected without postal tracking code.")

    # 5. Ship with tracking code
    shipped_case = await sales_svc.update_logistic_status(case_id, "SHIPPED", actor_user_id=admin_user["id"], shipping_tracking_code="POST-987654321")
    assert shipped_case["logistic_status"] == "SHIPPED"
    assert shipped_case["shipping_tracking_code"] == "POST-987654321"

    # 6. Deliver
    delivered_case = await sales_svc.update_logistic_status(case_id, "DELIVERED", actor_user_id=admin_user["id"])
    assert delivered_case["logistic_status"] == "DELIVERED"
    assert delivered_case["delivery_date"] is not None
    print("  ✓ Full logistic lifecycle completed: APPROVED -> CARD_ISSUED -> SHIPPED -> DELIVERED.")


async def test_financial_finalization_and_commission_credit(pool: asyncpg.Pool):
    print("\n[SALES TEST 4/4] Testing Financial Finalization & Automatic Commission Credit (AC-10)...")
    sales_svc = SalesCaseService(pool)
    wallet_svc = WalletService(pool)

    async with pool.acquire() as conn:
        admin_user = await conn.fetchrow("INSERT INTO users (mobile, roles) VALUES ($1, '{\"ADMIN\"}') RETURNING id", f"0942{uuid.uuid4().int % 10000000:07d}")
        agent_user = await conn.fetchrow("INSERT INTO users (mobile, roles) VALUES ($1, '{\"AGENT\"}') RETURNING id", f"0943{uuid.uuid4().int % 10000000:07d}")
        agent = await conn.fetchrow("INSERT INTO agents (user_id, business_name, province_id, city_id, verification_status) VALUES ($1, 'نمایندگی البرز', 1, 1, 'APPROVED') RETURNING id", agent_user["id"])
        holder = await conn.fetchrow("INSERT INTO plan_holders (first_name, last_name, national_code, mobile) VALUES ('کامران', 'نجفی', $1, $2) RETURNING id", f"{uuid.uuid4().int % 1000000000:010d}", f"0944{uuid.uuid4().int % 10000000:07d}")
        # Plan: 2,000,000 Toman with 20% agent commission = 400,000 Toman
        plan = await conn.fetchrow(
            "INSERT INTO discount_plans (title, price_toman, discount_percent, validity_days, agent_commission_percent) VALUES ('طرح طلایی VIP', 2000000, 40.0, 365, 20.0) RETURNING id"
        )

    # 1. Create and approve case
    case = await sales_svc.create_sales_case(agent_id=agent["id"], holder_id=holder["id"], plan_id=plan["id"])
    case_id = case["id"]
    await sales_svc.update_logistic_status(case_id, "APPROVED", actor_user_id=admin_user["id"])

    # 2. Finalize financial status
    final_res = await sales_svc.finalize_financial_status(case_id=case_id, actor_user_id=admin_user["id"])
    assert final_res["case"]["financial_status"] == "FINALIZED"
    assert final_res["commission_amount_toman"] == 400000
    print("  ✓ Financial status FINALIZED: exactly 400,000 Toman commission calculated (20% of 2,000,000).")

    # 3. Verify commission record in commissions table
    async with pool.acquire() as conn:
        comm = await conn.fetchrow("SELECT * FROM commissions WHERE id = $1", final_res["commission_id"])
        assert comm is not None
        assert comm["beneficiary_user_id"] == agent_user["id"]
        assert comm["amount_toman"] == 400000
        assert comm["status"] == "APPROVED"
    print("  ✓ Commission record persisted in commissions table.")

    # 4. Verify agent wallet was credited
    agent_wallet = await wallet_svc.get_wallet_by_user_id(agent_user["id"])
    assert agent_wallet["withdrawable_balance_toman"] == 400000
    print("  ✓ Agent wallet balance verified: 400,000 Toman withdrawable.")


async def main():
    pool = await asyncpg.create_pool(PG_URI, min_size=2, max_size=5)
    try:
        await test_unapproved_agent_sales_guard(pool)
        await test_sales_case_creation_and_initial_states(pool)
        await test_logistic_state_machine_invariants(pool)
        await test_financial_finalization_and_commission_credit(pool)
        print("\n" + "=" * 70)
        print("ALL 4 SALES CASES & DUAL STATE MACHINE TEST SUITES PASSED (100% SUCCESS)!")
        print("=" * 70)
    finally:
        await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
