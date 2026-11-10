"""
Automated Verification Suite for Wallets & Financial Ledger (WALLET-001..010, BR-15, AC-11)
Baseline: BL-HAMICARD-PRD-V1
Tests:
1. Idempotent wallet initialization.
2. Commission credit with atomic ledger entry.
3. Idempotency protection against double-crediting.
4. Settlement fund locking (withdrawable -> locked).
5. Insufficient funds prevention.
6. Settlement payout finalization (debits locked balance).
7. Settlement rejection refund (restores locked -> withdrawable).
8. Append-only ledger statement auditing.
"""

import asyncio
import os
import uuid

import asyncpg

from src.wallets.service import InsufficientFundsError, WalletService

PG_URI = os.getenv(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_dev"
)


async def test_wallet_initialization_and_commission_credit(pool: asyncpg.Pool):
    print("\n[WALLET TEST 1/4] Testing Wallet Init & Commission Credit...")
    wallet_svc = WalletService(pool)

    # 1. Create user
    async with pool.acquire() as conn:
        user_row = await conn.fetchrow(
            "INSERT INTO users (mobile) VALUES ($1) RETURNING id",
            f"0930{uuid.uuid4().int % 10000000:07d}"
        )
        user_id = user_row["id"]

    # 2. Get or create wallet
    wallet = await wallet_svc.get_or_create_wallet(user_id)
    assert wallet["withdrawable_balance_toman"] == 0
    assert wallet["locked_balance_toman"] == 0
    assert wallet["status"] == "ACTIVE"
    print("  ✓ Wallet initialized with 0 balance.")

    # 3. Credit commission 250,000 Toman
    idem_key = f"IDEM-COMM-{uuid.uuid4().hex}"
    credit_res = await wallet_svc.credit_commission(
        user_id=user_id,
        amount_toman=250000,
        reference_id="ORDER-12345",
        idempotency_key=idem_key,
        description="پورسانت فروش کارت طلایی"
    )
    assert credit_res["balance_before_toman"] == 0
    assert credit_res["balance_after_toman"] == 250000
    assert credit_res["credited_amount_toman"] == 250000
    print("  ✓ 250,000 Toman commission credited atomically.")

    # 4. Idempotency check: repeat same credit
    repeat_res = await wallet_svc.credit_commission(
        user_id=user_id,
        amount_toman=250000,
        reference_id="ORDER-12345",
        idempotency_key=idem_key,
        description="پورسانت فروش کارت طلایی"
    )
    # Balance must remain 250,000 (NOT 500,000)
    current_wallet = await wallet_svc.get_wallet_by_user_id(user_id)
    assert current_wallet["withdrawable_balance_toman"] == 250000
    print("  ✓ Financial Idempotency PASS: Replay prevented double-crediting.")


async def test_settlement_locking_and_insufficient_funds(pool: asyncpg.Pool):
    print("\n[WALLET TEST 2/4] Testing Settlement Locking & Insufficient Funds Guard...")
    wallet_svc = WalletService(pool)

    async with pool.acquire() as conn:
        user_row = await conn.fetchrow(
            "INSERT INTO users (mobile) VALUES ($1) RETURNING id",
            f"0931{uuid.uuid4().int % 10000000:07d}"
        )
        user_id = user_row["id"]

    # Credit 300,000 Toman
    await wallet_svc.credit_commission(
        user_id=user_id,
        amount_toman=300000,
        reference_id="COMM-1",
        idempotency_key=f"IDEM-{uuid.uuid4().hex}",
        description="شارژ اولیه"
    )

    # 1. Lock 200,000 Toman for settlement
    settlement_id = uuid.uuid4()
    lock_res = await wallet_svc.lock_funds_for_settlement(
        user_id=user_id,
        amount_toman=200000,
        settlement_id=settlement_id,
        idempotency_key=f"LOCK-{uuid.uuid4().hex}"
    )
    assert lock_res["withdrawable_balance_toman"] == 100000
    assert lock_res["locked_balance_toman"] == 200000
    print("  ✓ 200,000 Toman locked: withdrawable=100,000, locked=200,000.")

    # 2. Try to lock 150,000 Toman (only 100,000 available) -> Must FAIL
    overdraw_blocked = False
    try:
        await wallet_svc.lock_funds_for_settlement(
            user_id=user_id,
            amount_toman=150000,
            settlement_id=uuid.uuid4(),
            idempotency_key=f"LOCK-{uuid.uuid4().hex}"
        )
    except InsufficientFundsError:
        overdraw_blocked = True

    assert overdraw_blocked, "Overdrawing wallet was allowed!"
    print("  ✓ Insufficient Funds Guard PASS: Overdraft strictly rejected.")


async def test_settlement_payout_and_refund_cycles(pool: asyncpg.Pool):
    print("\n[WALLET TEST 3/4] Testing Settlement Payout & Refund Cycles...")
    wallet_svc = WalletService(pool)

    async with pool.acquire() as conn:
        admin_row = await conn.fetchrow("INSERT INTO users (mobile, roles) VALUES ($1, '{\"ADMIN\"}') RETURNING id", f"0932{uuid.uuid4().int % 10000000:07d}")
        user_row = await conn.fetchrow("INSERT INTO users (mobile) VALUES ($1) RETURNING id", f"0933{uuid.uuid4().int % 10000000:07d}")
        user_id = user_row["id"]

    # Credit 500,000 Toman
    await wallet_svc.credit_commission(user_id=user_id, amount_toman=500000, reference_id="REF-1", idempotency_key=f"IDEM-{uuid.uuid4().hex}", description="کمیسیون")

    # Settlement A (200,000 Toman) -> Will be PAID
    settle_a = uuid.uuid4()
    await wallet_svc.lock_funds_for_settlement(user_id=user_id, amount_toman=200000, settlement_id=settle_a, idempotency_key=f"LOCK-A-{uuid.uuid4().hex}")
    # Settlement B (150,000 Toman) -> Will be REJECTED/REFUNDED
    settle_b = uuid.uuid4()
    await wallet_svc.lock_funds_for_settlement(user_id=user_id, amount_toman=150000, settlement_id=settle_b, idempotency_key=f"LOCK-B-{uuid.uuid4().hex}")

    # Available: 150,000 | Locked: 350,000
    w_locked = await wallet_svc.get_wallet_by_user_id(user_id)
    assert w_locked["withdrawable_balance_toman"] == 150000
    assert w_locked["locked_balance_toman"] == 350000

    # 1. Finalize Settlement A payout
    pay_res = await wallet_svc.finalize_settlement_payout(
        user_id=user_id,
        amount_toman=200000,
        settlement_id=settle_a,
        idempotency_key=f"PAY-A-{uuid.uuid4().hex}",
        paid_by=admin_row["id"]
    )
    assert pay_res["locked_balance_toman"] == 150000
    print("  ✓ Settlement A paid: locked balance reduced to 150,000.")

    # 2. Refund Settlement B (e.g. Invalid Sheba)
    ref_res = await wallet_svc.refund_locked_settlement(
        user_id=user_id,
        amount_toman=150000,
        settlement_id=settle_b,
        idempotency_key=f"REFUND-B-{uuid.uuid4().hex}",
        reason="شماره شبا با نام کاربری مغایرت دارد"
    )
    assert ref_res["locked_balance_toman"] == 0
    assert ref_res["withdrawable_balance_toman"] == 300000
    print("  ✓ Settlement B refunded: funds returned to withdrawable balance (300,000).")


async def test_append_only_ledger_history(pool: asyncpg.Pool):
    print("\n[WALLET TEST 4/4] Testing Append-Only Ledger Statement Audit...")
    wallet_svc = WalletService(pool)

    async with pool.acquire() as conn:
        user_row = await conn.fetchrow("INSERT INTO users (mobile) VALUES ($1) RETURNING id", f"0934{uuid.uuid4().int % 10000000:07d}")
        user_id = user_row["id"]

    # 3 operations: Credit 100k, Credit 200k, Lock 50k
    await wallet_svc.credit_commission(user_id=user_id, amount_toman=100000, reference_id="REF-1", idempotency_key=f"IDEM-1-{uuid.uuid4().hex}", description="پورسانت ۱")
    await wallet_svc.credit_commission(user_id=user_id, amount_toman=200000, reference_id="REF-2", idempotency_key=f"IDEM-2-{uuid.uuid4().hex}", description="پورسانت ۲")
    await wallet_svc.lock_funds_for_settlement(user_id=user_id, amount_toman=50000, settlement_id=uuid.uuid4(), idempotency_key=f"LOCK-1-{uuid.uuid4().hex}")

    history = await wallet_svc.get_ledger_history(user_id)
    assert len(history) == 3
    directions = [e["direction"] for e in history]
    # Most recent first: DEBIT (lock 50k), CREDIT (200k), CREDIT (100k)
    assert directions == ["DEBIT", "CREDIT", "CREDIT"]
    print("  ✓ Append-only financial ledger statements exactly audited in reverse chronological order.")


async def main():
    pool = await asyncpg.create_pool(PG_URI, min_size=2, max_size=5)
    try:
        await test_wallet_initialization_and_commission_credit(pool)
        await test_settlement_locking_and_insufficient_funds(pool)
        await test_settlement_payout_and_refund_cycles(pool)
        await test_append_only_ledger_history(pool)
        print("\n" + "=" * 70)
        print("ALL 4 WALLET & FINANCIAL LEDGER TEST SUITES PASSED (100% SUCCESS)!")
        print("=" * 70)
    finally:
        await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
