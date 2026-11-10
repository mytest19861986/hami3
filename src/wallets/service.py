"""
Wallet & Append-Only Financial Ledger Service (WALLET-001..010, BR-15, AC-11)
REMEDIATION: HC-T14 (F-06, F-07, T14-AC1..AC4)

Guarantees:
- Atomic single-connection transaction composition (`conn` parameter supported across
  mutations so callers never split wallet deduction and settlement creation across two
  separate transactions!)
- Fail-closed policy gating (`OPEN_06`, `OPEN_04`, `OPEN_18`) so unapproved/blocked policies
  disable sensitive financial operations
- Mathematical invariants: non-negative balances, strictly positive settlement/credit amounts,
  idempotent ledger entries
"""

import uuid
from typing import Any, Dict, List

import asyncpg

from src.core.policy import PolicyNotApprovedError, require_approved_policy  # noqa: F401


class WalletError(Exception):
    """Base exception for wallet operations."""
    pass


class InsufficientFundsError(WalletError):
    """Raised when withdrawable balance is lower than required amount."""
    pass


class WalletNotFoundError(WalletError):
    """Raised when wallet does not exist."""
    pass


class DuplicateFinancialTransactionError(WalletError):
    """Raised on idempotency key replay."""
    pass


class WalletFrozenError(WalletError):
    """Raised when wallet is suspended or frozen."""
    pass


class SettlementMinimumViolationError(WalletError):
    """Raised when requested settlement amount is below the approved dynamic policy minimum."""
    pass


class WalletService:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    async def get_or_create_wallet(
        self,
        user_id: uuid.UUID,
        conn: asyncpg.Connection | None = None,
    ) -> Dict[str, Any]:
        """Idempotently gets or initializes a user wallet with 0 balance."""
        query = """
            INSERT INTO wallets (user_id, withdrawable_balance_toman, locked_balance_toman, status)
            VALUES ($1, 0, 0, 'ACTIVE')
            ON CONFLICT (user_id) DO UPDATE SET updated_at = NOW()
            RETURNING id, user_id, withdrawable_balance_toman, locked_balance_toman, status, created_at, updated_at
        """
        if conn is not None:
            row = await conn.fetchrow(query, user_id)
            return dict(row)

        async with self.pool.acquire() as own_conn:
            row = await own_conn.fetchrow(query, user_id)
            return dict(row)

    async def get_wallet_by_user_id(
        self,
        user_id: uuid.UUID,
        conn: asyncpg.Connection | None = None,
    ) -> Dict[str, Any]:
        """Retrieves wallet by user ID."""
        if conn is not None:
            row = await conn.fetchrow("SELECT * FROM wallets WHERE user_id = $1", user_id)
            if not row:
                raise WalletNotFoundError(f"Wallet for user {user_id} not found.")
            return dict(row)

        async with self.pool.acquire() as own_conn:
            row = await own_conn.fetchrow("SELECT * FROM wallets WHERE user_id = $1", user_id)
            if not row:
                raise WalletNotFoundError(f"Wallet for user {user_id} not found.")
            return dict(row)

    async def _credit_commission_on_conn(
        self,
        conn: asyncpg.Connection,
        user_id: uuid.UUID,
        amount_toman: int,
        reference_id: str,
        idempotency_key: str,
        description: str,
        created_by: uuid.UUID | None = None,
    ) -> Dict[str, Any]:
        await require_approved_policy(conn, "OPEN_18_CURRENCY_AND_ROUNDING")

        existing_entry = await conn.fetchrow(
            "SELECT id, balance_after_toman FROM wallet_ledger_entries WHERE idempotency_key = $1",
            idempotency_key,
        )
        if existing_entry:
            return await self.get_wallet_by_user_id(user_id, conn=conn)

        wallet = await conn.fetchrow(
            "SELECT id, status, withdrawable_balance_toman, locked_balance_toman FROM wallets WHERE user_id = $1 FOR UPDATE",
            user_id,
        )
        if not wallet:
            wallet = await conn.fetchrow(
                "INSERT INTO wallets (user_id) VALUES ($1) RETURNING id, status, withdrawable_balance_toman, locked_balance_toman",
                user_id,
            )

        if wallet["status"] != "ACTIVE":
            raise WalletFrozenError(f"Wallet is '{wallet['status']}'. Transactions blocked.")

        balance_before = wallet["withdrawable_balance_toman"]
        balance_after = balance_before + amount_toman

        await conn.execute(
            """
            UPDATE wallets
            SET withdrawable_balance_toman = $1,
                updated_at = NOW()
            WHERE id = $2
            """,
            balance_after,
            wallet["id"],
        )

        ledger_row = await conn.fetchrow(
            """
            INSERT INTO wallet_ledger_entries (
                wallet_id, entry_type, amount_toman, direction,
                balance_before_toman, balance_after_toman,
                reference_id, idempotency_key, description, created_by
            ) VALUES (
                $1, 'COMMISSION_CREDIT', $2, 'CREDIT',
                $3, $4, $5, $6, $7, $8
            )
            RETURNING id, created_at
            """,
            wallet["id"],
            amount_toman,
            balance_before,
            balance_after,
            reference_id,
            idempotency_key,
            description,
            created_by,
        )

        return {
            "wallet_id": wallet["id"],
            "balance_before_toman": balance_before,
            "balance_after_toman": balance_after,
            "ledger_entry_id": ledger_row["id"],
            "credited_amount_toman": amount_toman,
        }

    async def credit_commission(
        self,
        user_id: uuid.UUID,
        amount_toman: int,
        reference_id: str,
        idempotency_key: str,
        description: str,
        created_by: uuid.UUID | None = None,
        conn: asyncpg.Connection | None = None,
    ) -> Dict[str, Any]:
        """
        Atomically credits commission to wallet and records immutable ledger entry.
        Requires approved OPEN_18 currency/rounding policy.
        Accepts an optional transaction-scoped `conn` to compose atomically.
        """
        if amount_toman <= 0:
            raise WalletError("Credit amount must be positive.")

        if conn is not None:
            return await self._credit_commission_on_conn(
                conn, user_id, amount_toman, reference_id, idempotency_key, description, created_by
            )

        async with self.pool.acquire() as own_conn:
            async with own_conn.transaction():
                return await self._credit_commission_on_conn(
                    own_conn, user_id, amount_toman, reference_id, idempotency_key, description, created_by
                )

    async def _lock_funds_on_conn(
        self,
        conn: asyncpg.Connection,
        user_id: uuid.UUID,
        amount_toman: int,
        settlement_id: uuid.UUID,
        idempotency_key: str,
    ) -> Dict[str, Any]:
        # Fail-Closed Policy Gates (T14-AC1, T14-AC2)
        min_policy = await require_approved_policy(conn, "OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN")
        await require_approved_policy(conn, "OPEN_18_CURRENCY_AND_ROUNDING")

        min_amount = int(min_policy.get("min_amount_toman", 0))
        if min_amount <= 0:
            raise WalletError("Configured OPEN_06 min_amount_toman must be positive.")
        if amount_toman < min_amount:
            raise SettlementMinimumViolationError(
                f"Settlement amount {amount_toman} Toman is below approved minimum {min_amount} Toman."
            )

        existing_entry = await conn.fetchrow(
            "SELECT id FROM wallet_ledger_entries WHERE idempotency_key = $1",
            idempotency_key,
        )
        if existing_entry:
            raise DuplicateFinancialTransactionError("Duplicate settlement lock idempotency key.")

        wallet = await conn.fetchrow(
            "SELECT id, status, withdrawable_balance_toman, locked_balance_toman FROM wallets WHERE user_id = $1 FOR UPDATE",
            user_id,
        )
        if not wallet:
            raise WalletNotFoundError("Wallet not found.")

        if wallet["status"] != "ACTIVE":
            raise WalletFrozenError(f"Wallet is '{wallet['status']}'. Settlement blocked.")

        if wallet["withdrawable_balance_toman"] < amount_toman:
            raise InsufficientFundsError(
                f"Insufficient funds: Available {wallet['withdrawable_balance_toman']} < Requested {amount_toman}"
            )

        balance_before = wallet["withdrawable_balance_toman"]
        balance_after = balance_before - amount_toman
        new_locked = wallet["locked_balance_toman"] + amount_toman

        await conn.execute(
            """
            UPDATE wallets
            SET withdrawable_balance_toman = $1,
                locked_balance_toman = $2,
                updated_at = NOW()
            WHERE id = $3
            """,
            balance_after,
            new_locked,
            wallet["id"],
        )

        await conn.execute(
            """
            INSERT INTO wallet_ledger_entries (
                wallet_id, entry_type, amount_toman, direction,
                balance_before_toman, balance_after_toman,
                reference_id, idempotency_key, description
            ) VALUES (
                $1, 'SETTLEMENT_LOCK', $2, 'DEBIT',
                $3, $4, $5, $6, $7
            )
            """,
            wallet["id"],
            amount_toman,
            balance_before,
            balance_after,
            str(settlement_id),
            idempotency_key,
            f"قفل موجودی بابت درخواست تسویه {settlement_id}",
        )

        return {
            "wallet_id": wallet["id"],
            "withdrawable_balance_toman": balance_after,
            "locked_balance_toman": new_locked,
        }

    async def lock_funds_for_settlement(
        self,
        user_id: uuid.UUID,
        amount_toman: int,
        settlement_id: uuid.UUID,
        idempotency_key: str,
        conn: asyncpg.Connection | None = None,
    ) -> Dict[str, Any]:
        """
        Deducts from withdrawable balance and locks in locked_balance_toman (AC-12).
        F-07 Fix: Executes on caller's `conn` when provided so rollback of duplicate/invalid
        settlement requests atomically rolls back both wallet balance and ledger entry.
        """
        if amount_toman <= 0:
            raise WalletError("Settlement amount must be positive.")

        if conn is not None:
            return await self._lock_funds_on_conn(
                conn, user_id, amount_toman, settlement_id, idempotency_key
            )

        async with self.pool.acquire() as own_conn:
            async with own_conn.transaction():
                return await self._lock_funds_on_conn(
                    own_conn, user_id, amount_toman, settlement_id, idempotency_key
                )

    async def finalize_settlement_payout(
        self,
        user_id: uuid.UUID,
        amount_toman: int,
        settlement_id: uuid.UUID,
        idempotency_key: str,
        paid_by: uuid.UUID,
    ) -> Dict[str, Any]:
        """
        Deducts from locked_balance_toman upon successful bank transfer payout.
        Requires approved OPEN_04 & OPEN_18 financial policies.
        """
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await require_approved_policy(conn, "OPEN_04_FINANCIAL_PERMISSIONS_MATRIX")
                await require_approved_policy(conn, "OPEN_18_CURRENCY_AND_ROUNDING")

                wallet = await conn.fetchrow(
                    "SELECT id, locked_balance_toman, withdrawable_balance_toman FROM wallets WHERE user_id = $1 FOR UPDATE",
                    user_id,
                )
                if not wallet or wallet["locked_balance_toman"] < amount_toman:
                    raise WalletError("Invalid locked balance for settlement finalization.")

                new_locked = wallet["locked_balance_toman"] - amount_toman
                await conn.execute(
                    "UPDATE wallets SET locked_balance_toman = $1, updated_at = NOW() WHERE id = $2",
                    new_locked,
                    wallet["id"],
                )

                await conn.execute(
                    """
                    INSERT INTO wallet_ledger_entries (
                        wallet_id, entry_type, amount_toman, direction,
                        balance_before_toman, balance_after_toman,
                        reference_id, idempotency_key, description, created_by
                    ) VALUES (
                        $1, 'SETTLEMENT_DEBIT', $2, 'DEBIT',
                        $3, $3, $4, $5, $6, $7
                    )
                    """,
                    wallet["id"],
                    amount_toman,
                    wallet["withdrawable_balance_toman"],
                    str(settlement_id),
                    idempotency_key,
                    f"تکمیل و پرداخت حواله بانکی تسویه {settlement_id}",
                    paid_by,
                )

                return {
                    "wallet_id": wallet["id"],
                    "locked_balance_toman": new_locked,
                }

    async def refund_locked_settlement(
        self,
        user_id: uuid.UUID,
        amount_toman: int,
        settlement_id: uuid.UUID,
        idempotency_key: str,
        reason: str,
    ) -> Dict[str, Any]:
        """Unlocks funds back to withdrawable balance if settlement is REJECTED or CANCELLED."""
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await require_approved_policy(conn, "OPEN_18_CURRENCY_AND_ROUNDING")

                wallet = await conn.fetchrow(
                    "SELECT id, withdrawable_balance_toman, locked_balance_toman FROM wallets WHERE user_id = $1 FOR UPDATE",
                    user_id,
                )
                if not wallet or wallet["locked_balance_toman"] < amount_toman:
                    raise WalletError("Invalid locked balance for refund.")

                balance_before = wallet["withdrawable_balance_toman"]
                balance_after = balance_before + amount_toman
                new_locked = wallet["locked_balance_toman"] - amount_toman

                await conn.execute(
                    """
                    UPDATE wallets
                    SET withdrawable_balance_toman = $1,
                        locked_balance_toman = $2,
                        updated_at = NOW()
                    WHERE id = $3
                    """,
                    balance_after,
                    new_locked,
                    wallet["id"],
                )

                await conn.execute(
                    """
                    INSERT INTO wallet_ledger_entries (
                        wallet_id, entry_type, amount_toman, direction,
                        balance_before_toman, balance_after_toman,
                        reference_id, idempotency_key, description
                    ) VALUES (
                        $1, 'SETTLEMENT_REFUND', $2, 'CREDIT',
                        $3, $4, $5, $6, $7
                    )
                    """,
                    wallet["id"],
                    amount_toman,
                    balance_before,
                    balance_after,
                    str(settlement_id),
                    idempotency_key,
                    f"استرداد وجه تسویه رد شده: {reason}",
                )

                return {
                    "wallet_id": wallet["id"],
                    "withdrawable_balance_toman": balance_after,
                    "locked_balance_toman": new_locked,
                }

    async def get_ledger_history(
        self,
        user_id: uuid.UUID,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Returns append-only financial ledger statements for user auditing."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT l.*
                FROM wallet_ledger_entries l
                JOIN wallets w ON l.wallet_id = w.id
                WHERE w.user_id = $1
                ORDER BY l.created_at DESC
                LIMIT $2 OFFSET $3
                """,
                user_id,
                limit,
                offset,
            )
            return [dict(r) for r in rows]
