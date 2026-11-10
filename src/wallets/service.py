"""
Wallet & Append-Only Financial Ledger Service (WALLET-001..010, BR-15, AC-11)
Enforces mathematical invariants: non-negative balances, atomic ledger auditing,
idempotent commission credits, and settlement locking/settling cycles.
"""

import uuid
from typing import Dict, Any, List, Optional
import asyncpg


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


class WalletService:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    async def get_or_create_wallet(self, user_id: uuid.UUID) -> Dict[str, Any]:
        """Idempotently gets or initializes a user wallet with 0 balance."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO wallets (user_id, withdrawable_balance_toman, locked_balance_toman, status)
                VALUES ($1, 0, 0, 'ACTIVE')
                ON CONFLICT (user_id) DO UPDATE SET updated_at = NOW()
                RETURNING id, user_id, withdrawable_balance_toman, locked_balance_toman, status, created_at, updated_at
                """, user_id
            )
            return dict(row)

    async def get_wallet_by_user_id(self, user_id: uuid.UUID) -> Dict[str, Any]:
        """Retrieves wallet by user ID."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM wallets WHERE user_id = $1", user_id
            )
            if not row:
                raise WalletNotFoundError(f"Wallet for user {user_id} not found.")
            return dict(row)

    async def credit_commission(
        self,
        user_id: uuid.UUID,
        amount_toman: int,
        reference_id: str,
        idempotency_key: str,
        description: str,
        created_by: Optional[uuid.UUID] = None
    ) -> Dict[str, Any]:
        """
        Atomically credits commission to wallet and records immutable ledger entry.
        Idempotent: duplicate key returns existing balance without double-crediting.
        """
        if amount_toman <= 0:
            raise WalletError("Credit amount must be positive.")

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                # 1. Check idempotency
                existing_entry = await conn.fetchrow(
                    "SELECT id, balance_after_toman FROM wallet_ledger_entries WHERE idempotency_key = $1",
                    idempotency_key
                )
                if existing_entry:
                    wallet = await self.get_wallet_by_user_id(user_id)
                    return wallet

                # 2. Lock wallet row FOR UPDATE
                wallet = await conn.fetchrow(
                    "SELECT id, status, withdrawable_balance_toman, locked_balance_toman FROM wallets WHERE user_id = $1 FOR UPDATE",
                    user_id
                )
                if not wallet:
                    # Create if missing
                    wallet = await conn.fetchrow(
                        "INSERT INTO wallets (user_id) VALUES ($1) RETURNING id, status, withdrawable_balance_toman, locked_balance_toman",
                        user_id
                    )

                if wallet["status"] != "ACTIVE":
                    raise WalletFrozenError(f"Wallet is '{wallet['status']}'. Transactions blocked.")

                balance_before = wallet["withdrawable_balance_toman"]
                balance_after = balance_before + amount_toman

                # 3. Update wallet balance
                await conn.execute(
                    """
                    UPDATE wallets
                    SET withdrawable_balance_toman = $1,
                        updated_at = NOW()
                    WHERE id = $2
                    """, balance_after, wallet["id"]
                )

                # 4. Insert immutable ledger entry
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
                    wallet["id"], amount_toman, balance_before, balance_after,
                    reference_id, idempotency_key, description, created_by
                )

                return {
                    "wallet_id": wallet["id"],
                    "balance_before_toman": balance_before,
                    "balance_after_toman": balance_after,
                    "ledger_entry_id": ledger_row["id"],
                    "credited_amount_toman": amount_toman
                }

    async def lock_funds_for_settlement(
        self,
        user_id: uuid.UUID,
        amount_toman: int,
        settlement_id: uuid.UUID,
        idempotency_key: str
    ) -> Dict[str, Any]:
        """
        Deducts from withdrawable balance and locks in locked_balance_toman
        when a settlement request is created (AC-12).
        """
        if amount_toman <= 0:
            raise WalletError("Settlement amount must be positive.")

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                # Check idempotency
                existing_entry = await conn.fetchrow(
                    "SELECT id FROM wallet_ledger_entries WHERE idempotency_key = $1",
                    idempotency_key
                )
                if existing_entry:
                    raise DuplicateFinancialTransactionError("Duplicate settlement lock idempotency key.")

                # Lock wallet
                wallet = await conn.fetchrow(
                    "SELECT id, status, withdrawable_balance_toman, locked_balance_toman FROM wallets WHERE user_id = $1 FOR UPDATE",
                    user_id
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

                # Update wallet
                await conn.execute(
                    """
                    UPDATE wallets
                    SET withdrawable_balance_toman = $1,
                        locked_balance_toman = $2,
                        updated_at = NOW()
                    WHERE id = $3
                    """, balance_after, new_locked, wallet["id"]
                )

                # Record ledger
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
                    wallet["id"], amount_toman, balance_before, balance_after,
                    str(settlement_id), idempotency_key,
                    f"قفل موجودی بابت درخواست تسویه {settlement_id}"
                )

                return {
                    "wallet_id": wallet["id"],
                    "withdrawable_balance_toman": balance_after,
                    "locked_balance_toman": new_locked
                }

    async def finalize_settlement_payout(
        self,
        user_id: uuid.UUID,
        amount_toman: int,
        settlement_id: uuid.UUID,
        idempotency_key: str,
        paid_by: uuid.UUID
    ) -> Dict[str, Any]:
        """
        Deducts from locked_balance_toman upon successful bank transfer payout.
        """
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                wallet = await conn.fetchrow(
                    "SELECT id, locked_balance_toman, withdrawable_balance_toman FROM wallets WHERE user_id = $1 FOR UPDATE",
                    user_id
                )
                if not wallet or wallet["locked_balance_toman"] < amount_toman:
                    raise WalletError("Invalid locked balance for settlement finalization.")

                new_locked = wallet["locked_balance_toman"] - amount_toman
                await conn.execute(
                    "UPDATE wallets SET locked_balance_toman = $1, updated_at = NOW() WHERE id = $2",
                    new_locked, wallet["id"]
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
                    wallet["id"], amount_toman, wallet["withdrawable_balance_toman"],
                    str(settlement_id), idempotency_key,
                    f"تکمیل و پرداخت حواله بانکی تسویه {settlement_id}", paid_by
                )

                return {
                    "wallet_id": wallet["id"],
                    "locked_balance_toman": new_locked
                }

    async def refund_locked_settlement(
        self,
        user_id: uuid.UUID,
        amount_toman: int,
        settlement_id: uuid.UUID,
        idempotency_key: str,
        reason: str
    ) -> Dict[str, Any]:
        """
        Unlocks funds back to withdrawable balance if settlement is REJECTED or CANCELLED.
        """
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                wallet = await conn.fetchrow(
                    "SELECT id, withdrawable_balance_toman, locked_balance_toman FROM wallets WHERE user_id = $1 FOR UPDATE",
                    user_id
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
                    """, balance_after, new_locked, wallet["id"]
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
                    wallet["id"], amount_toman, balance_before, balance_after,
                    str(settlement_id), idempotency_key,
                    f"استرداد وجه تسویه رد شده: {reason}"
                )

                return {
                    "wallet_id": wallet["id"],
                    "withdrawable_balance_toman": balance_after,
                    "locked_balance_toman": new_locked
                }

    async def get_ledger_history(
        self,
        user_id: uuid.UUID,
        limit: int = 50,
        offset: int = 0
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
                """, user_id, limit, offset
            )
            return [dict(r) for r in rows]
