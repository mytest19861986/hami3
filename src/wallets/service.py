"""
Wallet & Append-Only Financial Ledger Service (WALLET-001..010, SETTLE-001..017, BR-15, AC-11)
REMEDIATION: HC-T14 (F-06, F-07), HC-T20 (T20-AC1..AC4), HC-T27 (M-2, T27-AC1..AC4)

Guarantees:
- Atomic single-connection transaction composition (`conn` parameter supported across
  mutations so callers never split wallet deduction/refund and settlement state changes
  across two separate transactions!)
- Serialized row locking (`settlements` -> `wallets` `FOR UPDATE`) so concurrent
  identical/conflicting replays NEVER double-lock, double-credit, double-pay, or
  double-refund (`SETTLE-010`, `SETTLE-011`, `SETTLE-012`).
- Fail-closed policy gating (`OPEN_04`, `OPEN_06`, `OPEN_18`) returning PolicyNotApprovedError.
- Authoritative RBAC (`settlements:process`, `settlements:pay` via `user_roles`) and
  documented external payout proof verification (`BasePayoutProofVerifier`) before
  marking any settlement `PAID` (no automated bank transfer, no self-asserted string trust).
"""

import hashlib
import json
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Set

import asyncpg

from src.auth.rbac import RbacAccessDeniedError, RbacEngine
from src.common.pii import mask_card_number, mask_shaba
from src.core.env import EnvironmentConfigurationError, is_restricted_environment
from src.core.policy import PolicyNotApprovedError, require_approved_policy  # noqa: F401

VALID_SETTLEMENT_STATUSES = (
    "PENDING",
    "PROCESSING",
    "APPROVED",
    "PAID",
    "REJECTED",
    "CANCELLED",
)


def _is_production_env() -> bool:
    try:
        return is_restricted_environment()
    except EnvironmentConfigurationError as exc:
        raise PayoutAdapterConfigurationError(str(exc)) from exc


def _resolve_actor_role_label(roles: Set[str]) -> str:
    for candidate in ("SUPER_ADMIN", "ADMIN", "SUPPORT", "DOCTOR", "AGENT", "USER"):
        if candidate in roles:
            return candidate
    return "USER"


def _normalize_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _normalize_idempotency_header(idempotency_key: str | None) -> str | None:
    if idempotency_key is None:
        return None
    clean = idempotency_key.strip()
    if len(clean) < 4 or len(clean) > 128:
        raise WalletError(
            "Invalid Idempotency-Key header (must be 4 to 128 non-whitespace characters)."
        )
    return clean


def _scope_actor_idem_key(actor_user_id: uuid.UUID, action: str, raw_key: str) -> str:
    digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:32]
    return f"{action}:{actor_user_id.hex}:{digest}"


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
    """Raised on idempotency key replay in financial ledger mutations."""
    pass


class IdempotencyConflictError(WalletError):
    """Raised when a client Idempotency-Key is reused with a different request payload."""
    pass


class WalletFrozenError(WalletError):
    """Raised when wallet is suspended or frozen."""
    pass


class SettlementMinimumViolationError(WalletError):
    """Raised when requested settlement amount is below the approved dynamic policy minimum."""
    pass


class SettlementAuthorizationError(WalletError):
    """Raised when actor lacks RBAC role/permission or OPEN-04 authorization."""
    pass


class SettlementNotFoundError(WalletError):
    """Raised when settlement record does not exist."""
    pass


class InvalidSettlementTransitionError(WalletError):
    """Raised when requested settlement state transition violates SETTLE-007..012."""
    pass


class DuplicatePayoutReferenceError(WalletError):
    """Raised when an external_payment_ref is reused across multiple settlements."""
    pass


class PayoutVerificationError(WalletError):
    """Raised when documented external bank payout evidence fails verification."""
    pass


class PayoutAdapterConfigurationError(WalletError):
    """Raised when no production-safe external payout verifier is configured."""
    pass


@dataclass
class PayoutVerificationResult:
    verified: bool
    external_payment_ref: str
    settlement_id: uuid.UUID
    amount_toman: int
    destination_sheba: str
    transfer_date: datetime
    evidence_source: str
    error_message: str | None = None


class BasePayoutProofVerifier(ABC):
    """
    Abstract verifier for documented off-system bank payout receipts (`SETTLE-008`, `SETTLE-016`).
    Must verify transfer evidence against an authoritative clearing/reconciliation source
    without executing automated bank transfers.
    """

    @abstractmethod
    async def verify_payout_proof(
        self,
        *,
        settlement_id: uuid.UUID,
        external_payment_ref: str,
        amount_toman: int,
        destination_sheba: str,
        payment_date: datetime,
    ) -> PayoutVerificationResult:
        pass


class SandboxPayoutProofVerifier(BasePayoutProofVerifier):
    """
    Non-production sandbox payout proof verifier mirroring `MockPaymentGateway`.
    Admin strings submitted over HTTP CANNOT mark a settlement PAID unless the matching
    transfer receipt was explicitly confirmed in this authoritative external registry.
    Strictly disabled in production (`APP_ENV` / `NODE_ENV == 'production'`).
    """

    def __init__(self) -> None:
        if _is_production_env():
            raise PayoutAdapterConfigurationError(
                "SandboxPayoutProofVerifier is strictly forbidden in production/staging."
            )
        self._verified_payouts: Dict[str, Dict[str, Any]] = {}

    def register_verified_payout(
        self,
        *,
        external_payment_ref: str,
        settlement_id: uuid.UUID,
        amount_toman: int,
        destination_sheba: str,
        transfer_date: datetime | None = None,
        evidence_source: str = "SANDBOX_PAYA_SETTLEMENT_FEED",
    ) -> Dict[str, Any]:
        if _is_production_env():
            raise PayoutAdapterConfigurationError(
                "Sandbox payout registration is strictly forbidden in production/staging."
            )
        ref_clean = (external_payment_ref or "").strip()
        if len(ref_clean) < 6:
            raise PayoutVerificationError(
                "external_payment_ref must be at least 6 non-whitespace characters."
            )
        sheba_clean = (destination_sheba or "").replace(" ", "").strip().upper()
        dt_utc = _normalize_utc(transfer_date or datetime.now(UTC))
        record = {
            "external_payment_ref": ref_clean,
            "settlement_id": uuid.UUID(str(settlement_id)),
            "amount_toman": int(amount_toman),
            "destination_sheba": sheba_clean,
            "transfer_date": dt_utc,
            "evidence_source": evidence_source,
            "verified": True,
        }
        self._verified_payouts[ref_clean] = record
        return dict(record)

    async def verify_payout_proof(
        self,
        *,
        settlement_id: uuid.UUID,
        external_payment_ref: str,
        amount_toman: int,
        destination_sheba: str,
        payment_date: datetime,
    ) -> PayoutVerificationResult:
        if _is_production_env():
            raise PayoutAdapterConfigurationError(
                "SandboxPayoutProofVerifier cannot verify payouts in production/staging."
            )
        ref_clean = (external_payment_ref or "").strip()
        sheba_clean = (destination_sheba or "").replace(" ", "").strip().upper()
        pay_dt_utc = _normalize_utc(payment_date)

        rec = self._verified_payouts.get(ref_clean)
        if not rec or not rec.get("verified", False):
            return PayoutVerificationResult(
                verified=False,
                external_payment_ref=ref_clean,
                settlement_id=settlement_id,
                amount_toman=int(amount_toman),
                destination_sheba=sheba_clean,
                transfer_date=pay_dt_utc,
                evidence_source="NONE",
                error_message=(
                    "Unverified external payout reference: no matching confirmed "
                    "bank clearing receipt exists for this transfer reference."
                ),
            )

        if rec["settlement_id"] != settlement_id:
            return PayoutVerificationResult(
                verified=False,
                external_payment_ref=ref_clean,
                settlement_id=settlement_id,
                amount_toman=int(amount_toman),
                destination_sheba=sheba_clean,
                transfer_date=pay_dt_utc,
                evidence_source=rec["evidence_source"],
                error_message="External payout receipt belongs to a different settlement ID.",
            )

        if int(rec["amount_toman"]) != int(amount_toman):
            return PayoutVerificationResult(
                verified=False,
                external_payment_ref=ref_clean,
                settlement_id=settlement_id,
                amount_toman=int(amount_toman),
                destination_sheba=sheba_clean,
                transfer_date=pay_dt_utc,
                evidence_source=rec["evidence_source"],
                error_message=(
                    f"External payout receipt amount ({rec['amount_toman']}) does not match "
                    f"settlement amount ({amount_toman})."
                ),
            )

        if rec["destination_sheba"] != sheba_clean:
            return PayoutVerificationResult(
                verified=False,
                external_payment_ref=ref_clean,
                settlement_id=settlement_id,
                amount_toman=int(amount_toman),
                destination_sheba=sheba_clean,
                transfer_date=pay_dt_utc,
                evidence_source=rec["evidence_source"],
                error_message="External payout destination Sheba does not match settlement request.",
            )

        if abs((rec["transfer_date"] - pay_dt_utc).total_seconds()) > 86400:
            return PayoutVerificationResult(
                verified=False,
                external_payment_ref=ref_clean,
                settlement_id=settlement_id,
                amount_toman=int(amount_toman),
                destination_sheba=sheba_clean,
                transfer_date=pay_dt_utc,
                evidence_source=rec["evidence_source"],
                error_message="Provided external_payment_date conflicts with confirmed transfer timestamp.",
            )

        return PayoutVerificationResult(
            verified=True,
            external_payment_ref=ref_clean,
            settlement_id=settlement_id,
            amount_toman=int(amount_toman),
            destination_sheba=sheba_clean,
            transfer_date=rec["transfer_date"],
            evidence_source=rec["evidence_source"],
        )


_sandbox_payout_verifier: SandboxPayoutProofVerifier | None = None


def reset_runtime_payout_verifier() -> None:
    """Clears process-local sandbox payout verifier registry (non-production tests only)."""
    global _sandbox_payout_verifier
    _sandbox_payout_verifier = None


def get_runtime_payout_verifier() -> BasePayoutProofVerifier:
    """
    Returns active external payout proof verifier.
    Fails closed in production (`APP_ENV`/`NODE_ENV=production`) until a real
    bank reconciliation verifier is configured (`SETTLE-008`, `SETTLE-016`).
    """
    global _sandbox_payout_verifier
    if _is_production_env():
        raise PayoutAdapterConfigurationError(
            "Sandbox payout verifier is disabled in production/staging; configure an authoritative bank reconciliation verifier."
        )
    if _sandbox_payout_verifier is None:
        _sandbox_payout_verifier = SandboxPayoutProofVerifier()
    return _sandbox_payout_verifier


class WalletService:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool
        self.rbac = RbacEngine(pool)

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

    async def find_settlement_by_idempotency_key(
        self,
        conn: asyncpg.Connection,
        user_id: uuid.UUID,
        idempotency_key: str,
    ) -> Dict[str, Any] | None:
        """
        Looks up a previously committed settlement record linked to a scoped
        SETTLEMENT_LOCK ledger idempotency key belonging to `user_id`.
        """
        row = await conn.fetchrow(
            """
            SELECT s.id, s.user_id, s.wallet_id, s.amount_toman, s.bank_card_number,
                   s.bank_sheba_number, s.bank_account_holder_name,
                   s.status, s.rejection_reason, s.external_payment_ref,
                   s.external_payment_date, s.paid_by, s.created_at, s.updated_at
            FROM wallet_ledger_entries wle
            JOIN wallets w ON wle.wallet_id = w.id
            JOIN settlements s ON wle.reference_id = s.id::text AND s.user_id = w.user_id
            WHERE wle.idempotency_key = $1
              AND w.user_id = $2
              AND wle.entry_type = 'SETTLEMENT_LOCK'
              AND s.deleted_at IS NULL
            """,
            idempotency_key,
            user_id,
        )
        return dict(row) if row else None

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

        await conn.execute(
            "INSERT INTO wallets (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING",
            user_id,
        )
        wallet = await conn.fetchrow(
            "SELECT id, status, withdrawable_balance_toman, locked_balance_toman FROM wallets WHERE user_id = $1 FOR UPDATE",
            user_id,
        )

        existing_entry = await conn.fetchrow(
            "SELECT id, balance_after_toman FROM wallet_ledger_entries WHERE idempotency_key = $1",
            idempotency_key,
        )
        if existing_entry:
            return await self.get_wallet_by_user_id(user_id, conn=conn)

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

        wallet = await conn.fetchrow(
            "SELECT id, status, withdrawable_balance_toman, locked_balance_toman FROM wallets WHERE user_id = $1 FOR UPDATE",
            user_id,
        )
        if not wallet:
            raise WalletNotFoundError("Wallet not found.")

        existing_entry = await conn.fetchrow(
            "SELECT id FROM wallet_ledger_entries WHERE idempotency_key = $1",
            idempotency_key,
        )
        if existing_entry:
            raise DuplicateFinancialTransactionError("Duplicate settlement lock idempotency key.")

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

    async def _finalize_settlement_payout_on_conn(
        self,
        conn: asyncpg.Connection,
        user_id: uuid.UUID,
        amount_toman: int,
        settlement_id: uuid.UUID,
        idempotency_key: str,
        paid_by: uuid.UUID,
    ) -> Dict[str, Any]:
        await require_approved_policy(conn, "OPEN_04_FINANCIAL_PERMISSIONS_MATRIX")
        await require_approved_policy(conn, "OPEN_18_CURRENCY_AND_ROUNDING")

        wallet = await conn.fetchrow(
            "SELECT id, locked_balance_toman, withdrawable_balance_toman FROM wallets WHERE user_id = $1 FOR UPDATE",
            user_id,
        )
        if not wallet:
            raise WalletNotFoundError("Wallet not found.")

        existing_entry = await conn.fetchrow(
            "SELECT id FROM wallet_ledger_entries WHERE idempotency_key = $1",
            idempotency_key,
        )
        if existing_entry:
            raise DuplicateFinancialTransactionError(
                "Duplicate settlement payout idempotency key."
            )

        if wallet["locked_balance_toman"] < amount_toman:
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

    async def finalize_settlement_payout(
        self,
        user_id: uuid.UUID,
        amount_toman: int,
        settlement_id: uuid.UUID,
        idempotency_key: str,
        paid_by: uuid.UUID,
        conn: asyncpg.Connection | None = None,
    ) -> Dict[str, Any]:
        """
        Deducts from locked_balance_toman upon verified external bank transfer payout.
        Requires approved OPEN_04 & OPEN_18 financial policies and enforces idempotency.
        Accepts optional transaction-scoped `conn` to compose atomically with settlement state updates.
        """
        if amount_toman <= 0:
            raise WalletError("Payout amount must be positive.")

        if conn is not None:
            return await self._finalize_settlement_payout_on_conn(
                conn, user_id, amount_toman, settlement_id, idempotency_key, paid_by
            )

        async with self.pool.acquire() as own_conn:
            async with own_conn.transaction():
                return await self._finalize_settlement_payout_on_conn(
                    own_conn, user_id, amount_toman, settlement_id, idempotency_key, paid_by
                )

    async def _refund_locked_settlement_on_conn(
        self,
        conn: asyncpg.Connection,
        user_id: uuid.UUID,
        amount_toman: int,
        settlement_id: uuid.UUID,
        idempotency_key: str,
        reason: str,
        created_by: uuid.UUID | None = None,
    ) -> Dict[str, Any]:
        await require_approved_policy(conn, "OPEN_18_CURRENCY_AND_ROUNDING")

        wallet = await conn.fetchrow(
            "SELECT id, withdrawable_balance_toman, locked_balance_toman FROM wallets WHERE user_id = $1 FOR UPDATE",
            user_id,
        )
        if not wallet:
            raise WalletNotFoundError("Wallet not found.")

        existing_entry = await conn.fetchrow(
            "SELECT id FROM wallet_ledger_entries WHERE idempotency_key = $1",
            idempotency_key,
        )
        if existing_entry:
            raise DuplicateFinancialTransactionError(
                "Duplicate settlement refund idempotency key."
            )

        if wallet["locked_balance_toman"] < amount_toman:
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
                reference_id, idempotency_key, description, created_by
            ) VALUES (
                $1, 'SETTLEMENT_REFUND', $2, 'CREDIT',
                $3, $4, $5, $6, $7, $8
            )
            """,
            wallet["id"],
            amount_toman,
            balance_before,
            balance_after,
            str(settlement_id),
            idempotency_key,
            f"استرداد وجه تسویه رد شده: {reason}",
            created_by,
        )

        return {
            "wallet_id": wallet["id"],
            "withdrawable_balance_toman": balance_after,
            "locked_balance_toman": new_locked,
        }

    async def refund_locked_settlement(
        self,
        user_id: uuid.UUID,
        amount_toman: int,
        settlement_id: uuid.UUID,
        idempotency_key: str,
        reason: str,
        conn: asyncpg.Connection | None = None,
        created_by: uuid.UUID | None = None,
    ) -> Dict[str, Any]:
        """
        Unlocks funds back to withdrawable balance if settlement is REJECTED or CANCELLED.
        Enforces idempotency under FOR UPDATE lock so double refunds are blocked.
        """
        if amount_toman <= 0:
            raise WalletError("Refund amount must be positive.")

        if conn is not None:
            return await self._refund_locked_settlement_on_conn(
                conn, user_id, amount_toman, settlement_id, idempotency_key, reason, created_by
            )

        async with self.pool.acquire() as own_conn:
            async with own_conn.transaction():
                return await self._refund_locked_settlement_on_conn(
                    own_conn, user_id, amount_toman, settlement_id, idempotency_key, reason, created_by
                )

    async def list_settlements(
        self,
        actor_user_id: uuid.UUID,
        *,
        status_filter: str | None = None,
        user_id: uuid.UUID | None = None,
        from_date: datetime | None = None,
        to_date: datetime | None = None,
        applicant_query: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        Lists settlement requests with strict RBAC & PII masking (`SETTLE-013`, `SETTLE-014`, `SETTLE-015`).
        - Financial admins (`ADMIN` / `SUPER_ADMIN` with `settlements:process` or `settlements:pay`)
          may filter across all users by status, user_id, date range, and applicant search.
        - All other roles (including `SUPPORT`) may ONLY inspect their own settlements and receive 403
          if querying another user's records or performing admin applicant searches.
        """
        async with self.pool.acquire() as conn:
            try:
                actor_roles = await self.rbac.get_user_roles(conn, actor_user_id)
                actor_perms = await self.rbac.get_user_permissions(conn, actor_user_id)
            except RbacAccessDeniedError as exc:
                raise SettlementAuthorizationError(str(exc)) from exc

            is_fin_admin = bool(actor_roles & {"ADMIN", "SUPER_ADMIN"}) and (
                "SUPER_ADMIN" in actor_roles
                or "settlements:process" in actor_perms
                or "settlements:pay" in actor_perms
            )

            if not is_fin_admin:
                if user_id is not None and user_id != actor_user_id:
                    raise SettlementAuthorizationError(
                        "Forbidden: Only financial administrators may query another user's settlements."
                    )
                if applicant_query and applicant_query.strip():
                    raise SettlementAuthorizationError(
                        "Forbidden: Only financial administrators may search settlements by applicant."
                    )
                effective_user_id = actor_user_id
            else:
                effective_user_id = user_id

            conditions = ["s.deleted_at IS NULL"]
            params: List[Any] = []
            idx = 1

            if effective_user_id is not None:
                conditions.append(f"s.user_id = ${idx}")
                params.append(effective_user_id)
                idx += 1

            if status_filter is not None:
                st_clean = status_filter.strip().upper()
                if st_clean not in VALID_SETTLEMENT_STATUSES:
                    raise WalletError(f"Invalid settlement status filter '{status_filter}'.")
                conditions.append(f"s.status = ${idx}")
                params.append(st_clean)
                idx += 1

            if from_date is not None:
                conditions.append(f"s.created_at >= ${idx}")
                params.append(_normalize_utc(from_date))
                idx += 1

            if to_date is not None:
                conditions.append(f"s.created_at <= ${idx}")
                params.append(_normalize_utc(to_date))
                idx += 1

            if applicant_query and applicant_query.strip():
                q_pattern = f"%{applicant_query.strip()}%"
                conditions.append(
                    f"(s.bank_account_holder_name ILIKE ${idx} OR u.mobile ILIKE ${idx})"
                )
                params.append(q_pattern)
                idx += 1

            safe_limit = max(1, min(int(limit), 100))
            safe_offset = max(0, int(offset))
            params.extend([safe_limit, safe_offset])

            where_sql = " AND ".join(conditions)
            rows = await conn.fetch(
                f"""
                SELECT s.id, s.user_id, s.wallet_id, s.amount_toman,
                       s.bank_card_number, s.bank_sheba_number, s.bank_account_holder_name,
                       s.status, s.rejection_reason, s.external_payment_ref,
                       s.external_payment_date, s.paid_by, s.created_at, s.updated_at,
                       u.mobile AS applicant_mobile
                FROM settlements s
                JOIN users u ON s.user_id = u.id
                WHERE {where_sql}
                ORDER BY s.created_at DESC
                LIMIT ${idx} OFFSET ${idx + 1}
                """,
                *params,
            )
            return [dict(r) for r in rows]

    async def get_settlement_detail(
        self,
        settlement_id: uuid.UUID,
        actor_user_id: uuid.UUID,
    ) -> Dict[str, Any]:
        """Retrieves single settlement strictly for owner or authorized financial admin (`OPEN-10`)."""
        async with self.pool.acquire() as conn:
            try:
                actor_roles = await self.rbac.get_user_roles(conn, actor_user_id)
                actor_perms = await self.rbac.get_user_permissions(conn, actor_user_id)
            except RbacAccessDeniedError as exc:
                raise SettlementAuthorizationError(str(exc)) from exc

            is_fin_admin = bool(actor_roles & {"ADMIN", "SUPER_ADMIN"}) and (
                "SUPER_ADMIN" in actor_roles
                or "settlements:process" in actor_perms
                or "settlements:pay" in actor_perms
            )

            row = await conn.fetchrow(
                """
                SELECT s.id, s.user_id, s.wallet_id, s.amount_toman,
                       s.bank_card_number, s.bank_sheba_number, s.bank_account_holder_name,
                       s.status, s.rejection_reason, s.external_payment_ref,
                       s.external_payment_date, s.paid_by, s.created_at, s.updated_at
                FROM settlements s
                WHERE s.id = $1 AND s.deleted_at IS NULL
                """,
                settlement_id,
            )
            if not row:
                if is_fin_admin:
                    raise SettlementNotFoundError(f"Settlement {settlement_id} not found.")
                raise SettlementAuthorizationError(
                    "Forbidden: You are not authorized to inspect this settlement."
                )

            if row["user_id"] != actor_user_id and not is_fin_admin:
                raise SettlementAuthorizationError(
                    "Forbidden: You are not authorized to inspect this settlement."
                )
            return dict(row)

    async def approve_settlement(
        self,
        settlement_id: uuid.UUID,
        actor_user_id: uuid.UUID,
        notes: str | None = None,
    ) -> Dict[str, Any]:
        """
        Transitions settlement `PENDING -> APPROVED` (`SETTLE-007`, `SETTLE-009`).
        - Enforces authoritative `settlements:process` permission & rejects `SUPPORT`/`USER`/`DOCTOR`/`AGENT`.
        - Enforces approved `OPEN_04`, `OPEN_06`, `OPEN_18` (`403` if PROPOSED/BLOCKED).
        """
        notes_clean = notes.strip() if notes and notes.strip() else None

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                try:
                    actor_roles = await self.rbac.get_user_roles(conn, actor_user_id)
                    actor_perms = await self.rbac.get_user_permissions(conn, actor_user_id)
                except RbacAccessDeniedError as exc:
                    raise SettlementAuthorizationError(str(exc)) from exc

                is_allowed_actor = bool(actor_roles & {"ADMIN", "SUPER_ADMIN"}) and (
                    "SUPER_ADMIN" in actor_roles or "settlements:process" in actor_perms
                )
                if not is_allowed_actor:
                    raise SettlementAuthorizationError(
                        "Permission denied: Financial administrator with 'settlements:process' required."
                    )

                await require_approved_policy(conn, "OPEN_04_FINANCIAL_PERMISSIONS_MATRIX")
                await require_approved_policy(conn, "OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN")
                await require_approved_policy(conn, "OPEN_18_CURRENCY_AND_ROUNDING")

                row = await conn.fetchrow(
                    """
                    SELECT * FROM settlements
                    WHERE id = $1 AND deleted_at IS NULL
                    FOR UPDATE
                    """,
                    settlement_id,
                )
                if not row:
                    raise SettlementNotFoundError(f"Settlement {settlement_id} not found.")

                current_status = row["status"]
                if current_status != "PENDING":
                    raise InvalidSettlementTransitionError(
                        f"Cannot approve settlement in status '{current_status}'; must be 'PENDING'."
                    )

                updated = await conn.fetchrow(
                    """
                    UPDATE settlements
                    SET status = 'APPROVED',
                        updated_at = NOW()
                    WHERE id = $1 AND status = 'PENDING'
                    RETURNING *
                    """,
                    settlement_id,
                )
                if not updated:
                    raise InvalidSettlementTransitionError(
                        "Settlement state changed concurrently; approval aborted."
                    )

                actor_role = _resolve_actor_role_label(actor_roles)
                await conn.execute(
                    """
                    INSERT INTO audit_logs (
                        actor_user_id, actor_role, action, entity_name, entity_id,
                        old_values, new_values
                    ) VALUES (
                        $1, $2, 'SETTLEMENT_APPROVED', 'settlements', $3::varchar,
                        $4::jsonb, $5::jsonb
                    )
                    """,
                    actor_user_id,
                    actor_role,
                    str(settlement_id),
                    json.dumps({"status": current_status}),
                    json.dumps(
                        {
                            "status": "APPROVED",
                            "amount_toman": int(updated["amount_toman"]),
                            "bank_card_masked": mask_card_number(updated["bank_card_number"]),
                            "bank_sheba_masked": mask_shaba(updated["bank_sheba_number"]),
                            "notes": notes_clean,
                        },
                        ensure_ascii=False,
                    ),
                )

                return dict(updated)

    async def reject_settlement(
        self,
        settlement_id: uuid.UUID,
        actor_user_id: uuid.UUID,
        reason: str,
        idempotency_key: str | None = None,
    ) -> Dict[str, Any]:
        """
        Atomically rejects an open settlement (`PENDING | PROCESSING | APPROVED -> REJECTED`)
        and unlocks `locked_balance_toman` back to `withdrawable_balance_toman` EXACTLY ONCE (`SETTLE-012`).
        """
        reason_clean = (reason or "").strip()
        if len(reason_clean) < 3:
            raise WalletError("Rejection reason must be at least 3 non-whitespace characters.")

        clean_idem = _normalize_idempotency_header(idempotency_key)
        scoped_idem_key = (
            _scope_actor_idem_key(actor_user_id, "SETTLE-REJECT-REQ", clean_idem)
            if clean_idem is not None
            else None
        )

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                try:
                    actor_roles = await self.rbac.get_user_roles(conn, actor_user_id)
                    actor_perms = await self.rbac.get_user_permissions(conn, actor_user_id)
                except RbacAccessDeniedError as exc:
                    raise SettlementAuthorizationError(str(exc)) from exc

                is_allowed_actor = bool(actor_roles & {"ADMIN", "SUPER_ADMIN"}) and (
                    "SUPER_ADMIN" in actor_roles or "settlements:process" in actor_perms
                )
                if not is_allowed_actor:
                    raise SettlementAuthorizationError(
                        "Permission denied: Financial administrator with 'settlements:process' required."
                    )

                await require_approved_policy(conn, "OPEN_04_FINANCIAL_PERMISSIONS_MATRIX")
                await require_approved_policy(conn, "OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN")
                await require_approved_policy(conn, "OPEN_18_CURRENCY_AND_ROUNDING")

                row = await conn.fetchrow(
                    """
                    SELECT * FROM settlements
                    WHERE id = $1 AND deleted_at IS NULL
                    FOR UPDATE
                    """,
                    settlement_id,
                )
                if not row:
                    raise SettlementNotFoundError(f"Settlement {settlement_id} not found.")

                if scoped_idem_key is not None:
                    prior_key_log = await conn.fetchrow(
                        """
                        SELECT entity_id, new_values
                        FROM audit_logs
                        WHERE action = 'SETTLEMENT_REJECTED'
                          AND new_values->>'client_idempotency_key' = $1
                        LIMIT 1
                        """,
                        scoped_idem_key,
                    )
                    if prior_key_log is not None:
                        if prior_key_log["entity_id"] != str(settlement_id):
                            raise IdempotencyConflictError(
                                "Idempotency-Key was already used for a different settlement rejection."
                            )
                        prior_vals = prior_key_log["new_values"]
                        if isinstance(prior_vals, str):
                            prior_vals = json.loads(prior_vals)
                        if (prior_vals or {}).get("rejection_reason") != reason_clean:
                            raise IdempotencyConflictError(
                                "Idempotency-Key was already used with a different rejection reason."
                            )
                        return {**dict(row), "idempotent_replay": True}

                current_status = row["status"]
                if current_status not in ("PENDING", "PROCESSING", "APPROVED"):
                    raise InvalidSettlementTransitionError(
                        f"Cannot reject settlement in terminal status '{current_status}'."
                    )

                await self.refund_locked_settlement(
                    user_id=row["user_id"],
                    amount_toman=int(row["amount_toman"]),
                    settlement_id=settlement_id,
                    idempotency_key=f"SETTLE-REFUND-{settlement_id}",
                    reason=reason_clean,
                    conn=conn,
                    created_by=actor_user_id,
                )

                updated = await conn.fetchrow(
                    """
                    UPDATE settlements
                    SET status = 'REJECTED',
                        rejection_reason = $1,
                        updated_at = NOW()
                    WHERE id = $2 AND status IN ('PENDING', 'PROCESSING', 'APPROVED')
                    RETURNING *
                    """,
                    reason_clean,
                    settlement_id,
                )
                if not updated:
                    raise InvalidSettlementTransitionError(
                        "Settlement state changed concurrently; rejection aborted."
                    )

                actor_role = _resolve_actor_role_label(actor_roles)
                await conn.execute(
                    """
                    INSERT INTO audit_logs (
                        actor_user_id, actor_role, action, entity_name, entity_id,
                        old_values, new_values
                    ) VALUES (
                        $1, $2, 'SETTLEMENT_REJECTED', 'settlements', $3::varchar,
                        $4::jsonb, $5::jsonb
                    )
                    """,
                    actor_user_id,
                    actor_role,
                    str(settlement_id),
                    json.dumps({"status": current_status}),
                    json.dumps(
                        {
                            "status": "REJECTED",
                            "amount_toman": int(updated["amount_toman"]),
                            "rejection_reason": reason_clean,
                            "bank_card_masked": mask_card_number(updated["bank_card_number"]),
                            "bank_sheba_masked": mask_shaba(updated["bank_sheba_number"]),
                            "client_idempotency_key": scoped_idem_key,
                        },
                        ensure_ascii=False,
                    ),
                )

                return {**dict(updated), "idempotent_replay": False}

    async def mark_settlement_paid(
        self,
        settlement_id: uuid.UUID,
        actor_user_id: uuid.UUID,
        external_payment_ref: str,
        external_payment_date: datetime,
        amount_toman: int | None = None,
        notes: str | None = None,
        idempotency_key: str | None = None,
        verifier: BasePayoutProofVerifier | None = None,
    ) -> Dict[str, Any]:
        """
        Transitions `APPROVED -> PAID` (`SETTLE-007..011`, `OPEN-04`, `T27-AC1..AC4`).
        - Enforces authoritative `settlements:pay` permission AND `OPEN_04["mark_settlement_paid"]`
          (rejects regular users, SUPPORT, DOCTOR, AGENT, and standard ADMIN -> 403).
        - Enforces approved `OPEN_04`, `OPEN_06`, `OPEN_18` (`403` if PROPOSED/BLOCKED).
        - Verifies documented off-system bank transfer evidence via `BasePayoutProofVerifier`
          (rejects unverified/self-asserted refs, mismatched amount/Sheba/settlement_id).
        - Enforces unique `external_payment_ref` across settlements (`409` on duplicate).
        - Atomically debits `locked_balance_toman` ONCE inside the same transaction.
        """
        ref_clean = (external_payment_ref or "").strip()
        if len(ref_clean) < 6:
            raise WalletError(
                "external_payment_ref must be at least 6 non-whitespace characters."
            )
        if external_payment_date is None:
            raise WalletError("external_payment_date is required.")
        pay_date_utc = _normalize_utc(external_payment_date)
        if pay_date_utc > datetime.now(UTC) + timedelta(minutes=5):
            raise WalletError("external_payment_date cannot be in the future.")

        clean_idem = _normalize_idempotency_header(idempotency_key)
        scoped_idem_key = (
            _scope_actor_idem_key(actor_user_id, "SETTLE-PAY-REQ", clean_idem)
            if clean_idem is not None
            else None
        )
        notes_clean = notes.strip() if notes and notes.strip() else None

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                try:
                    actor_roles = await self.rbac.get_user_roles(conn, actor_user_id)
                    actor_perms = await self.rbac.get_user_permissions(conn, actor_user_id)
                except RbacAccessDeniedError as exc:
                    raise SettlementAuthorizationError(str(exc)) from exc

                if "SUPER_ADMIN" not in actor_roles and "settlements:pay" not in actor_perms:
                    raise SettlementAuthorizationError(
                        "Permission denied: 'settlements:pay' permission required."
                    )

                open04 = await require_approved_policy(conn, "OPEN_04_FINANCIAL_PERMISSIONS_MATRIX")
                await require_approved_policy(conn, "OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN")
                await require_approved_policy(conn, "OPEN_18_CURRENCY_AND_ROUNDING")

                allowed_pay_roles = (
                    set(open04.get("mark_settlement_paid", ["SUPER_ADMIN"]))
                    & {"ADMIN", "SUPER_ADMIN"}
                )
                if not (actor_roles & allowed_pay_roles):
                    raise SettlementAuthorizationError(
                        "Forbidden: Actor role is not authorized by OPEN-04 'mark_settlement_paid' policy."
                    )

                # Deadlock-free ordered advisory locks -> settlements FOR UPDATE -> wallets FOR UPDATE
                lock_keys = [f"settle_payout_ref:{ref_clean}"]
                if scoped_idem_key is not None:
                    lock_keys.append(scoped_idem_key)
                for lk in sorted(lock_keys):
                    await conn.execute(
                        "SELECT pg_advisory_xact_lock(hashtext($1));",
                        lk,
                    )

                row = await conn.fetchrow(
                    """
                    SELECT * FROM settlements
                    WHERE id = $1 AND deleted_at IS NULL
                    FOR UPDATE
                    """,
                    settlement_id,
                )
                if not row:
                    raise SettlementNotFoundError(f"Settlement {settlement_id} not found.")

                if scoped_idem_key is not None:
                    prior_key_log = await conn.fetchrow(
                        """
                        SELECT entity_id, new_values
                        FROM audit_logs
                        WHERE action = 'SETTLEMENT_MARKED_PAID'
                          AND new_values->>'client_idempotency_key' = $1
                        LIMIT 1
                        """,
                        scoped_idem_key,
                    )
                    if prior_key_log is not None:
                        if prior_key_log["entity_id"] != str(settlement_id):
                            raise IdempotencyConflictError(
                                "Idempotency-Key was already used for a different settlement payout."
                            )
                        prior_vals = prior_key_log["new_values"]
                        if isinstance(prior_vals, str):
                            prior_vals = json.loads(prior_vals)
                        same_payload = (
                            (prior_vals or {}).get("external_payment_ref") == ref_clean
                            and (prior_vals or {}).get("external_payment_date") == pay_date_utc.isoformat()
                            and (amount_toman is None or int(amount_toman) == int(row["amount_toman"]))
                        )
                        if not same_payload:
                            raise IdempotencyConflictError(
                                "Idempotency-Key was already used with different payout evidence."
                            )
                        return {**dict(row), "idempotent_replay": True}

                current_status = row["status"]
                if current_status == "PAID":
                    raise InvalidSettlementTransitionError(
                        "Settlement has already been marked PAID."
                    )
                if current_status != "APPROVED":
                    raise InvalidSettlementTransitionError(
                        f"Cannot mark settlement as PAID from status '{current_status}'; must be 'APPROVED' first."
                    )

                expected_amount = int(row["amount_toman"])
                if amount_toman is not None and int(amount_toman) != expected_amount:
                    raise PayoutVerificationError(
                        f"Provided amount ({amount_toman}) does not match settlement amount ({expected_amount})."
                    )

                created_at_utc = _normalize_utc(row["created_at"])
                if pay_date_utc < created_at_utc - timedelta(seconds=5):
                    raise PayoutVerificationError(
                        "external_payment_date cannot predate the settlement request creation timestamp."
                    )

                dup_ref = await conn.fetchrow(
                    """
                    SELECT id FROM settlements
                    WHERE external_payment_ref = $1 AND id <> $2
                    LIMIT 1
                    """,
                    ref_clean,
                    settlement_id,
                )
                if dup_ref:
                    raise DuplicatePayoutReferenceError(
                        "external_payment_ref has already been used for another settlement."
                    )

                active_verifier = verifier or get_runtime_payout_verifier()
                verification = await active_verifier.verify_payout_proof(
                    settlement_id=settlement_id,
                    external_payment_ref=ref_clean,
                    amount_toman=expected_amount,
                    destination_sheba=row["bank_sheba_number"],
                    payment_date=pay_date_utc,
                )
                if not verification.verified:
                    raise PayoutVerificationError(
                        verification.error_message
                        or "External bank payout evidence failed verification."
                    )

                await self.finalize_settlement_payout(
                    user_id=row["user_id"],
                    amount_toman=expected_amount,
                    settlement_id=settlement_id,
                    idempotency_key=f"SETTLE-PAY-{settlement_id}",
                    paid_by=actor_user_id,
                    conn=conn,
                )

                updated = await conn.fetchrow(
                    """
                    UPDATE settlements
                    SET status = 'PAID',
                        external_payment_ref = $1,
                        external_payment_date = $2,
                        paid_by = $3,
                        updated_at = NOW()
                    WHERE id = $4 AND status = 'APPROVED'
                    RETURNING *
                    """,
                    ref_clean,
                    pay_date_utc,
                    actor_user_id,
                    settlement_id,
                )
                if not updated:
                    raise InvalidSettlementTransitionError(
                        "Settlement state changed concurrently; mark-paid aborted."
                    )

                actor_role = _resolve_actor_role_label(actor_roles)
                await conn.execute(
                    """
                    INSERT INTO audit_logs (
                        actor_user_id, actor_role, action, entity_name, entity_id,
                        old_values, new_values
                    ) VALUES (
                        $1, $2, 'SETTLEMENT_MARKED_PAID', 'settlements', $3::varchar,
                        $4::jsonb, $5::jsonb
                    )
                    """,
                    actor_user_id,
                    actor_role,
                    str(settlement_id),
                    json.dumps({"status": current_status}),
                    json.dumps(
                        {
                            "status": "PAID",
                            "amount_toman": expected_amount,
                            "external_payment_ref": ref_clean,
                            "external_payment_date": pay_date_utc.isoformat(),
                            "evidence_source": verification.evidence_source,
                            "bank_card_masked": mask_card_number(updated["bank_card_number"]),
                            "bank_sheba_masked": mask_shaba(updated["bank_sheba_number"]),
                            "notes": notes_clean,
                            "client_idempotency_key": scoped_idem_key,
                        },
                        ensure_ascii=False,
                    ),
                )

                return {**dict(updated), "idempotent_replay": False}

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
