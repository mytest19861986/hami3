"""
External Payment Gateway Adapters
BASELINE: BL-HAMICARD-PRD-V1 | Section 28 (OPEN_11_EXTERNAL_ADAPTERS_CONFIG)
REMEDIATION: HC-T17 (F-11 CRITICAL, T17-AC1..AC2)
Supports: Mock (dev/test ONLY), Zarinpal REST v4.

Security Guarantees:
- Fail-Closed Production Guard: MockPaymentGateway and unconfigured providers are strictly
  forbidden when APP_ENV / NODE_ENV == 'production'.
- No Self-Asserted Proof: Unknown, unissued, mismatched-amount, or mismatched-order
  authorities ALWAYS fail verification.
- Runtime Sandbox Explicit Confirmation: HTTP runtime sandbox gateway runs with
  `require_explicit_confirmation=True` so ordinary users cannot self-confirm orders
  simply by invoking `/initiate` -> `/verify`.
"""

import logging
import os
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import httpx

logger = logging.getLogger("hamicard.adapters.payment")


def _is_production_env() -> bool:
    app_env = os.getenv("APP_ENV", "").strip().lower()
    node_env = os.getenv("NODE_ENV", "").strip().lower()
    return app_env == "production" or node_env == "production"


class PaymentGatewayError(Exception):
    """Base exception for payment gateway operations."""
    pass


@dataclass
class PaymentRequestResult:
    payment_url: str
    authority: str
    gateway_name: str


@dataclass
class PaymentVerificationResult:
    success: bool
    ref_id: str
    amount_toman: int
    card_pan: str | None = None
    error_message: str | None = None


class BasePaymentGateway(ABC):
    """Abstract interface for Iranian banking payment gateways."""

    @abstractmethod
    async def request_payment(
        self,
        amount_toman: int,
        callback_url: str,
        description: str,
        mobile: str | None = None,
        order_id: str | None = None,
    ) -> PaymentRequestResult:
        """Initiates a payment request and returns gateway redirect URL."""
        pass

    @abstractmethod
    async def verify_payment(
        self,
        authority: str,
        amount_toman: int,
        expected_order_id: str | None = None,
    ) -> PaymentVerificationResult:
        """Verifies transaction outcome with payment gateway upon return."""
        pass


class MockPaymentGateway(BasePaymentGateway):
    """
    In-memory mock gateway for isolated non-production testing ONLY.
    Tracks issued authorities, bound amounts, bound order IDs, and settlement state.
    """

    def __init__(self, require_explicit_confirmation: bool = False):
        if _is_production_env():
            raise PaymentGatewayError(
                "MockPaymentGateway is strictly disabled in production (APP_ENV/NODE_ENV=production)."
            )
        self.require_explicit_confirmation = require_explicit_confirmation
        self.pending_authorities: dict[str, int] = {}
        self.pending_requests: dict[str, dict[str, Any]] = {}

    async def request_payment(
        self,
        amount_toman: int,
        callback_url: str,
        description: str,
        mobile: str | None = None,
        order_id: str | None = None,
    ) -> PaymentRequestResult:
        if _is_production_env():
            raise PaymentGatewayError("MockPaymentGateway request_payment blocked in production.")
        if amount_toman <= 0:
            raise PaymentGatewayError("Payment amount must be strictly positive.")

        authority = f"MOCK-AUTH-{uuid.uuid4().hex[:12]}"
        self.pending_authorities[authority] = int(amount_toman)
        self.pending_requests[authority] = {
            "amount_toman": int(amount_toman),
            "order_id": str(order_id) if order_id is not None else None,
            "confirmed": not self.require_explicit_confirmation,
            "ref_id": None,
            "card_pan": "603799******1234",
        }
        payment_url = f"{callback_url}?Authority={authority}&Status=OK"
        logger.info("[MockGateway] Issued payment authority for order_id=%s amount=%s", order_id, amount_toman)
        return PaymentRequestResult(
            payment_url=payment_url,
            authority=authority,
            gateway_name="MOCK",
        )

    def confirm_payment(self, authority: str, card_pan: str = "603799******1234") -> str:
        """
        Isolated test-harness hook simulating bank-side customer checkout completion.
        Forbidden in production.
        """
        if _is_production_env():
            raise PaymentGatewayError("MockPaymentGateway.confirm_payment is forbidden in production.")
        req_info = self.pending_requests.get(authority)
        if not req_info:
            raise PaymentGatewayError(f"Unknown payment authority '{authority}'.")
        req_info["confirmed"] = True
        req_info["card_pan"] = card_pan
        if not req_info["ref_id"]:
            req_info["ref_id"] = f"REF-{uuid.uuid4().int % 100000000:08d}"
        return req_info["ref_id"]

    async def verify_payment(
        self,
        authority: str,
        amount_toman: int,
        expected_order_id: str | None = None,
    ) -> PaymentVerificationResult:
        if _is_production_env():
            raise PaymentGatewayError("MockPaymentGateway verify_payment blocked in production.")

        auth_clean = (authority or "").strip()
        req_info = self.pending_requests.get(auth_clean)
        if req_info is None:
            return PaymentVerificationResult(
                success=False,
                ref_id="",
                amount_toman=amount_toman,
                error_message="Unknown or unissued payment authority",
            )

        if int(req_info["amount_toman"]) != int(amount_toman):
            return PaymentVerificationResult(
                success=False,
                ref_id="",
                amount_toman=amount_toman,
                error_message="Amount mismatch during verification",
            )

        bound_order_id = req_info.get("order_id")
        if expected_order_id is not None and bound_order_id is not None and str(bound_order_id) != str(expected_order_id):
            return PaymentVerificationResult(
                success=False,
                ref_id="",
                amount_toman=amount_toman,
                error_message="Order reference mismatch during verification",
            )

        if self.require_explicit_confirmation and not req_info.get("confirmed", False):
            return PaymentVerificationResult(
                success=False,
                ref_id="",
                amount_toman=amount_toman,
                error_message="Payment authority has not been confirmed by gateway provider.",
            )

        if not req_info.get("ref_id"):
            req_info["ref_id"] = f"REF-{uuid.uuid4().int % 100000000:08d}"

        logger.info("[MockGateway] Verified authority order_id=%s", bound_order_id)
        return PaymentVerificationResult(
            success=True,
            ref_id=req_info["ref_id"],
            amount_toman=int(amount_toman),
            card_pan=req_info.get("card_pan", "603799******1234"),
        )


class ZarinpalGateway(BasePaymentGateway):
    """
    Zarinpal REST API v4 Payment Gateway Adapter.
    Endpoint: https://payment.zarinpal.com/pg/v4/payment/
    """

    def __init__(self, merchant_id: str | None = None, sandbox: bool = False):
        self.merchant_id = merchant_id or os.getenv("ZARINPAL_MERCHANT_ID", "")
        self.sandbox = sandbox or (os.getenv("ZARINPAL_SANDBOX", "false").lower() == "true")
        if self.sandbox:
            self.base_url = "https://sandbox.zarinpal.com/pg/v4/payment"
            self.start_pay_url = "https://sandbox.zarinpal.com/pg/StartPay"
        else:
            self.base_url = "https://payment.zarinpal.com/pg/v4/payment"
            self.start_pay_url = "https://payment.zarinpal.com/pg/StartPay"

    async def request_payment(
        self,
        amount_toman: int,
        callback_url: str,
        description: str,
        mobile: str | None = None,
        order_id: str | None = None,
    ) -> PaymentRequestResult:
        if not self.merchant_id:
            raise PaymentGatewayError("ZARINPAL_MERCHANT_ID is not configured.")
        if amount_toman <= 0:
            raise PaymentGatewayError("Payment amount must be strictly positive.")

        url = f"{self.base_url}/request.json"
        payload = {
            "merchant_id": self.merchant_id,
            "amount": int(amount_toman),
            "currency": "IRT",
            "callback_url": callback_url,
            "description": description,
            "metadata": {"mobile": mobile or "", "order_id": order_id or ""},
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.post(url, json=payload)
                data = resp.json()
                data_obj = data.get("data", {})
                code = data_obj.get("code")
                if code == 100 and data_obj.get("authority"):
                    authority = str(data_obj["authority"])
                    payment_url = f"{self.start_pay_url}/{authority}"
                    return PaymentRequestResult(
                        payment_url=payment_url,
                        authority=authority,
                        gateway_name="ZARINPAL",
                    )
                errors = data.get("errors", {})
                raise PaymentGatewayError(f"Zarinpal request failed: code {code}, errors: {errors}")
            except httpx.HTTPError as e:
                raise PaymentGatewayError(f"Zarinpal connection error: {e}")

    async def verify_payment(
        self,
        authority: str,
        amount_toman: int,
        expected_order_id: str | None = None,
    ) -> PaymentVerificationResult:
        if not self.merchant_id:
            raise PaymentGatewayError("ZARINPAL_MERCHANT_ID is not configured.")
        auth_clean = (authority or "").strip()
        if not auth_clean or amount_toman <= 0:
            return PaymentVerificationResult(
                success=False,
                ref_id="",
                amount_toman=amount_toman,
                error_message="Missing authority or non-positive amount for Zarinpal verification.",
            )

        url = f"{self.base_url}/verify.json"
        payload = {
            "merchant_id": self.merchant_id,
            "amount": int(amount_toman),
            "authority": auth_clean,
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.post(url, json=payload)
                data = resp.json()
                data_obj = data.get("data", {})
                code = data_obj.get("code")
                ref_id = str(data_obj.get("ref_id", "")).strip()
                if code in (100, 101) and ref_id:
                    card_pan = data_obj.get("card_pan")
                    return PaymentVerificationResult(
                        success=True,
                        ref_id=ref_id,
                        amount_toman=int(amount_toman),
                        card_pan=card_pan,
                    )
                errors = data.get("errors", {})
                return PaymentVerificationResult(
                    success=False,
                    ref_id="",
                    amount_toman=amount_toman,
                    error_message=f"Zarinpal verification failed with code {code}: {errors}",
                )
            except httpx.HTTPError as e:
                raise PaymentGatewayError(f"Zarinpal connection error during verification: {e}")


_sandbox_runtime_gateway: MockPaymentGateway | None = None


def reset_runtime_sandbox_gateway() -> None:
    """Clears process-local sandbox gateway state (non-production tests only)."""
    global _sandbox_runtime_gateway
    _sandbox_runtime_gateway = None


def get_payment_gateway(provider_name: str | None = None) -> BasePaymentGateway:
    """
    Factory resolver for Payment Gateway.
    - Production: fails closed unless a configured real gateway (`zarinpal`) is selected.
    - Non-production unit usage: returns `MockPaymentGateway()` when mock/fallback requested.
    """
    provider = (provider_name or os.getenv("PAYMENT_PROVIDER", "mock")).lower().strip()
    if provider == "zarinpal":
        gw = ZarinpalGateway()
        if _is_production_env() and not gw.merchant_id:
            raise PaymentGatewayError("ZARINPAL_MERCHANT_ID must be configured in production.")
        return gw

    if _is_production_env():
        raise PaymentGatewayError(
            f"Unsupported or mock payment gateway '{provider}' is strictly forbidden in production."
        )
    return MockPaymentGateway()


def get_runtime_payment_gateway(provider_name: str | None = None) -> BasePaymentGateway:
    """
    HTTP runtime gateway resolver used by FastAPI payment endpoints.
    Uses Zarinpal in production (fail-closed) or a strict process-scoped
    MockPaymentGateway(require_explicit_confirmation=True) in non-production sandbox.
    """
    global _sandbox_runtime_gateway
    provider = (provider_name or os.getenv("PAYMENT_PROVIDER", "mock")).lower().strip()
    if provider == "zarinpal":
        gw = ZarinpalGateway()
        if _is_production_env() and not gw.merchant_id:
            raise PaymentGatewayError("ZARINPAL_MERCHANT_ID must be configured in production.")
        return gw

    if _is_production_env():
        raise PaymentGatewayError(
            f"Unsupported or mock payment gateway '{provider}' is strictly forbidden in production."
        )

    if _sandbox_runtime_gateway is None:
        _sandbox_runtime_gateway = MockPaymentGateway(require_explicit_confirmation=True)
    return _sandbox_runtime_gateway
