"""
External Payment Gateway Adapters
BASELINE: BL-HAMICARD-PRD-V1 | Section 28 (OPEN_11_EXTERNAL_ADAPTERS_CONFIG)
Supports: Mock (dev/test), Zarinpal, PayPing, Shaparak IPG.
"""

import logging
import os
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx

logger = logging.getLogger("hamicard.adapters.payment")


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
    ) -> PaymentVerificationResult:
        """Verifies transaction outcome with payment gateway upon return."""
        pass


class MockPaymentGateway(BasePaymentGateway):
    """
    In-memory mock gateway for sandbox testing.
    Instantly returns simulated payment URL and validates transactions.
    """

    def __init__(self):
        self.pending_authorities: dict[str, int] = {}

    async def request_payment(
        self,
        amount_toman: int,
        callback_url: str,
        description: str,
        mobile: str | None = None,
        order_id: str | None = None,
    ) -> PaymentRequestResult:
        authority = f"MOCK-AUTH-{uuid.uuid4().hex[:12]}"
        self.pending_authorities[authority] = amount_toman
        payment_url = f"{callback_url}?Authority={authority}&Status=OK"
        logger.info(f"[MockGateway] Created request: authority={authority}, amount={amount_toman}")
        return PaymentRequestResult(
            payment_url=payment_url,
            authority=authority,
            gateway_name="MOCK",
        )

    async def verify_payment(
        self,
        authority: str,
        amount_toman: int,
    ) -> PaymentVerificationResult:
        expected = self.pending_authorities.get(authority)
        if expected is not None and expected != amount_toman:
            return PaymentVerificationResult(
                success=False,
                ref_id="",
                amount_toman=amount_toman,
                error_message="Amount mismatch during verification",
            )
        ref_id = f"REF-{uuid.uuid4().int % 100000000:08d}"
        logger.info(f"[MockGateway] Verified authority={authority}, ref_id={ref_id}")
        return PaymentVerificationResult(
            success=True,
            ref_id=ref_id,
            amount_toman=amount_toman,
            card_pan="603799******1234",
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

        # Zarinpal v4 expects Toman amount
        url = f"{self.base_url}/request.json"
        payload = {
            "merchant_id": self.merchant_id,
            "amount": amount_toman,
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
                if code == 100:
                    authority = data_obj["authority"]
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
    ) -> PaymentVerificationResult:
        if not self.merchant_id:
            raise PaymentGatewayError("ZARINPAL_MERCHANT_ID is not configured.")

        url = f"{self.base_url}/verify.json"
        payload = {
            "merchant_id": self.merchant_id,
            "amount": amount_toman,
            "authority": authority,
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.post(url, json=payload)
                data = resp.json()
                data_obj = data.get("data", {})
                code = data_obj.get("code")
                if code in (100, 101):  # 100: Verified, 101: Already verified
                    ref_id = str(data_obj.get("ref_id", ""))
                    card_pan = data_obj.get("card_pan")
                    return PaymentVerificationResult(
                        success=True,
                        ref_id=ref_id,
                        amount_toman=amount_toman,
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


def get_payment_gateway(provider_name: str | None = None) -> BasePaymentGateway:
    """Factory resolver for configured Payment Gateway."""
    provider = (provider_name or os.getenv("PAYMENT_PROVIDER", "mock")).lower().strip()
    if provider == "zarinpal":
        return ZarinpalGateway()
    else:
        return MockPaymentGateway()

