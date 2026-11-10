"""
Unit Tests for External Adapters (SMS & Payment Gateways)
BASELINE: BL-HAMICARD-PRD-V1 | Section 28 (OPEN_11_EXTERNAL_ADAPTERS_CONFIG)
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from src.adapters.payment import (
    BasePaymentGateway,
    MockPaymentGateway,
    PaymentGatewayError,
    ZarinpalGateway,
    get_payment_gateway,
)
from src.adapters.sms import (
    BaseSmsAdapter,
    GhasedakSmsAdapter,
    KavenegarSmsAdapter,
    MockSmsAdapter,
    SmsAdapterError,
    get_sms_adapter,
)


@pytest.mark.asyncio
async def test_mock_sms_adapter():
    adapter = MockSmsAdapter()
    assert isinstance(adapter, BaseSmsAdapter)

    # Send OTP
    success = await adapter.send_otp("09121112233", "123456")
    assert success is True
    assert len(adapter.sent_messages) == 1
    assert adapter.sent_messages[0]["code"] == "123456"
    assert adapter.sent_messages[0]["mobile"] == "09121112233"

    # Send notification
    success_notif = await adapter.send_notification("09121112233", "خوش آمدید")
    assert success_notif is True
    assert len(adapter.sent_messages) == 2
    assert adapter.sent_messages[1]["type"] == "NOTIFICATION"


def test_sms_factory():
    assert isinstance(get_sms_adapter("mock"), MockSmsAdapter)
    assert isinstance(get_sms_adapter("kavenegar"), KavenegarSmsAdapter)
    assert isinstance(get_sms_adapter("ghasedak"), GhasedakSmsAdapter)
    assert isinstance(get_sms_adapter("unknown"), MockSmsAdapter)


@pytest.mark.asyncio
async def test_live_sms_adapters_guard_missing_keys():
    kav = KavenegarSmsAdapter(api_key="")
    with pytest.raises(SmsAdapterError, match="KAVENEGAR_API_KEY is not configured"):
        await kav.send_otp("09120000000", "999999")

    ghas = GhasedakSmsAdapter(api_key="")
    with pytest.raises(SmsAdapterError, match="GHASEDAK_API_KEY is not configured"):
        await ghas.send_otp("09120000000", "999999")


@pytest.mark.asyncio
async def test_mock_payment_gateway():
    gateway = MockPaymentGateway()
    assert isinstance(gateway, BasePaymentGateway)

    # Request payment
    req = await gateway.request_payment(
        amount_toman=500000,
        callback_url="https://hamicard.ir/verify",
        description="خرید طرح سلامت طلایی",
        mobile="09121112233",
    )
    assert req.gateway_name == "MOCK"
    assert "Authority=" in req.payment_url
    assert req.authority.startswith("MOCK-AUTH-")

    # Verify payment - Success
    ver_success = await gateway.verify_payment(req.authority, amount_toman=500000)
    assert ver_success.success is True
    assert ver_success.amount_toman == 500000
    assert ver_success.ref_id.startswith("REF-")
    assert ver_success.card_pan == "603799******1234"

    # Verify payment - Amount mismatch
    ver_fail = await gateway.verify_payment(req.authority, amount_toman=400000)
    assert ver_fail.success is False
    assert "mismatch" in ver_fail.error_message


def test_payment_factory():
    assert isinstance(get_payment_gateway("mock"), MockPaymentGateway)
    assert isinstance(get_payment_gateway("zarinpal"), ZarinpalGateway)
    assert isinstance(get_payment_gateway("unknown"), MockPaymentGateway)


@pytest.mark.asyncio
async def test_zarinpal_gateway_guards_missing_merchant():
    zp = ZarinpalGateway(merchant_id="")
    with pytest.raises(PaymentGatewayError, match="ZARINPAL_MERCHANT_ID is not configured"):
        await zp.request_payment(100000, "https://callback", "Test")


if __name__ == "__main__":
    import asyncio
    asyncio.run(test_mock_sms_adapter())
    test_sms_factory()
    asyncio.run(test_live_sms_adapters_guard_missing_keys())
    asyncio.run(test_mock_payment_gateway())
    test_payment_factory()
    asyncio.run(test_zarinpal_gateway_guards_missing_merchant())
    print("All external adapter tests passed successfully!")
