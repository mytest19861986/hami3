"""
External SMS Gateway Adapters
BASELINE: BL-HAMICARD-PRD-V1 | Section 28 (OPEN_11_EXTERNAL_ADAPTERS_CONFIG)
Supports: Mock (dev/test), Kavenegar, Ghasedak, FarazSMS (IPPanel).
"""

import logging
import os
from abc import ABC, abstractmethod
from typing import Any, Dict

import httpx

logger = logging.getLogger("hamicard.adapters.sms")


class SmsAdapterError(Exception):
    """Base exception for SMS gateway errors."""
    pass


class BaseSmsAdapter(ABC):
    """Abstract interface for all SMS provider adapters."""

    @abstractmethod
    async def send_otp(self, mobile: str, code: str, template: str | None = None) -> bool:
        """Sends OTP verification code to recipient mobile."""
        pass

    @abstractmethod
    async def send_notification(self, mobile: str, message: str) -> bool:
        """Sends arbitrary plain text notification SMS."""
        pass


class MockSmsAdapter(BaseSmsAdapter):
    """
    In-memory / log mock adapter for development and testing.
    Never sends real network requests.
    """

    def __init__(self):
        self.sent_messages: list[Dict[str, Any]] = []

    async def send_otp(self, mobile: str, code: str, template: str | None = None) -> bool:
        env = (os.getenv("APP_ENV") or os.getenv("NODE_ENV") or "development").lower().strip()
        if env == "production":
            raise SmsAdapterError("Fail-Closed: MockSmsAdapter cannot be used in production.")
        record = {
            "type": "OTP",
            "mobile": mobile,
            "code": code,
            "template": template or "otp-verify",
        }
        self.sent_messages.append(record)
        logger.info("[MockSMS] Dispatched OTP message to %s", mobile)
        return True

    async def send_notification(self, mobile: str, message: str) -> bool:
        record = {
            "type": "NOTIFICATION",
            "mobile": mobile,
            "message": message,
        }
        self.sent_messages.append(record)
        logger.info(f"[MockSMS] Sent notification to {mobile}: {message}")
        return True


class KavenegarSmsAdapter(BaseSmsAdapter):
    """Kavenegar REST API Adapter."""

    def __init__(self, api_key: str | None = None, sender_number: str | None = None):
        self.api_key = api_key or os.getenv("KAVENEGAR_API_KEY", "")
        self.sender = sender_number or os.getenv("KAVENEGAR_SENDER", "10008000")
        self.base_url = f"https://api.kavenegar.com/v1/{self.api_key}"

    async def send_otp(self, mobile: str, code: str, template: str | None = "hamicard-otp") -> bool:
        if not self.api_key:
            raise SmsAdapterError("KAVENEGAR_API_KEY is not configured.")

        url = f"{self.base_url}/verify/lookup.json"
        params = {
            "receptor": mobile,
            "token": code,
            "template": template,
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.get(url, params=params)
                data = resp.json()
                if resp.status_code == 200 and data.get("return", {}).get("status") == 200:
                    return True
                raise SmsAdapterError(f"Kavenegar OTP failed: {data.get('return', {}).get('message')}")
            except httpx.HTTPError as e:
                raise SmsAdapterError(f"Kavenegar connection error: {e}")

    async def send_notification(self, mobile: str, message: str) -> bool:
        if not self.api_key:
            raise SmsAdapterError("KAVENEGAR_API_KEY is not configured.")

        url = f"{self.base_url}/sms/send.json"
        data = {
            "receptor": mobile,
            "sender": self.sender,
            "message": message,
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.post(url, data=data)
                res_data = resp.json()
                if resp.status_code == 200 and res_data.get("return", {}).get("status") == 200:
                    return True
                raise SmsAdapterError(f"Kavenegar notification failed: {res_data.get('return', {}).get('message')}")
            except httpx.HTTPError as e:
                raise SmsAdapterError(f"Kavenegar connection error: {e}")


class GhasedakSmsAdapter(BaseSmsAdapter):
    """Ghasedak REST API Adapter."""

    def __init__(self, api_key: str | None = None, sender_number: str | None = None):
        self.api_key = api_key or os.getenv("GHASEDAK_API_KEY", "")
        self.sender = sender_number or os.getenv("GHASEDAK_SENDER", "30005088")
        self.base_url = "https://api.ghasedak.me/v2"

    async def send_otp(self, mobile: str, code: str, template: str | None = "hamicard-otp") -> bool:
        if not self.api_key:
            raise SmsAdapterError("GHASEDAK_API_KEY is not configured.")

        url = f"{self.base_url}/verification/send/simple"
        headers = {"apikey": self.api_key}
        payload = {
            "receptor": mobile,
            "type": "1",
            "template": template,
            "param1": code,
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.post(url, headers=headers, json=payload)
                data = resp.json()
                if resp.status_code == 200 and data.get("result", {}).get("code") == 200:
                    return True
                raise SmsAdapterError(f"Ghasedak OTP failed: {data.get('result', {}).get('message')}")
            except httpx.HTTPError as e:
                raise SmsAdapterError(f"Ghasedak connection error: {e}")

    async def send_notification(self, mobile: str, message: str) -> bool:
        if not self.api_key:
            raise SmsAdapterError("GHASEDAK_API_KEY is not configured.")

        url = f"{self.base_url}/sms/send/simple"
        headers = {"apikey": self.api_key}
        payload = {
            "receptor": mobile,
            "linenumber": self.sender,
            "message": message,
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.post(url, headers=headers, json=payload)
                data = resp.json()
                if resp.status_code == 200 and data.get("result", {}).get("code") == 200:
                    return True
                raise SmsAdapterError(f"Ghasedak notification failed: {data.get('result', {}).get('message')}")
            except httpx.HTTPError as e:
                raise SmsAdapterError(f"Ghasedak connection error: {e}")


def get_sms_adapter(provider_name: str | None = None) -> BaseSmsAdapter:
    """Factory resolver for configured SMS provider (fail-closed in production)."""
    provider = (provider_name or os.getenv("SMS_PROVIDER", "mock")).lower().strip()
    env = (os.getenv("APP_ENV") or os.getenv("NODE_ENV") or "development").lower().strip()
    if provider == "kavenegar":
        return KavenegarSmsAdapter()
    elif provider == "ghasedak":
        return GhasedakSmsAdapter()
    elif env == "production":
        raise SmsAdapterError(
            f"Fail-Closed: Unconfigured or mock SMS provider '{provider}' prohibited in production."
        )
    else:
        return MockSmsAdapter()

