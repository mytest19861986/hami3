"""
OTP Service with Redis Rate Limiting & Fail-Closed Delivery
BASELINE: BL-HAMICARD-PRD-V1 | AUTH-001, AUTH-002, AC-01, AC-02, OPEN-14

Guarantees:
- Mobile normalization (09XXXXXXXXX)
- 120s TTL for OTP codes
- Max 3 incorrect verification attempts
- Max 5 OTP requests per hour (OPEN-14 / SLA)
- Fail-closed SMS delivery simulation
- Zero plaintext OTP or credentials in logs
"""

import re
from typing import Tuple

import redis

from src.core.security import generate_otp_code


class OtpError(Exception):
    pass

class OtpRateLimitError(OtpError):
    pass

class OtpMaxAttemptsExceededError(OtpError):
    pass

class OtpExpiredOrInvalidError(OtpError):
    pass

class SmsDeliveryError(OtpError):
    pass

def normalize_iranian_mobile(mobile: str) -> str:
    """Normalizes mobile to standard Iranian format: 09XXXXXXXXX."""
    if not mobile:
        raise ValueError("Mobile number cannot be empty")
    clean = re.sub(r"\D", "", str(mobile))
    if clean.startswith("989") and len(clean) == 12:
        clean = "0" + clean[2:]
    elif clean.startswith("9") and len(clean) == 10:
        clean = "0" + clean
    if len(clean) != 11 or not clean.startswith("09"):
        raise ValueError(f"Invalid Iranian mobile number format: '{mobile}'")
    return clean

class OtpService:
    def __init__(self, redis_client: redis.Redis, sms_provider_healthy: bool = True):
        self.r = redis_client
        self.sms_healthy = sms_provider_healthy

    def request_otp(self, raw_mobile: str) -> Tuple[bool, int]:
        """
        Generates and dispatches OTP code.
        Returns: (success: bool, ttl_seconds: int)
        Raises OtpRateLimitError or SmsDeliveryError.
        """
        mobile = normalize_iranian_mobile(raw_mobile)

        # Check blocklist
        block_key = f"otp:block:{mobile}"
        if self.r.exists(block_key):
            ttl = self.r.ttl(block_key)
            raise OtpRateLimitError(f"Account temporarily blocked due to repeated failures. Try again in {ttl}s.")

        # Check active OTP (1 request per 120s)
        code_key = f"otp:code:{mobile}"
        if self.r.exists(code_key):
            ttl = self.r.ttl(code_key)
            raise OtpRateLimitError(f"Please wait {ttl} seconds before requesting a new OTP.")

        # Check hourly rate limit (max 5/hour)
        hourly_key = f"otp:hourly:{mobile}"
        current_hourly = self.r.incr(hourly_key)
        if current_hourly == 1:
            self.r.expire(hourly_key, 3600)
        elif current_hourly > 5:
            raise OtpRateLimitError("Hourly OTP limit exceeded (max 5 requests per hour).")

        # Generate secure 6-digit code
        code = generate_otp_code(6)

        # Dispatch via SMS adapter (Fail-Closed)
        if not self.sms_healthy:
            # Revert hourly counter on immediate downstream failure
            self.r.decr(hourly_key)
            raise SmsDeliveryError("SMS provider unavailable. Fail-Closed policy: aborted.")

        # Store in Redis with 120s TTL
        self.r.set(code_key, code, ex=120)
        attempts_key = f"otp:attempts:{mobile}"
        self.r.set(attempts_key, "0", ex=120)

        return True, 120

    def verify_otp(self, raw_mobile: str, input_code: str) -> bool:
        """
        Verifies input OTP code.
        Returns True on success.
        Raises OtpMaxAttemptsExceededError or OtpExpiredOrInvalidError.
        """
        mobile = normalize_iranian_mobile(raw_mobile)
        code_key = f"otp:code:{mobile}"
        attempts_key = f"otp:attempts:{mobile}"
        block_key = f"otp:block:{mobile}"

        if self.r.exists(block_key):
            ttl = self.r.ttl(block_key)
            raise OtpRateLimitError(f"Account temporarily blocked. Retry in {ttl}s.")

        stored_code = self.r.get(code_key)
        if not stored_code:
            raise OtpExpiredOrInvalidError("OTP has expired or does not exist. Please request a new code.")

        attempts = self.r.incr(attempts_key)
        if attempts > 3:
            # Max 3 attempts exceeded: invalidate OTP and block for 15 minutes (900s)
            self.r.delete(code_key)
            self.r.delete(attempts_key)
            self.r.set(block_key, "1", ex=900)
            raise OtpMaxAttemptsExceededError("Maximum 3 verification attempts exceeded. Account blocked for 15 minutes.")

        clean_input = re.sub(r"\D", "", str(input_code))
        if clean_input != stored_code:
            remaining = 3 - attempts
            raise OtpExpiredOrInvalidError(f"Incorrect OTP code. {remaining} attempt(s) remaining.")

        # Verification successful: clean up ephemeral keys
        self.r.delete(code_key)
        self.r.delete(attempts_key)
        return True

    def get_active_otp_for_test(self, raw_mobile: str) -> str | None:
        """Test harness helper only: reads active OTP from Redis."""
        mobile = normalize_iranian_mobile(raw_mobile)
        return self.r.get(f"otp:code:{mobile}")

