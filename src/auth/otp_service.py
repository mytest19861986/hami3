"""
OTP Service with Atomic Redis Consumption, Rate Limiting & Fail-Closed SMS Delivery
BASELINE: BL-HAMICARD-PRD-V1 | AUTH-001..003, AUTH-017, AC-01, AC-02, OPEN-14
REMEDIATION: HC-T13 (F-02, T13-AC1, T13-AC6)

Guarantees:
- Mobile normalization (09XXXXXXXXX)
- 120s TTL for OTP codes
- Atomic Redis Lua script verification & single-use consumption (eliminates OTP concurrent reuse race)
- Max 3 incorrect verification attempts -> 15-minute lockout
- Max 5 OTP requests per hour (OPEN-14 / SLA)
- Fail-closed SMS adapter integration (Mock adapter strictly prohibited in production; aborts before storing OTP on SMS failure)
- Zero test-only OTP backdoors in production code; zero plaintext OTP/secrets in logs
"""

import re
from typing import Tuple

import redis

from src.adapters.sms import BaseSmsAdapter, MockSmsAdapter, SmsAdapterError, get_sms_adapter
from src.core.env import (
    EnvironmentConfigurationError,
    is_restricted_environment,
)
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


# Atomic Lua script for OTP verification & single-use consumption.
# Executes atomically on the single-threaded Redis server:
# KEYS[1] = otp:code:{mobile}
# KEYS[2] = otp:attempts:{mobile}
# KEYS[3] = otp:block:{mobile}
# ARGV[1] = clean_input_code
# ARGV[2] = block_seconds (900)
_ATOMIC_OTP_VERIFY_LUA = """
if redis.call('EXISTS', KEYS[3]) == 1 then
    return {'BLOCKED', tostring(redis.call('TTL', KEYS[3]))}
end
local stored = redis.call('GET', KEYS[1])
if not stored then
    return {'EXPIRED', '0'}
end
local attempts = redis.call('INCR', KEYS[2])
if attempts > 3 then
    redis.call('DEL', KEYS[1], KEYS[2])
    redis.call('SET', KEYS[3], '1', 'EX', tonumber(ARGV[2]))
    return {'MAX_ATTEMPTS', '0'}
end
if ARGV[1] ~= stored then
    return {'INVALID', tostring(3 - attempts)}
end
redis.call('DEL', KEYS[1], KEYS[2])
return {'OK', '0'}
"""


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


def _is_production_env() -> bool:
    try:
        return is_restricted_environment()
    except EnvironmentConfigurationError as exc:
        raise SmsDeliveryError(str(exc)) from exc


class OtpService:
    def __init__(
        self,
        redis_client: redis.Redis,
        sms_adapter: BaseSmsAdapter | None = None,
        sms_provider_healthy: bool = True,
    ):
        self.r = redis_client
        if sms_adapter is not None:
            self.sms_adapter = sms_adapter
        else:
            try:
                self.sms_adapter = get_sms_adapter()
            except SmsAdapterError as exc:
                raise SmsDeliveryError(str(exc)) from exc
        self.sms_healthy = sms_provider_healthy
        self._verify_script = self.r.register_script(_ATOMIC_OTP_VERIFY_LUA)

    async def request_otp(self, raw_mobile: str) -> Tuple[bool, int]:
        """
        Generates and dispatches OTP code via configured SMS adapter (Fail-Closed).
        Only stores the OTP in Redis AFTER verified provider acceptance.
        Returns: (success: bool, ttl_seconds: int)
        Raises OtpRateLimitError or SmsDeliveryError.
        """
        mobile = normalize_iranian_mobile(raw_mobile)

        # Enforce Fail-Closed production guard against Mock SMS bypass (T13-AC6)
        if _is_production_env() and isinstance(self.sms_adapter, MockSmsAdapter):
            raise SmsDeliveryError(
                "Fail-Closed violation: Mock SMS adapter is forbidden in production."
            )

        # Check blocklist
        block_key = f"otp:block:{mobile}"
        if self.r.exists(block_key):
            ttl = self.r.ttl(block_key)
            raise OtpRateLimitError(
                f"Account temporarily blocked due to repeated failures. Try again in {ttl}s."
            )

        # Check active OTP (1 request per 120s)
        code_key = f"otp:code:{mobile}"
        if self.r.exists(code_key):
            ttl = self.r.ttl(code_key)
            raise OtpRateLimitError(
                f"Please wait {ttl} seconds before requesting a new OTP."
            )

        # Check hourly rate limit (max 5/hour)
        hourly_key = f"otp:hourly:{mobile}"
        current_hourly = self.r.incr(hourly_key)
        if current_hourly == 1:
            self.r.expire(hourly_key, 3600)
        elif current_hourly > 5:
            raise OtpRateLimitError("Hourly OTP limit exceeded (max 5 requests per hour).")

        # Generate secure 6-digit code
        code = generate_otp_code(6)

        # Dispatch via SMS adapter BEFORE storing in Redis (Strict Fail-Closed)
        if not self.sms_healthy:
            self.r.decr(hourly_key)
            raise SmsDeliveryError("SMS provider unavailable. Fail-Closed policy: aborted.")

        try:
            delivered = await self.sms_adapter.send_otp(mobile, code)
        except SmsAdapterError as exc:
            self.r.decr(hourly_key)
            raise SmsDeliveryError(f"SMS delivery failed. Fail-Closed policy: {exc}") from exc
        except Exception as exc:
            self.r.decr(hourly_key)
            raise SmsDeliveryError("SMS provider unexpected failure. Aborted.") from exc

        if not delivered:
            self.r.decr(hourly_key)
            raise SmsDeliveryError("SMS provider did not confirm delivery. Aborted.")

        # Store in Redis with 120s TTL only after verified dispatch
        self.r.set(code_key, code, ex=120)
        attempts_key = f"otp:attempts:{mobile}"
        self.r.set(attempts_key, "0", ex=120)

        return True, 120

    def verify_otp(self, raw_mobile: str, input_code: str) -> bool:
        """
        Atomically verifies and consumes OTP code in Redis via Lua script.
        Eliminates concurrent verification race conditions (F-02, T13-AC1).
        """
        mobile = normalize_iranian_mobile(raw_mobile)
        code_key = f"otp:code:{mobile}"
        attempts_key = f"otp:attempts:{mobile}"
        block_key = f"otp:block:{mobile}"
        clean_input = re.sub(r"\D", "", str(input_code))

        result = self._verify_script(
            keys=[code_key, attempts_key, block_key],
            args=[clean_input, 900],
        )
        status_flag = result[0].decode() if isinstance(result[0], bytes) else str(result[0])
        detail_val = result[1].decode() if isinstance(result[1], bytes) else str(result[1])

        if status_flag == "BLOCKED":
            raise OtpRateLimitError(
                f"Account temporarily blocked. Retry in {detail_val}s."
            )
        if status_flag == "EXPIRED":
            raise OtpExpiredOrInvalidError(
                "OTP has expired or does not exist. Please request a new code."
            )
        if status_flag == "MAX_ATTEMPTS":
            raise OtpMaxAttemptsExceededError(
                "Maximum 3 verification attempts exceeded. Account blocked for 15 minutes."
            )
        if status_flag == "INVALID":
            raise OtpExpiredOrInvalidError(
                f"Incorrect OTP code. {detail_val} attempt(s) remaining."
            )
        if status_flag == "OK":
            return True

        raise OtpExpiredOrInvalidError("OTP verification failed.")
