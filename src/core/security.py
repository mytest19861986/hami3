"""
Security, Cryptography, and Password Hashing Services
BASELINE: BL-HAMICARD-PRD-V1 | AUTH-001..017, SEC-001..014

Standards:
- Argon2id for password hashing (OWASP standard: time_cost=3, memory_cost=65536, parallelism=4)
- SHA-256 for refresh token storage (SSOT in PostgreSQL)
- Cryptographically secure random tokens and OTP generation
"""

import hashlib
import secrets
from typing import Optional
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

# Argon2id password hasher with OWASP parameters
ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MiB
    parallelism=4,
    hash_len=32,
    salt_len=16
)

def hash_password(password: str) -> str:
    """Hashes a password using Argon2id."""
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    return ph.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against an Argon2id hash."""
    if not plain_password or not hashed_password:
        return False
    try:
        return ph.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False

def hash_token(token: str) -> str:
    """Computes SHA-256 digest of token for safe DB storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def generate_secure_token(nbytes: int = 32) -> str:
    """Generates a URL-safe random string for refresh tokens and session secrets."""
    return secrets.token_urlsafe(nbytes)

def generate_otp_code(digits: int = 6) -> str:
    """Generates a cryptographically secure numeric OTP."""
    range_start = 10 ** (digits - 1)
    range_end = (10 ** digits) - 1
    return str(secrets.randbelow(range_end - range_start + 1) + range_start)
