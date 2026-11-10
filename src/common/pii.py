"""
PII Masking and Sanitization Utilities for HamiCard
BASELINE: BL-HAMICARD-PRD-V1 | SEC-006, SEC-014
Guarantees:
- Iranian National Code (10 digits) masked to ******XXXX
- Iranian Mobile Number (11 digits) masked to 0912***XXXX
- Bank Card Number (16 digits) masked to 6037********XXXX
- Bank Sheba / IBAN (26 chars) masked to IR** **** **** **** **** **XX
- Sensitive fields are never logged or returned unmasked in public responses
"""

import re
from typing import Optional

def mask_national_code(code: Optional[str]) -> Optional[str]:
    """Masks 10-digit national code, revealing only last 4 digits."""
    if not code:
        return code
    clean = re.sub(r"\D", "", str(code))
    if len(clean) != 10:
        return "******" + clean[-4:] if len(clean) >= 4 else "******"
    return "******" + clean[-4:]

def mask_phone(phone: Optional[str]) -> Optional[str]:
    """Masks Iranian mobile phone, revealing prefix (4 chars) and suffix (4 chars)."""
    if not phone:
        return phone
    clean = re.sub(r"\D", "", str(phone))
    if len(clean) == 11 and clean.startswith("09"):
        return f"{clean[:4]}***{clean[-4:]}"
    if len(clean) == 10 and clean.startswith("9"):
        return f"0{clean[:3]}***{clean[-4:]}"
    if len(clean) >= 7:
        return f"{clean[:3]}***{clean[-4:]}"
    return "****"

def mask_card_number(card: Optional[str]) -> Optional[str]:
    """Masks 16-digit debit/credit card, revealing first 4 and last 4 digits."""
    if not card:
        return card
    clean = re.sub(r"\D", "", str(card))
    if len(clean) >= 8:
        return f"{clean[:4]}********{clean[-4:]}"
    return "************"

def mask_shaba(shaba: Optional[str]) -> Optional[str]:
    """Masks Iranian Sheba / IBAN (IR + 24 digits), revealing only country code and last 2 digits."""
    if not shaba:
        return shaba
    clean = str(shaba).strip().upper()
    if clean.startswith("IR") and len(clean) >= 26:
        return f"IR** **** **** **** **** **{clean[-2:]}"
    if len(clean) >= 4:
        return f"{clean[:2]}**...**{clean[-2:]}"
    return "IR************************"

