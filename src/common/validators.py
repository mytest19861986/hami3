"""Common Iranian validation routines: National Code, Bank Card (Luhn), and IBAN/Sheba (ISO 7064)."""
import re
from typing import Optional


def validate_iranian_national_code(code: Optional[str]) -> bool:
    """
    Validates an Iranian National Code (کد ملی).
    Requirements:
    - 10 numeric digits (padded with leading zeros if given as 8 or 9 digits).
    - Cannot consist of all identical digits (e.g. 1111111111, 0000000000).
    - Standard checksum verification (weighted sum mod 11).
    """
    if not code:
        return False

    clean_code = re.sub(r"\D", "", str(code))
    if len(clean_code) < 8 or len(clean_code) > 10:
        return False

    # Pad with leading zeros up to 10 digits
    clean_code = clean_code.zfill(10)

    # Reject identical repeating numbers
    if len(set(clean_code)) == 1:
        return False

    check_digit = int(clean_code[9])
    weighted_sum = sum(int(clean_code[i]) * (10 - i) for i in range(9))
    remainder = weighted_sum % 11

    if remainder < 2:
        return check_digit == remainder
    else:
        return check_digit == (11 - remainder)


def validate_iranian_card_number(card: Optional[str]) -> bool:
    """
    Validates an Iranian 16-digit debit/credit card number using the Luhn algorithm (Mod 10).
    """
    if not card:
        return False

    clean_card = re.sub(r"\D", "", str(card))
    if len(clean_card) != 16:
        return False

    total = 0
    for i, digit_char in enumerate(clean_card):
        digit = int(digit_char)
        # Even indices (0, 2, 4...) get doubled in 16-digit numbers (counting from left)
        if i % 2 == 0:
            doubled = digit * 2
            total += doubled - 9 if doubled > 9 else doubled
        else:
            total += digit

    return total % 10 == 0


def validate_iranian_shaba(shaba: Optional[str]) -> bool:
    """
    Validates an Iranian IBAN/Sheba (شماره شبا).
    Format: 'IR' + 24 numeric digits = 26 characters total.
    Algorithm: ISO 7064 Mod 97-10.
    """
    if not shaba:
        return False

    clean = re.sub(r"\s+", "", str(shaba)).upper()
    if not re.match(r"^IR\d{24}$", clean):
        return False

    # Move first 4 characters (Country code + Check digits) to the end: BBAN + CCKK
    rearranged = clean[4:] + clean[:4]

    # Convert letters to digits: 'I' -> 18, 'R' -> 27
    numeric_string = ""
    for char in rearranged:
        if char.isdigit():
            numeric_string += char
        elif 'A' <= char <= 'Z':
            numeric_string += str(ord(char) - ord('A') + 10)
        else:
            return False

    # Check ISO 7064 Mod 97
    return int(numeric_string) % 97 == 1


def validate_iranian_mobile(mobile: Optional[str]) -> bool:
    """
    Validates standard Iranian mobile number format: 09XXXXXXXXX (11 digits).
    """
    if not mobile:
        return False

    clean = re.sub(r"\D", "", str(mobile))
    # Support +989... or 989...
    if clean.startswith("989") and len(clean) == 12:
        clean = "0" + clean[2:]
    elif clean.startswith("9") and len(clean) == 10:
        clean = "0" + clean

    return bool(re.match(r"^09\d{9}$", clean))
