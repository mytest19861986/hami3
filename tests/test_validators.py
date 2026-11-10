"""Unit tests for Iranian National Code, Card (Luhn), and Sheba (ISO 7064) validators."""
import pytest
from src.common.validators import (
    validate_iranian_national_code,
    validate_iranian_card_number,
    validate_iranian_shaba,
    validate_iranian_mobile,
)


def test_national_code_valid():
    assert validate_iranian_national_code("0010350829") is True
    assert validate_iranian_national_code("0082697817") is True
    assert validate_iranian_national_code("1234567891") is True
    # Zero padded from 8/9 digits
    assert validate_iranian_national_code("10350829") is True


def test_national_code_invalid():
    # Repeating digits
    assert validate_iranian_national_code("1111111111") is False
    assert validate_iranian_national_code("0000000000") is False
    # Wrong checksum
    assert validate_iranian_national_code("0010350820") is False
    # Invalid length
    assert validate_iranian_national_code("123") is False
    assert validate_iranian_national_code(None) is False
    assert validate_iranian_national_code("0010350829999") is False


def test_card_number_valid():
    assert validate_iranian_card_number("6037991199999990") is True
    assert validate_iranian_card_number("5022291012345672") is True
    # With spaces or dashes
    assert validate_iranian_card_number("6037-9911-9999-9990") is True
    assert validate_iranian_card_number("5022 2910 1234 5672") is True


def test_card_number_invalid():
    # Wrong Luhn check digit
    assert validate_iranian_card_number("6037991199999995") is False
    # Wrong length
    assert validate_iranian_card_number("60379911") is False
    assert validate_iranian_card_number(None) is False


def test_shaba_valid():
    # Mathematically valid ISO 7064 test IBANs
    assert validate_iranian_shaba("IR630170000000100412345678") is True
    assert validate_iranian_shaba("ir630170000000100412345678") is True
    assert validate_iranian_shaba("IR100560000000100412345678") is True
    # With spaces
    assert validate_iranian_shaba("IR63 0170 0000 0010 0412 3456 78") is True


def test_shaba_invalid():
    # Corrupted check digits
    assert validate_iranian_shaba("IR000170000000100412345678") is False
    # Wrong prefix
    assert validate_iranian_shaba("GB630170000000100412345678") is False
    # Wrong length
    assert validate_iranian_shaba("IR12345") is False
    assert validate_iranian_shaba(None) is False


def test_mobile_valid():
    assert validate_iranian_mobile("09123456789") is True
    assert validate_iranian_mobile("+989123456789") is True
    assert validate_iranian_mobile("989123456789") is True
    assert validate_iranian_mobile("9123456789") is True


def test_mobile_invalid():
    assert validate_iranian_mobile("08123456789") is False
    assert validate_iranian_mobile("0912345678") is False
    assert validate_iranian_mobile("091234567890") is False
    assert validate_iranian_mobile(None) is False


if __name__ == "__main__":
    test_national_code_valid()
    test_national_code_invalid()
    test_card_number_valid()
    test_card_number_invalid()
    test_shaba_valid()
    test_shaba_invalid()
    test_mobile_valid()
    test_mobile_invalid()
    print("All validator tests passed successfully!")
