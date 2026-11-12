/**
 * Deterministic Gregorian -> Jalali (Persian Solar Hijri) Date & Number Utilities
 * UX-001, UX-002, UX-003 (BL-HAMICARD-PRD-V1)
 */

const PERSIAN_DIGITS = ['۰', '۱', '۲', '۳', '۴', '۵', '۶', '۷', '۸', '۹'];

export function toPersianDigits(input) {
  return String(input).replace(/\d/g, (d) => PERSIAN_DIGITS[Number(d)]);
}

export function formatToman(amount) {
  const num = Math.trunc(Number(amount || 0));
  const formatted = num.toLocaleString('en-US').replace(/,/g, '٬');
  return `${toPersianDigits(formatted)} تومان`;
}

/**
 * Exact Gregorian (gy, gm, gd) to Jalali (jy, jm, jd) conversion
 * Algorithm based on standard 33/2820-year Persian solar calendar arithmetic.
 */
export function toJalali(gy, gm, gd) {
  const g_d_m = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
  let gy2 = gm > 2 ? gy + 1 : gy;
  let days =
    355666 +
    365 * gy +
    Math.floor((gy2 + 3) / 4) -
    Math.floor((gy2 + 99) / 100) +
    Math.floor((gy2 + 399) / 400) +
    gd +
    g_d_m[gm - 1];
  let jy = -1595 + 33 * Math.floor(days / 12053);
  days %= 12053;
  jy += 4 * Math.floor(days / 1461);
  days %= 1461;
  if (days > 365) {
    jy += Math.floor((days - 1) / 365);
    days = (days - 1) % 365;
  }
  const jm = days < 186 ? 1 + Math.floor(days / 31) : 7 + Math.floor((days - 186) / 30);
  const jd = 1 + (days < 186 ? days % 31 : (days - 186) % 30);
  return { jy, jm, jd };
}

export function formatJalaliDate(isoDateStr) {
  const parts = String(isoDateStr).slice(0, 10).split('-').map(Number);
  if (parts.length !== 3 || parts.some(Number.isNaN)) {
    return 'نامشخص';
  }
  const { jy, jm, jd } = toJalali(parts[0], parts[1], parts[2]);
  const pad = (n) => String(n).padStart(2, '0');
  return toPersianDigits(`${jy}/${pad(jm)}/${pad(jd)}`);
}
