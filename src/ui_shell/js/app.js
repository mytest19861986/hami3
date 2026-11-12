/**
 * HamiCard Integrated Phase 3 UI Shell Controller (HC-T39)
 * - Integrates hardened HttpOnly cookie + private RAM access token auth flow (HC-T38).
 * - Zero persistent web storage, zero inline style/script CSP sinks.
 * - Preserves synthetic demo data, Jalali rendering, RTL layout, and OPEN-01..18 PROPOSED gates.
 */

import {
  checkPanelAccess,
  fetchMyProfile,
  fetchReadOnlyRoleExtras,
  getAuthSnapshot,
  getSessionVersion,
  hasSessionHintCookie,
  initAuthLifecycle,
  loginPasswordCookie,
  logoutCookie,
  refreshSessionCoordinated,
  requestOtp,
  verifyOtpCookie,
} from './auth_session.js';
import {
  CONTENT_PAGES,
  ROLE_SHELL_CONFIGS,
  SYNTHETIC_DOCTORS,
  SYNTHETIC_PLANS,
} from './demo_data.js';
import { formatJalaliDate, formatToman, toPersianDigits } from './jalali.js';

const APP_STATE = {
  route: '#/home',
  uiState: 'NORMAL', // NORMAL | LOADING | EMPTY | ERROR | DISABLED_GATE
  docQuery: '',
  docProvince: '',
  docSpecialty: '',
  mobileMenuOpen: false,
  selectedDoctorId: null,
  forms: {
    otpMobile: '',
    otpCode: '',
    pwdMobile: '',
  },
  panelDecisionKey: null,
  panelDecision: null, // { status: 'LOADING' | 'ALLOW' | 'FORBIDDEN' | 'EXPIRED' | 'ERROR', httpStatus, data, detail, unreadCount }
};

const VALID_STATES = ['NORMAL', 'LOADING', 'EMPTY', 'ERROR', 'DISABLED_GATE'];

const ROLE_TO_ROUTE = {
  USER: '#/panel/user',
  DOCTOR: '#/panel/doctor',
  AGENT: '#/panel/agent',
  SUPPORT: '#/panel/support',
  ADMIN: '#/panel/admin',
  SUPER_ADMIN: '#/panel/super-admin',
};

const ROUTE_TO_ROLE = {
  '#/panel/user': 'USER',
  '#/panel/doctor': 'DOCTOR',
  '#/panel/agent': 'AGENT',
  '#/panel/support': 'SUPPORT',
  '#/panel/admin': 'ADMIN',
  '#/panel/super-admin': 'SUPER_ADMIN',
};

function escapeHtml(text) {
  return String(text ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

function getParsedHash() {
  const raw = window.location.hash || '#/home';
  return raw.startsWith('#/') ? raw : '#/home';
}

function setRoute(hashRoute) {
  if (window.location.hash !== hashRoute) {
    window.location.hash = hashRoute;
  } else {
    render();
  }
}

function getPrimaryPanelRoute(roles) {
  const order = ['SUPER_ADMIN', 'ADMIN', 'SUPPORT', 'DOCTOR', 'AGENT', 'USER'];
  for (let i = 0; i < order.length; i += 1) {
    if (Array.isArray(roles) && roles.includes(order[i])) {
      return ROLE_TO_ROUTE[order[i]];
    }
  }
  return '#/panel/user';
}

function renderSessionBar() {
  const snap = getAuthSnapshot();

  if (snap.status === 'REMOTE_REVOKE_FAILED') {
    return `
      <div id="hc-session-bar" class="hc-session-bar hc-session-bar--expired" role="alert" aria-label="هشدار عدم تأیید خروج سروری">
        <div class="hc-flex-wrap">
          <span id="hc-session-badge" class="hc-badge hc-badge--err">هشدار: خروج سروری تأیید نشد</span>
          <span id="hc-logout-warning-banner" class="hc-text-err-sm">${escapeHtml(snap.lastErrorMessage || snap.lastEventMessage)}</span>
        </div>
        <div class="hc-flex-wrap">
          <button type="button" id="hc-retry-logout-btn" class="hc-btn hc-btn--danger">تلاش مجدد خروج سروری</button>
          <a href="#/auth/shell" class="hc-btn hc-btn--secondary">مرکز کنترل نشست</a>
        </div>
      </div>
    `;
  }

  if (snap.status === 'EXPIRED') {
    return `
      <div id="hc-session-bar" class="hc-session-bar hc-session-bar--expired" role="region" aria-label="وضعیت نشست احراز هویت">
        <div>
          <span id="hc-expired-banner" class="hc-badge hc-badge--err">نشست منقضی یا لغو شده (HTTP 401)</span>
          <span class="hc-text-sec-xs">${escapeHtml(snap.lastEventMessage)}</span>
        </div>
        <div class="hc-flex-wrap">
          <a href="#/auth/shell" class="hc-btn hc-btn--primary">ورود مجدد به نشست</a>
        </div>
      </div>
    `;
  }

  if (snap.authenticated) {
    const prof = snap.profile || {};
    const roles = Array.isArray(prof.roles) ? prof.roles : [];
    const fullName = [prof.first_name, prof.last_name].filter(Boolean).join(' ').trim();
    const identityText = fullName
      ? `${fullName} (${prof.mobile || ''})`
      : prof.mobile || 'کاربر احراز‌شده';
    const primaryRoute = getPrimaryPanelRoute(roles);

    return `
      <div id="hc-session-bar" class="hc-session-bar" role="region" aria-label="وضعیت نشست فعال">
        <div class="hc-flex-wrap">
          <span id="hc-session-badge" class="hc-badge hc-badge--ok">نشست امن فعال • HttpOnly Cookie + RAM</span>
          <strong>${escapeHtml(identityText)}</strong>
          ${roles.map((r) => `<span class="hc-badge hc-badge--info">${escapeHtml(r)}</span>`).join('')}
        </div>
        <div class="hc-flex-wrap">
          <a id="hc-goto-allowed-panel-btn" href="${escapeHtml(primaryRoute)}" class="hc-btn hc-btn--secondary">پنل مجاز من</a>
          <button type="button" id="hc-top-refresh-btn" class="hc-btn hc-btn--secondary">تازه‌سازی نشست</button>
          <button type="button" id="hc-top-logout-btn" class="hc-btn hc-btn--danger">خروج امن</button>
        </div>
      </div>
    `;
  }

  return `
    <div id="hc-session-bar" class="hc-session-bar" role="region" aria-label="وضعیت نشست مهمان">
      <div class="hc-flex-wrap">
        <span id="hc-session-badge" class="hc-badge hc-badge--info">وضعیت نشست: مهمان (حافظه موقت RAM فقط)</span>
        <span class="hc-text-sec-xs">${escapeHtml(snap.lastEventMessage)}</span>
      </div>
      <div class="hc-flex-wrap">
        <a href="#/auth/shell" class="hc-btn hc-btn--primary">ورود با OTP یا رمز عبور</a>
      </div>
    </div>
  `;
}

function renderStateBannerIfNeeded(contextTitle) {
  if (APP_STATE.uiState === 'LOADING') {
    return `
      <div class="hc-section" aria-busy="true" aria-label="در حال بارگذاری محتوای نمونه">
        <div class="hc-badge hc-badge--info hc-mb-sm">حالت نمایشی: در حال بارگذاری (Skeleton / UX-009)</div>
        <div class="hc-grid hc-grid--3">
          <div class="hc-skeleton-card"></div>
          <div class="hc-skeleton-card"></div>
          <div class="hc-skeleton-card"></div>
        </div>
      </div>
    `;
  }

  if (APP_STATE.uiState === 'EMPTY') {
    return `
      <section class="hc-card hc-state-box" role="status">
        <span class="hc-badge hc-badge--info">وضعیت داده خالی (UX-011)</span>
        <h2 class="hc-mt-md">داده‌ای برای «${escapeHtml(contextTitle)}» یافت نشد</h2>
        <p class="hc-text-sec">فیلترهای جست‌وجو یا بازه انتخابی نتیجه‌ای برنگرداند. این وضعیت بدون شکستگی جدول یا صفحه خالی بدون راهنما مدیریت می‌شود.</p>
        <button type="button" class="hc-btn hc-btn--secondary" data-reset-state="NORMAL">بازگشت به نمایش عادی داده‌های مصنوعی</button>
      </section>
    `;
  }

  if (APP_STATE.uiState === 'ERROR') {
    return `
      <section class="hc-card hc-state-box hc-state-box--error" role="alert">
        <span class="hc-badge hc-badge--err">وضعیت خطای ایمن و غیرفاش‌کننده (UX-010)</span>
        <h2 class="hc-mt-md">دریافت موقت اطلاعات «${escapeHtml(contextTitle)}» انجام نشد</h2>
        <p>سامانه بدون افشای جزئیات داخلی سرور یا اعتبارنامه، پیام فارسی روشن و مسیر بازگشت امن ارائه می‌دهد.</p>
        <button type="button" class="hc-btn hc-btn--secondary" data-reset-state="NORMAL">تلاش مجدد (بازگشت به حالت عادی)</button>
      </section>
    `;
  }

  if (APP_STATE.uiState === 'DISABLED_GATE') {
    return `
      <section class="hc-card hc-state-box hc-state-box--disabled" role="status">
        <span class="hc-badge hc-badge--proposed">عملیات مسدود / نیازمند تایید (Fail-Closed UX)</span>
        <h2 class="hc-mt-md">اکشن‌های حساس مالی در «${escapeHtml(contextTitle)}» غیرفعال هستند</h2>
        <p>سیاست‌های باز تجاری (OPEN-01 تا OPEN-18) در وضعیت PROPOSED باقی مانده‌اند و هیچ تراکنش مالی یا پیامک زنده ارسال نمی‌شود.</p>
        <button type="button" class="hc-btn hc-btn--secondary" data-reset-state="NORMAL">بازگشت به پیش‌نمایش عادی</button>
      </section>
    `;
  }

  return '';
}

function renderHomeView() {
  const overrideState = renderStateBannerIfNeeded('صفحه اصلی حامی‌کارت');
  if (overrideState) return overrideState;

  return `
    <section class="hc-section hc-hero">
      <div class="hc-flex-wrap hc-mb-sm">
        <span class="hc-badge hc-badge--proposed">تم پیشنهادی OPEN-15 (در انتظار تایید مالک)</span>
        <span class="hc-badge hc-badge--info">شِل یکپارچه فاز ۳ — تاریخ جلالی نمونه: ${formatJalaliDate('2026-11-10')}</span>
      </div>
      <h1>سامانه خدمات رفاهی و درمانی حامی‌کارت — نسخه یکپارچه احراز هویت امن (HC-T39)</h1>
      <p>
        این نسخه کاندید، رابط کاربری راست‌به‌چپ فاز ۳ با داده‌های مصنوعی را به جریان ورود امن کوکی HttpOnly، توکن کوتاه‌عمر در حافظه RAM و کنترل دسترسی سروری نقش‌ها (RBAC) متصل می‌کند؛ بدون هرگونه ذخیره توکن در مرورگر یا فعال‌سازی عملیات مالی.
      </p>
      <div class="hc-flex-wrap-lg">
        <a href="#/auth/shell" class="hc-btn hc-btn--primary">ورود و آزمایش نشست امن (Cookie + RAM)</a>
        <a href="#/doctors" class="hc-btn hc-btn--secondary">مشاهده دایرکتوری پزشکان (نمونه)</a>
        <a href="#/plans" class="hc-btn hc-btn--secondary">مقایسه طرح‌های تخفیف (تومان)</a>
        <a href="#/panel/user" class="hc-btn hc-btn--secondary">مرور پنل‌های ۶گانه</a>
      </div>
    </section>

    <section class="hc-section">
      <div class="hc-grid hc-grid--3">
        ${SYNTHETIC_PLANS.map(
          (p) => `
          <article class="hc-card">
            <span class="hc-badge hc-badge--proposed">${escapeHtml(p.badge)}</span>
            <h2 class="hc-h2-md">${escapeHtml(p.title)}</h2>
            <p class="hc-desc-min3">${escapeHtml(p.summary)}</p>
            <div class="hc-price-big">${formatToman(p.priceToman)}</div>
            <div class="hc-text-sec-xs hc-mb-sm">
              تخفیف نمونه: ${toPersianDigits(p.discountPercent)}٪ | اعتبار: ${toPersianDigits(p.validityDays)} روز
            </div>
            <button type="button" class="hc-btn hc-btn--secondary hc-btn--full" disabled aria-disabled="true">
              انتخاب و پرداخت (قفل تا تایید OPEN-18)
            </button>
          </article>
        `
        ).join('')}
      </div>
    </section>
  `;
}

function renderDoctorsView() {
  const overrideState = renderStateBannerIfNeeded('فهرست پزشکان نمونه');
  if (overrideState) return overrideState;

  const provinces = [...new Set(SYNTHETIC_DOCTORS.map((d) => d.province))];
  const specialties = [...new Set(SYNTHETIC_DOCTORS.map((d) => d.specialty))];

  const filtered = SYNTHETIC_DOCTORS.filter((doc) => {
    const q = APP_STATE.docQuery.trim();
    const matchQ = !q || doc.name.includes(q) || doc.clinic.includes(q) || doc.specialty.includes(q);
    const matchP = !APP_STATE.docProvince || doc.province === APP_STATE.docProvince;
    const matchS = !APP_STATE.docSpecialty || doc.specialty === APP_STATE.docSpecialty;
    return matchQ && matchP && matchS;
  });

  const detailDoc = APP_STATE.selectedDoctorId
    ? SYNTHETIC_DOCTORS.find((d) => d.id === APP_STATE.selectedDoctorId)
    : null;

  return `
    <section class="hc-section">
      <div class="hc-card hc-mb-md">
        <div class="hc-flex-between hc-mb-sm">
          <div>
            <h1 class="hc-h1-md">دایرکتوری مراکز و پزشکان (داده مصنوعی)</h1>
            <p class="hc-text-sec-xs hc-mt-xs">فیلتر بر اساس استان، تخصص و متن — بدون مسیریابی لحظه‌ای GPS مطابق بخش ۲.۲ PRD.</p>
          </div>
          <span class="hc-badge hc-badge--info">مجموع نتایج نمونه: ${toPersianDigits(filtered.length)}</span>
        </div>

        <div class="hc-filter-bar">
          <input id="hc-doc-search" class="hc-input" type="search" value="${escapeHtml(APP_STATE.docQuery)}" placeholder="جست‌وجو نام مرکز، پزشک یا تخصص..." aria-label="جست‌وجو پزشک" />
          <select id="hc-doc-province" class="hc-select" aria-label="فیلتر استان">
            <option value="">همه استان‌های نمونه</option>
            ${provinces
              .map(
                (p) =>
                  `<option value="${escapeHtml(p)}" ${APP_STATE.docProvince === p ? 'selected' : ''}>${escapeHtml(p)}</option>`
              )
              .join('')}
          </select>
          <select id="hc-doc-specialty" class="hc-select" aria-label="فیلتر تخصص">
            <option value="">همه تخصص‌ها</option>
            ${specialties
              .map(
                (s) =>
                  `<option value="${escapeHtml(s)}" ${APP_STATE.docSpecialty === s ? 'selected' : ''}>${escapeHtml(s)}</option>`
              )
              .join('')}
          </select>
        </div>

        ${
          filtered.length === 0
            ? `<div class="hc-state-box" role="status"><strong>پزشک نمونه‌ای با فیلتر انتخابی یافت نشد.</strong> <div class="hc-mt-sm"><button type="button" class="hc-btn hc-btn--secondary" id="hc-clear-doc-filter">پاک‌کردن فیلترها</button></div></div>`
            : `<div class="hc-grid hc-grid--3">
                ${filtered
                  .map(
                    (d) => `
                  <article class="hc-card">
                    <span class="hc-badge hc-badge--ok">تاییدشده نمایشی • ${toPersianDigits(d.discountPercent)}٪ تخفیف</span>
                    <h2 class="hc-h2-sm">${escapeHtml(d.clinic)}</h2>
                    <p class="hc-text-sec-sm hc-mb-xs">${escapeHtml(d.name)}</p>
                    <p class="hc-text-muted-sm">استان ${escapeHtml(d.province)} — شهر ${escapeHtml(d.city)} | تاریخ عضویت: ${formatJalaliDate(d.joinedIso)}</p>
                    <button type="button" class="hc-btn hc-btn--secondary hc-btn--full hc-mt-sm" data-select-doctor="${escapeHtml(d.id)}">مشاهده جزئیات مرکز</button>
                  </article>
                `
                  )
                  .join('')}
              </div>`
        }
      </div>

      ${
        detailDoc
          ? `<div id="hc-doc-detail" class="hc-card" role="region" aria-labelledby="hc-doc-detail-heading" tabindex="-1">
              <div class="hc-flex-between">
                <h2 id="hc-doc-detail-heading" tabindex="-1" class="hc-title-clean">جزئیات مرکز: ${escapeHtml(detailDoc.clinic)}</h2>
                <button type="button" class="hc-btn hc-btn--secondary" id="hc-close-doc-detail">بستن</button>
              </div>
              <p class="hc-text-sec hc-mt-sm">تخصص: ${escapeHtml(detailDoc.specialty)} | تخفیف نمونه: ${toPersianDigits(detailDoc.discountPercent)}٪ (قاعده نهایی تابع OPEN-02) | تاریخ عضویت شمسی: ${formatJalaliDate(detailDoc.joinedIso)}</p>
              <button type="button" class="hc-btn hc-btn--primary" disabled aria-disabled="true">ارائه کارت دیجیتال برای این مرکز (قفل در محیط آزمایشی)</button>
            </div>`
          : ''
      }
    </section>
  `;
}

function renderPlansView() {
  const overrideState = renderStateBannerIfNeeded('کاتالوگ طرح‌های تخفیف');
  if (overrideState) return overrideState;

  return `
    <section class="hc-card">
      <div class="hc-flex-between hc-mb-md">
        <h1 class="hc-h1-md">مقایسه طرح‌های تخفیف حامی‌کارت (واحد تومان — OPEN-18 PROPOSED)</h1>
        <span class="hc-badge hc-badge--proposed">داده نمایشی مصنوعی • فاقد اتصال درگاه پرداخت</span>
      </div>

      <div class="hc-table-wrap">
        <table class="hc-table">
          <thead>
            <tr>
              <th>عنوان طرح (نمونه)</th>
              <th>مبلغ نمایشی</th>
              <th>تخفیف نمونه</th>
              <th>اعتبار</th>
              <th>سقف ویزیت</th>
              <th>اقدام</th>
            </tr>
          </thead>
          <tbody>
            ${SYNTHETIC_PLANS.map(
              (p) => `
              <tr>
                <td><strong>${escapeHtml(p.title)}</strong></td>
                <td>${formatToman(p.priceToman)}</td>
                <td>${toPersianDigits(p.discountPercent)}٪</td>
                <td>${toPersianDigits(p.validityDays)} روز</td>
                <td>${p.maxVisits ? `${toPersianDigits(p.maxVisits)} نوبت` : 'نامحدود'}</td>
                <td><button type="button" class="hc-btn hc-btn--secondary" disabled aria-disabled="true">خرید غیرفعال</button></td>
              </tr>
            `
            ).join('')}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

function renderContentPage(slug) {
  const page = CONTENT_PAGES[slug] || CONTENT_PAGES.about;
  const overrideState = renderStateBannerIfNeeded(page.title);
  if (overrideState) return overrideState;

  return `
    <article class="hc-card">
      <div class="hc-flex-between hc-mb-sm">
        <span class="hc-badge hc-badge--info">صفحه محتوایی عمومی (CONTENT-002)</span>
        <span class="hc-text-muted-sm">آخرین بازنگری (شمسی): ${formatJalaliDate(page.updatedIso)}</span>
      </div>
      <h1 class="hc-h1-lg">${escapeHtml(page.title)}</h1>
      ${page.body.map((para) => `<p class="hc-text-sec">${escapeHtml(para)}</p>`).join('')}
    </article>
  `;
}

function renderAuthShellView() {
  const overrideState = renderStateBannerIfNeeded('احراز هویت و نشست امن کوکی');
  if (overrideState) return overrideState;

  const snap = getAuthSnapshot();
  const auditPayload = {
    authStatus: snap.status,
    authenticated: snap.authenticated,
    hasAccessTokenInClosure: snap.hasAccessTokenInClosure,
    accessExpiresAtMs: snap.accessExpiresAtMs,
    refreshCallsThisTab: snap.refreshCallsThisTab,
    visibleCookieNames: snap.visibleCookieNames,
    hasSessionHintCookie: snap.hasSessionHintCookie,
    persistentWebStorageUsed: false,
  };

  const badgeClass =
    snap.status === 'AUTHENTICATED'
      ? 'hc-badge--ok'
      : snap.status === 'EXPIRED' || snap.status === 'REMOTE_REVOKE_FAILED'
      ? 'hc-badge--err'
      : 'hc-badge--proposed';

  return `
    <section class="hc-section">
      <div class="hc-card hc-mb-md">
        <div class="hc-flex-between">
          <div>
            <span id="hc-auth-status-badge" class="hc-badge ${badgeClass}">${escapeHtml(snap.status)}</span>
            <h1 class="hc-h1-md hc-mt-sm">مرکز ورود امن، رفرش هماهنگ و کنترل نشست فاز ۳ (HC-T39)</h1>
          </div>
          <span class="hc-badge hc-badge--info">HttpOnly Cookie + Closure RAM • Zero Persistent Web Storage</span>
        </div>
        <p id="hc-auth-event-msg" class="hc-text-sec-sm hc-mt-sm">${escapeHtml(snap.lastEventMessage)}</p>
        ${
          snap.lastErrorMessage
            ? `<p id="hc-auth-error-msg" role="alert" class="hc-text-err-sm hc-mt-sm">${escapeHtml(snap.lastErrorMessage)}</p>`
            : ''
        }
        ${
          snap.status === 'REMOTE_REVOKE_FAILED'
            ? `<div class="hc-mt-sm"><button type="button" id="hc-auth-retry-logout-btn" class="hc-btn hc-btn--danger">تلاش مجدد برای لغو نشست در سرور</button></div>`
            : ''
        }
      </div>

      <div class="hc-auth-grid hc-mb-md">
        <article class="hc-card">
          <h2 class="hc-h2-md">۱. ورود با کد یک‌بارمصرف (OTP — Cookie Mode)</h2>
          <form id="hc-otp-form" class="hc-grid-form">
            <label>
              <span class="hc-label-block">شماره موبایل (مثال: 09120000000)</span>
              <input id="hc-otp-mobile" class="hc-input" type="tel" dir="ltr" value="${escapeHtml(APP_STATE.forms.otpMobile)}" placeholder="0912xxxxxxx" required />
            </label>
            <div class="hc-flex-wrap">
              <button type="button" id="hc-otp-request-btn" class="hc-btn hc-btn--secondary">درخواست کد تایید (OTP)</button>
            </div>
            <label>
              <span class="hc-label-block">کد ۶ رقمی تایید</span>
              <input id="hc-otp-code" class="hc-input" type="text" dir="ltr" maxlength="6" value="${escapeHtml(APP_STATE.forms.otpCode)}" placeholder="6 digits" />
            </label>
            <button type="submit" id="hc-otp-verify-btn" class="hc-btn hc-btn--primary">تایید OTP و ایجاد نشست امن</button>
          </form>
        </article>

        <article class="hc-card">
          <h2 class="hc-h2-md">۲. ورود با شماره موبایل و رمز عبور (Cookie Mode)</h2>
          <form id="hc-pwd-form" class="hc-grid-form">
            <label>
              <span class="hc-label-block">شماره موبایل</span>
              <input id="hc-pwd-mobile" class="hc-input" type="tel" dir="ltr" value="${escapeHtml(APP_STATE.forms.pwdMobile)}" placeholder="0912xxxxxxx" required />
            </label>
            <label>
              <span class="hc-label-block">رمز عبور</span>
              <input id="hc-pwd-input" class="hc-input" type="password" dir="ltr" autocomplete="current-password" placeholder="••••••••" required />
            </label>
            <button type="submit" id="hc-pwd-login-btn" class="hc-btn hc-btn--primary">ورود با رمز عبور (Cookie Mode)</button>
          </form>
        </article>
      </div>

      <article class="hc-card">
        <div class="hc-flex-between hc-mb-sm">
          <h2 class="hc-title-clean">۳. عملیات نشست، پروفایل و ممیزی حافظه مرورگر</h2>
          <div class="hc-flex-wrap">
            <button type="button" id="hc-refresh-btn" class="hc-btn hc-btn--secondary">رفرش هماهنگ (Coordinated Refresh)</button>
            <button type="button" id="hc-fetch-profile-btn" class="hc-btn hc-btn--secondary">استعلام پروفایل (/profile/me)</button>
            <button type="button" id="hc-logout-btn" class="hc-btn hc-btn--danger">خروج امن سراسری (All Tabs)</button>
          </div>
        </div>
        <div class="hc-auth-grid">
          <div>
            <div class="hc-label-block">نتیجه پروفایل و نقش‌های سروری (XSS-Safe Escaped):</div>
            <pre id="hc-auth-profile-box" class="hc-pre-audit">${escapeHtml(
              snap.profile ? JSON.stringify(snap.profile, null, 2) : 'هنوز پروفایلی بارگذاری نشده است.'
            )}</pre>
          </div>
          <div>
            <div class="hc-label-block">ممیزی امنیت ذخیره‌سازی و کوکی:</div>
            <pre id="hc-auth-audit-box" class="hc-pre-audit">${escapeHtml(JSON.stringify(auditPayload, null, 2))}</pre>
          </div>
        </div>
      </article>
    </section>
  `;
}

async function verifyPanelAuthorization(roleKey) {
  const decisionKey = `${roleKey}:${getSessionVersion()}`;
  if (APP_STATE.panelDecisionKey === decisionKey) {
    return;
  }

  APP_STATE.panelDecisionKey = decisionKey;
  APP_STATE.panelDecision = {
    status: 'LOADING',
    httpStatus: null,
    data: null,
    detail: '',
    unreadCount: null,
  };
  render();

  try {
    const res = await checkPanelAccess(roleKey);
    if (APP_STATE.panelDecisionKey !== decisionKey) {
      return;
    }

    if (res.ok) {
      const extras = await fetchReadOnlyRoleExtras();
      if (APP_STATE.panelDecisionKey !== decisionKey) {
        return;
      }
      APP_STATE.panelDecision = {
        status: 'ALLOW',
        httpStatus: res.status,
        data: res.data,
        detail: '',
        unreadCount: extras && typeof extras.unread_count === 'number' ? extras.unread_count : null,
      };
    } else if (res.status === 403 && res.data && res.data.code === 'PROFESSIONAL_APPROVAL_REQUIRED') {
      APP_STATE.panelDecision = {
        status: 'APPLICATION_STATUS_ONLY',
        httpStatus: 403,
        data: res.data,
        detail: res.data.detail || 'پرونده صنفی شما هنوز تایید نهایی (APPROVED) نشده است.',
        unreadCount: null,
      };
    } else if (res.status === 403) {
      APP_STATE.panelDecision = {
        status: 'FORBIDDEN',
        httpStatus: 403,
        data: res.data,
        detail: res.data.detail || 'دسترسی به این پنل برای نقش فعلی مجاز نیست.',
        unreadCount: null,
      };
    } else if (res.status === 401) {
      APP_STATE.panelDecision = {
        status: 'EXPIRED',
        httpStatus: 401,
        data: res.data,
        detail: res.data.detail || 'نشست منقضی شده است.',
        unreadCount: null,
      };
    } else {
      APP_STATE.panelDecision = {
        status: 'ERROR',
        httpStatus: res.status,
        data: res.data,
        detail: res.data.detail || `خطای سرور (${res.status})`,
        unreadCount: null,
      };
    }
  } catch (err) {
    if (APP_STATE.panelDecisionKey !== decisionKey) {
      return;
    }
    APP_STATE.panelDecision = {
      status: err && err.message === 'UNAUTHENTICATED' ? 'EXPIRED' : 'ERROR',
      httpStatus: 401,
      data: null,
      detail: 'نشست معتبر برای بررسی دسترسی سرور موجود نیست.',
      unreadCount: null,
    };
  }
  render();
}

function renderRolePanel(roleKey) {
  const cfg = ROLE_SHELL_CONFIGS[roleKey] || ROLE_SHELL_CONFIGS.USER;
  const overrideState = renderStateBannerIfNeeded(cfg.roleTitle);
  if (overrideState) return overrideState;

  const snap = getAuthSnapshot();
  const shouldVerifyWithServer = snap.authenticated || hasSessionHintCookie();

  if (shouldVerifyWithServer) {
    const expectedKey = `${roleKey}:${getSessionVersion()}`;
    if (APP_STATE.panelDecisionKey !== expectedKey) {
      queueMicrotask(() => {
        verifyPanelAuthorization(roleKey);
      });
      return `
        <section class="hc-card hc-state-box" aria-busy="true">
          <span class="hc-badge hc-badge--info">در حال اعتبارسنجی مجوز نقش در سرور (RBAC)...</span>
          <h2 class="hc-mt-md">بررسی دسترسی پنل ${escapeHtml(cfg.roleTitle)}</h2>
        </section>
      `;
    }

    const dec = APP_STATE.panelDecision;
    if (dec && dec.status === 'LOADING') {
      return `
        <section class="hc-card hc-state-box" aria-busy="true">
          <span class="hc-badge hc-badge--info">در حال دریافت تاییدیه سروری از /api/v1/auth/panels/...</span>
          <h2 class="hc-mt-md">${escapeHtml(cfg.roleTitle)}</h2>
        </section>
      `;
    }

    if (dec && dec.status === 'APPLICATION_STATUS_ONLY' && dec.data) {
      const vStatus = dec.data.verification_status || 'PENDING';
      return `
        <section id="hc-application-status-box" class="hc-card hc-card--warn hc-state-box" role="status">
          <div class="hc-flex-between hc-mb-sm">
            <span class="hc-badge hc-badge--warn">صفحه محدود وضعیت پرونده صنفی (بدون دسترسی عملیاتی)</span>
            <span class="hc-badge hc-badge--info">وضعیت پرونده در سرور: <code dir="ltr">${escapeHtml(vStatus)}</code></span>
          </div>
          <h1 class="hc-h1-lg">پرونده «${escapeHtml(cfg.roleTitle)}» در وضعیت «${escapeHtml(vStatus)}» است</h1>
          <p>${escapeHtml(dec.detail)}</p>
          <p class="hc-text-sec-sm">امکانات عملیاتی داشبورد پزشک/نماینده تنها پس از تغییر وضعیت پرونده در پایگاه‌داده به <code dir="ltr">APPROVED</code> توسط سرور فعال می‌شوند.</p>
          <div class="hc-flex-wrap hc-mt-md">
            <a href="#/panel/user" class="hc-btn hc-btn--secondary">ورود به پنل کاربری عادی</a>
            <a href="#/home" class="hc-btn hc-btn--primary">بازگشت به صفحه اصلی</a>
          </div>
        </section>
      `;
    }

    if (dec && dec.status === 'FORBIDDEN') {
      const roles = (snap.profile && snap.profile.roles) || [];
      const allowedRoute = getPrimaryPanelRoute(roles);
      return `
        <section id="hc-forbidden-box" class="hc-card hc-state-box hc-state-box--error" role="alert">
          <div class="hc-flex-between hc-mb-sm">
            <span class="hc-badge hc-badge--err">خطای ۴۰۳ — عدم دسترسی مجاز (RBAC Server Enforced)</span>
            <span class="hc-badge hc-badge--info">مسیر درخواستی: ${escapeHtml(cfg.route)}</span>
          </div>
          <h1 class="hc-h1-lg">شما مجاز به مشاهده «${escapeHtml(cfg.roleTitle)}» نیستید</h1>
          <p>${escapeHtml(dec.detail)}</p>
          <p class="hc-text-sec-sm">نقش‌های تاییدشده در نشست فعلی: <strong>${escapeHtml(roles.join(', ') || 'بدون نقش')}</strong></p>
          <div class="hc-flex-wrap hc-mt-md">
            <a id="hc-forbidden-back-btn" href="${escapeHtml(allowedRoute)}" class="hc-btn hc-btn--primary">بازگشت به پنل مجاز من</a>
            <a href="#/home" class="hc-btn hc-btn--secondary">بازگشت به صفحه اصلی</a>
          </div>
        </section>
      `;
    }

    if (dec && dec.status === 'EXPIRED') {
      return `
        <section class="hc-card hc-state-box hc-state-box--error" role="alert">
          <span class="hc-badge hc-badge--err">نشست منقضی یا لغو شده (HTTP 401)</span>
          <h1 class="hc-h1-lg hc-mt-md">برای دسترسی به «${escapeHtml(cfg.roleTitle)}» دوباره وارد شوید</h1>
          <p>${escapeHtml(dec.detail)}</p>
          <a href="#/auth/shell" class="hc-btn hc-btn--primary">ورود مجدد</a>
        </section>
      `;
    }
  }

  const prof = snap.profile || {};
  const fullName = [prof.first_name, prof.last_name].filter(Boolean).join(' ').trim();
  const dec = APP_STATE.panelDecision;
  const serverVerifiedBanner =
    dec && dec.status === 'ALLOW' && dec.data && dec.data.access_level === 'ADMIN_REVIEW_ONLY'
      ? `<div id="hc-admin-review-badge" class="hc-card hc-card--warn hc-mb-sm">
          <div class="hc-flex-between">
            <span class="hc-badge hc-badge--warn">نمای بازبینی مدیریتی (غیرعملیاتی • ${escapeHtml(dec.data.panel_role)})</span>
            ${
              dec.unreadCount !== null
                ? `<span class="hc-badge hc-badge--info">اعلان‌های خوانده‌نشده: ${toPersianDigits(dec.unreadCount)}</span>`
                : ''
            }
          </div>
          <div class="hc-text-sec-sm hc-mt-sm">
            ناظر مدیریتی: <strong>${escapeHtml(fullName || prof.mobile || 'مدیر ارشد')}</strong>
            | نقش‌های سروری: <code dir="ltr">${escapeHtml((dec.data.effective_roles || []).join(', '))}</code>
            | حالت: <code dir="ltr">ADMIN_REVIEW_ONLY (operational_access=false)</code>
          </div>
        </div>`
      : dec && dec.status === 'ALLOW' && dec.data && dec.data.operational_access === true
      ? `<div id="hc-panel-authorized-badge" class="hc-card hc-mb-sm">
          <div class="hc-flex-between">
            <span class="hc-badge hc-badge--ok">دسترسی تاییدشده عملیاتی سرور (HTTP 200 • ${escapeHtml(dec.data.panel_role)})</span>
            ${
              dec.unreadCount !== null
                ? `<span class="hc-badge hc-badge--info">اعلان‌های خوانده‌نشده: ${toPersianDigits(dec.unreadCount)}</span>`
                : ''
            }
          </div>
          <div class="hc-text-sec-sm hc-mt-sm">
            کاربر نشست: <strong>${escapeHtml(fullName || prof.mobile || 'کاربر')}</strong>
            | نقش‌های سروری: <code dir="ltr">${escapeHtml((dec.data.effective_roles || []).join(', '))}</code>
            ${
              dec.data.verification_status
                ? `| وضعیت احراز صنفی: <strong>${escapeHtml(dec.data.verification_status)}</strong>`
                : ''
            }
          </div>
        </div>`
      : `<div class="hc-card hc-card--warn hc-mb-sm">
          <strong>پیش‌نمایش ساختاری بدون نشست فعال:</strong> برای آزمایش کنترل دسترسی واقعی RBAC و داده‌های نشست، از <a href="#/auth/shell">صفحه ورود امن</a> وارد شوید.
        </div>`;

  return `
    <section class="hc-workspace" aria-label="فضای کاری نقش ${escapeHtml(cfg.roleTitle)}">
      <aside class="hc-sidebar">
        <div class="hc-mb-sm">
          <span class="hc-badge hc-badge--info">پنل ساختاری بخش ۲۷</span>
          <h2 class="hc-h2-nav">${escapeHtml(cfg.roleTitle)}</h2>
          <p class="hc-text-muted-xs">مسیر مرجع: <code dir="ltr">${escapeHtml(cfg.route)}</code></p>
        </div>
        <ul class="hc-sidebar-list">
          ${cfg.navItems.map((item) => `<li class="hc-sidebar-item">${escapeHtml(item)}</li>`).join('')}
        </ul>
      </aside>

      <div class="hc-grid-gap">
        ${serverVerifiedBanner}

        <div class="hc-card hc-card--warn">
          <strong>مرز دسترسی و حفاظت سیاست‌ها:</strong> ${escapeHtml(cfg.boundaryNotice)}
        </div>

        <div class="hc-grid hc-grid--3">
          ${cfg.metrics
            .map((m) => {
              const renderedVal = m.valueIso
                ? formatJalaliDate(m.valueIso)
                : m.valueToman !== undefined
                ? formatToman(m.valueToman)
                : `<bdi dir="auto">${escapeHtml(m.value)}</bdi>`;
              return `
              <div class="hc-card">
                <div class="hc-metric-label">${escapeHtml(m.label)}</div>
                <div class="hc-metric-val">${renderedVal}</div>
              </div>
            `;
            })
            .join('')}
        </div>

        <div class="hc-card">
          <div class="hc-flex-between hc-mb-sm">
            <h2 class="hc-title-clean">فهرست نمونه با داده‌های مصنوعی (Synthetic Demo Rows)</h2>
            <span class="hc-badge hc-badge--proposed">OPEN-01..18 PROPOSED</span>
          </div>
          <div class="hc-table-wrap">
            <table class="hc-table">
              <thead>
                <tr>${cfg.columns.map((c) => `<th>${escapeHtml(c)}</th>`).join('')}</tr>
              </thead>
              <tbody>
                ${cfg.rows
                  .map(
                    (r) => `
                  <tr>
                    <td><code>${escapeHtml(r.col1)}</code></td>
                    <td>${escapeHtml(r.col2)}</td>
                    <td>${r.col3 === '0' ? 'غیرمجاز / ۰' : formatToman(r.col3)}</td>
                    <td>${formatJalaliDate(r.col4Iso)}</td>
                    <td><span class="hc-badge hc-badge--proposed">${escapeHtml(r.status)}</span></td>
                  </tr>
                `
                  )
                  .join('')}
              </tbody>
            </table>
          </div>
          <div class="hc-mt-lg">
            <button type="button" class="hc-btn hc-btn--primary" disabled aria-disabled="true">${escapeHtml(cfg.blockedActionLabel)}</button>
          </div>
        </div>
      </div>
    </section>
  `;
}

function announceStatus(message) {
  const statusEl = document.getElementById('hc-live-status');
  if (statusEl) {
    statusEl.textContent = message;
  }
}

function updateActiveNavIndicators() {
  const currentHash = getParsedHash();
  document.querySelectorAll('[data-nav-route]').forEach((el) => {
    const target = el.getAttribute('data-nav-route');
    if (currentHash === target || (target === '#/panel/user' && currentHash.startsWith('#/panel/'))) {
      el.setAttribute('aria-current', 'page');
    } else {
      el.removeAttribute('aria-current');
    }
  });

  document.querySelectorAll('[data-ui-state]').forEach((btn) => {
    const isChecked = btn.getAttribute('data-ui-state') === APP_STATE.uiState;
    btn.setAttribute('aria-checked', isChecked ? 'true' : 'false');
    btn.setAttribute('tabindex', isChecked ? '0' : '-1');
  });

  const roleBtns = [...document.querySelectorAll('[data-role-route]')];
  const anyRoleActive = roleBtns.some((btn) => btn.getAttribute('data-role-route') === currentHash);
  roleBtns.forEach((btn, idx) => {
    const isChecked = btn.getAttribute('data-role-route') === currentHash;
    btn.setAttribute('aria-checked', isChecked ? 'true' : 'false');
    btn.setAttribute('tabindex', isChecked || (!anyRoleActive && idx === 0) ? '0' : '-1');
  });
}

function bindViewEvents() {
  const topRefreshBtn = document.getElementById('hc-top-refresh-btn');
  if (topRefreshBtn) {
    topRefreshBtn.addEventListener('click', async () => {
      await refreshSessionCoordinated({ force: true });
      APP_STATE.panelDecisionKey = null;
      render();
      announceStatus('نشست امن تازه‌سازی شد.');
    });
  }

  const handleLogoutAttempt = async () => {
    const res = await logoutCookie();
    APP_STATE.panelDecisionKey = null;
    APP_STATE.panelDecision = null;
    render();
    announceStatus(
      res && res.revokedOnServer
        ? 'خروج امن با تأیید سرور انجام شد.'
        : 'هشدار: لغو نشست روی سرور تأیید نشد؛ تلاش مجدد لازم است.'
    );
  };

  const topLogoutBtn = document.getElementById('hc-top-logout-btn');
  if (topLogoutBtn) {
    topLogoutBtn.addEventListener('click', handleLogoutAttempt);
  }

  const retryLogoutBtn = document.getElementById('hc-retry-logout-btn');
  if (retryLogoutBtn) {
    retryLogoutBtn.addEventListener('click', handleLogoutAttempt);
  }

  const authRetryLogoutBtn = document.getElementById('hc-auth-retry-logout-btn');
  if (authRetryLogoutBtn) {
    authRetryLogoutBtn.addEventListener('click', handleLogoutAttempt);
  }

  const otpMobileEl = document.getElementById('hc-otp-mobile');
  if (otpMobileEl) {
    otpMobileEl.addEventListener('input', (e) => {
      APP_STATE.forms.otpMobile = e.target.value;
    });
  }

  const otpCodeEl = document.getElementById('hc-otp-code');
  if (otpCodeEl) {
    otpCodeEl.addEventListener('input', (e) => {
      APP_STATE.forms.otpCode = e.target.value;
    });
  }

  const pwdMobileEl = document.getElementById('hc-pwd-mobile');
  if (pwdMobileEl) {
    pwdMobileEl.addEventListener('input', (e) => {
      APP_STATE.forms.pwdMobile = e.target.value;
    });
  }

  const otpReqBtn = document.getElementById('hc-otp-request-btn');
  if (otpReqBtn) {
    otpReqBtn.addEventListener('click', async () => {
      const mobile = (document.getElementById('hc-otp-mobile')?.value || '').trim();
      APP_STATE.forms.otpMobile = mobile;
      if (!mobile) return;
      await requestOtp(mobile);
      announceStatus('درخواست کد تایید ارسال شد.');
    });
  }

  const otpForm = document.getElementById('hc-otp-form');
  if (otpForm) {
    otpForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const mobile = (document.getElementById('hc-otp-mobile')?.value || '').trim();
      const code = (document.getElementById('hc-otp-code')?.value || '').trim();
      APP_STATE.forms.otpMobile = mobile;
      APP_STATE.forms.otpCode = code;
      const res = await verifyOtpCookie(mobile, code);
      if (res.ok) {
        APP_STATE.panelDecisionKey = null;
        APP_STATE.forms.otpCode = '';
        announceStatus('ورود با OTP با موفقیت انجام شد.');
      }
    });
  }

  const pwdForm = document.getElementById('hc-pwd-form');
  if (pwdForm) {
    pwdForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const mobile = (document.getElementById('hc-pwd-mobile')?.value || '').trim();
      const pwdInput = document.getElementById('hc-pwd-input');
      const password = pwdInput ? pwdInput.value : '';
      APP_STATE.forms.pwdMobile = mobile;
      const res = await loginPasswordCookie(mobile, password);
      if (pwdInput) pwdInput.value = '';
      if (res.ok) {
        APP_STATE.panelDecisionKey = null;
        announceStatus('ورود با رمز عبور با موفقیت انجام شد.');
      }
    });
  }

  const refreshBtn = document.getElementById('hc-refresh-btn');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', async () => {
      await refreshSessionCoordinated({ force: true });
      APP_STATE.panelDecisionKey = null;
      render();
    });
  }

  const fetchProfBtn = document.getElementById('hc-fetch-profile-btn');
  if (fetchProfBtn) {
    fetchProfBtn.addEventListener('click', async () => {
      try {
        await fetchMyProfile();
      } catch {
        render();
      }
    });
  }

  const logoutBtn = document.getElementById('hc-logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      const res = await logoutCookie();
      APP_STATE.panelDecisionKey = null;
      APP_STATE.panelDecision = null;
      render();
      announceStatus(
        res && res.revokedOnServer
          ? 'خروج امن با تأیید سرور انجام شد.'
          : 'هشدار: لغو نشست روی سرور تأیید نشد؛ تلاش مجدد لازم است.'
      );
    });
  }

  const searchEl = document.getElementById('hc-doc-search');
  if (searchEl) {
    searchEl.addEventListener('input', (e) => {
      APP_STATE.docQuery = e.target.value;
      render();
      const restored = document.getElementById('hc-doc-search');
      if (restored) {
        restored.focus();
        restored.setSelectionRange(restored.value.length, restored.value.length);
      }
      announceStatus('فهرست پزشکان بر اساس متن جست‌وجو به‌روزرسانی شد.');
    });
  }

  const provEl = document.getElementById('hc-doc-province');
  if (provEl) {
    provEl.addEventListener('change', (e) => {
      APP_STATE.docProvince = e.target.value;
      render();
      const restoredProv = document.getElementById('hc-doc-province');
      if (restoredProv) restoredProv.focus();
      announceStatus('فیلتر استان پزشکان به‌روزرسانی شد.');
    });
  }

  const specEl = document.getElementById('hc-doc-specialty');
  if (specEl) {
    specEl.addEventListener('change', (e) => {
      APP_STATE.docSpecialty = e.target.value;
      render();
      const restoredSpec = document.getElementById('hc-doc-specialty');
      if (restoredSpec) restoredSpec.focus();
      announceStatus('فیلتر تخصص پزشکان به‌روزرسانی شد.');
    });
  }

  const clearBtn = document.getElementById('hc-clear-doc-filter');
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      APP_STATE.docQuery = '';
      APP_STATE.docProvince = '';
      APP_STATE.docSpecialty = '';
      render();
      const restoredSearch = document.getElementById('hc-doc-search');
      if (restoredSearch) restoredSearch.focus();
      announceStatus('فیلترهای پزشکان پاک شدند.');
    });
  }

  document.querySelectorAll('[data-select-doctor]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const docId = btn.getAttribute('data-select-doctor');
      APP_STATE.selectedDoctorId = docId;
      render();
      const heading = document.getElementById('hc-doc-detail-heading');
      const region = document.getElementById('hc-doc-detail');
      if (heading) {
        heading.focus();
        announceStatus(`${heading.textContent} باز شد.`);
      } else if (region) {
        region.focus();
      }
    });
  });

  const closeDetailAndRestore = () => {
    const prevId = APP_STATE.selectedDoctorId;
    APP_STATE.selectedDoctorId = null;
    render();
    if (prevId) {
      const trigger = document.querySelector(`[data-select-doctor="${prevId}"]`);
      if (trigger) trigger.focus();
    }
    announceStatus('نمای جزئیات پزشک بسته شد.');
  };

  const closeDocBtn = document.getElementById('hc-close-doc-detail');
  if (closeDocBtn) {
    closeDocBtn.addEventListener('click', closeDetailAndRestore);
  }

  const detailRegion = document.getElementById('hc-doc-detail');
  if (detailRegion) {
    detailRegion.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        closeDetailAndRestore();
      }
    });
  }

  document.querySelectorAll('[data-reset-state]').forEach((btn) => {
    btn.addEventListener('click', () => {
      APP_STATE.uiState = btn.getAttribute('data-reset-state') || 'NORMAL';
      render();
      announceStatus('وضعیت نمایش به حالت عادی بازگشت.');
    });
  });
}

export function render() {
  const root = document.getElementById('app-root');
  if (!root) return;

  const route = getParsedHash();
  APP_STATE.route = route;

  let viewHtml = '';
  if (route === '#/home') {
    viewHtml = renderHomeView();
  } else if (route === '#/doctors') {
    viewHtml = renderDoctorsView();
  } else if (route === '#/plans') {
    viewHtml = renderPlansView();
  } else if (route === '#/auth/shell') {
    viewHtml = renderAuthShellView();
  } else if (route.startsWith('#/content/')) {
    const slug = route.replace('#/content/', '');
    viewHtml = renderContentPage(slug);
  } else if (ROUTE_TO_ROLE[route]) {
    viewHtml = renderRolePanel(ROUTE_TO_ROLE[route]);
  } else {
    viewHtml = renderHomeView();
  }

  root.innerHTML = `${renderSessionBar()}${viewHtml}`;
  updateActiveNavIndicators();
  bindViewEvents();
}

function wireRadiogroup(radios, onActivate) {
  if (!radios.length) return;
  radios.forEach((btn, idx) => {
    btn.addEventListener('click', () => {
      onActivate(btn);
    });
    btn.addEventListener('keydown', (e) => {
      let nextIdx = null;
      if (e.key === 'ArrowLeft' || e.key === 'ArrowDown') {
        nextIdx = (idx + 1) % radios.length;
      } else if (e.key === 'ArrowRight' || e.key === 'ArrowUp') {
        nextIdx = (idx - 1 + radios.length) % radios.length;
      } else if (e.key === 'Home') {
        nextIdx = 0;
      } else if (e.key === 'End') {
        nextIdx = radios.length - 1;
      }
      if (nextIdx !== null) {
        e.preventDefault();
        const target = radios[nextIdx];
        target.focus();
        onActivate(target);
      }
    });
  });
}

function initShell() {
  const menuBtn = document.getElementById('hc-menu-toggle');
  const drawer = document.getElementById('hc-mobile-drawer');
  const drawerCloseBtn = document.getElementById('hc-drawer-close');

  const getDrawerFocusables = () => {
    if (!drawer) return [];
    return [...drawer.querySelectorAll('a[href], button:not([disabled])')];
  };

  const openMobileDrawer = () => {
    if (!menuBtn || !drawer) return;
    APP_STATE.mobileMenuOpen = true;
    drawer.classList.add('is-open');
    drawer.setAttribute('aria-hidden', 'false');
    menuBtn.setAttribute('aria-expanded', 'true');
    const items = getDrawerFocusables();
    const firstLink = drawer.querySelector('a[href]') || items[0];
    if (firstLink) firstLink.focus();
    announceStatus('منوی موبایل باز شد.');
  };

  const closeMobileDrawer = (restoreFocus = false) => {
    if (!menuBtn || !drawer) return;
    APP_STATE.mobileMenuOpen = false;
    drawer.classList.remove('is-open');
    drawer.setAttribute('aria-hidden', 'true');
    menuBtn.setAttribute('aria-expanded', 'false');
    if (restoreFocus) menuBtn.focus();
    announceStatus('منوی موبایل بسته شد.');
  };

  if (menuBtn && drawer) {
    menuBtn.addEventListener('click', () => {
      if (APP_STATE.mobileMenuOpen) {
        closeMobileDrawer(true);
      } else {
        openMobileDrawer();
      }
    });

    if (drawerCloseBtn) {
      drawerCloseBtn.addEventListener('click', () => {
        closeMobileDrawer(true);
      });
    }

    drawer.addEventListener('click', (e) => {
      if (e.target.closest('a')) {
        closeMobileDrawer(false);
      }
    });

    document.addEventListener('keydown', (e) => {
      if (!APP_STATE.mobileMenuOpen) return;
      if (e.key === 'Escape') {
        e.preventDefault();
        closeMobileDrawer(true);
        return;
      }
      if (e.key === 'Tab') {
        const focusables = getDrawerFocusables();
        if (!focusables.length) return;
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        const activeIdx = focusables.indexOf(document.activeElement);
        e.preventDefault();
        if (activeIdx === -1) {
          first.focus();
        } else if (e.shiftKey) {
          (activeIdx === 0 ? last : focusables[activeIdx - 1]).focus();
        } else {
          (activeIdx === focusables.length - 1 ? first : focusables[activeIdx + 1]).focus();
        }
      }
    });
  }

  wireRadiogroup([...document.querySelectorAll('[data-ui-state]')], (btn) => {
    const next = btn.getAttribute('data-ui-state');
    if (VALID_STATES.includes(next)) {
      APP_STATE.uiState = next;
      render();
      announceStatus(`وضعیت پیش‌نمایش روی «${btn.textContent.trim()}» تنظیم شد.`);
    }
  });

  wireRadiogroup([...document.querySelectorAll('[data-role-route]')], (btn) => {
    const nextRoute = btn.getAttribute('data-role-route');
    if (nextRoute) {
      APP_STATE.uiState = 'NORMAL';
      setRoute(nextRoute);
      announceStatus(`پنل نقش ${btn.textContent.trim()} نمایش داده شد.`);
    }
  });

  window.addEventListener('hashchange', () => {
    APP_STATE.panelDecisionKey = null;
    render();
    announceStatus(`مسیر صفحه به ${getParsedHash()} تغییر یافت.`);
  });

  initAuthLifecycle(() => {
    render();
  });

  render();
}

document.addEventListener('DOMContentLoaded', initShell);
