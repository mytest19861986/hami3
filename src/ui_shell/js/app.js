/**
 * HamiCard Isolated Phase 3 UI Shell Controller (HC-T16)
 * - Strictly disconnected from unaccepted Phase 2 auth or unapproved OPEN policies.
 * - Zero credential storage, zero silent mock success on sensitive financial writes.
 * - Supports all Section 27 routes, 6 PRD roles, RTL Jalali rendering, and 5 UI states.
 */

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
};

const VALID_STATES = ['NORMAL', 'LOADING', 'EMPTY', 'ERROR', 'DISABLED_GATE'];

function escapeHtml(text) {
  return String(text ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function getParsedHash() {
  const raw = window.location.hash || '#/home';
  const clean = raw.startsWith('#/') ? raw : '#/home';
  return clean;
}

function setRoute(hashRoute) {
  if (window.location.hash !== hashRoute) {
    window.location.hash = hashRoute;
  } else {
    render();
  }
}

function renderStateBannerIfNeeded(contextTitle) {
  if (APP_STATE.uiState === 'LOADING') {
    return `
      <div class="hc-section" aria-busy="true" aria-label="در حال بارگذاری محتوای نمونه">
        <div class="hc-badge hc-badge--info" style="margin-bottom:0.75rem;">حالت نمایشی: در حال بارگذاری (Skeleton / UX-009)</div>
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
        <h2 style="margin-top:0.75rem;">داده‌ای برای «${escapeHtml(contextTitle)}» یافت نشد</h2>
        <p style="color:var(--hc-text-secondary);">فیلترهای جست‌وجو یا بازه انتخابی نتیجه‌ای برنگرداند. این وضعیت بدون شکستگی جدول یا صفحه خالی بدون راهنما مدیریت می‌شود.</p>
        <button type="button" class="hc-btn hc-btn--secondary" data-reset-state="NORMAL">بازگشت به نمایش عادی داده‌های مصنوعی</button>
      </section>
    `;
  }

  if (APP_STATE.uiState === 'ERROR') {
    return `
      <section class="hc-card hc-state-box hc-state-box--error" role="alert">
        <span class="hc-badge hc-badge--err">وضعیت خطای ایمن و غیرفاش‌کننده (UX-010)</span>
        <h2 style="margin-top:0.75rem;">دریافت موقت اطلاعات «${escapeHtml(contextTitle)}» انجام نشد</h2>
        <p>سامانه بدون افشای جزئیات داخلی سرور یا اعتبارنامه، پیام فارسی روشن و مسیر بازگشت امن ارائه می‌دهد.</p>
        <button type="button" class="hc-btn hc-btn--secondary" data-reset-state="NORMAL">تلاش مجدد (بازگشت به حالت عادی)</button>
      </section>
    `;
  }

  if (APP_STATE.uiState === 'DISABLED_GATE') {
    return `
      <section class="hc-card hc-state-box hc-state-box--disabled" role="status">
        <span class="hc-badge hc-badge--proposed">عملیات مسدود / نیازمند تایید (Fail-Closed UX)</span>
        <h2 style="margin-top:0.75rem;">اکشن‌های حساس مالی و هویتی در «${escapeHtml(contextTitle)}» غیرفعال هستند</h2>
        <p>تا زمان پذیرش رسمی امنیتی فاز ۲ (HC-T13) و تصویب سیاست‌های باز تجاری (OPEN-01 تا OPEN-18 در HC-T14)، هیچ درخواست احراز هویت یا تراکنش واقعی ارسال نمی‌شود.</p>
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
      <div style="display:flex;flex-wrap:wrap;gap:0.5rem;margin-bottom:0.75rem;">
        <span class="hc-badge hc-badge--proposed">تم پیشنهادی OPEN-15 (در انتظار تایید مالک)</span>
        <span class="hc-badge hc-badge--info">اسکلت فاز ۳ — تاریخ جلالی نمونه: ${formatJalaliDate('2026-11-10')}</span>
      </div>
      <h1>سامانه خدمات رفاهی و درمانی حامی‌کارت — پیش‌نمایش ایزوله فاز ۳</h1>
      <p>
        این محیط شامل نقشه کامل صفحات عمومی و پنل‌های ۶گانه مطابق سند نیازمندی‌ها (بخش ۲۷) با طراحی راست‌به‌چپ، تاریخ شمسی و داده‌های آزمایشی کاملاً مصنوعی است. اتصال به ورود واقعی و عملیات مالی پس از تایید فاز ۲ و سیاست‌های باز انجام می‌شود.
      </p>
      <div style="display:flex;flex-wrap:wrap;gap:0.65rem;">
        <a href="#/doctors" class="hc-btn hc-btn--primary">مشاهده دایرکتوری پزشکان (نمونه)</a>
        <a href="#/plans" class="hc-btn hc-btn--secondary">مقایسه طرح‌های تخفیف (تومان)</a>
        <a href="#/panel/user" class="hc-btn hc-btn--secondary">مرور ساختار پنل‌های ۶گانه</a>
      </div>
    </section>

    <section class="hc-section">
      <div class="hc-grid hc-grid--3">
        ${SYNTHETIC_PLANS.map(
          (p) => `
          <article class="hc-card">
            <span class="hc-badge hc-badge--proposed">${escapeHtml(p.badge)}</span>
            <h2 style="margin-top:0.65rem;font-size:1.05rem;">${escapeHtml(p.title)}</h2>
            <p style="font-size:0.875rem;color:var(--hc-text-secondary);min-height:3rem;">${escapeHtml(p.summary)}</p>
            <div style="font-size:1.25rem;font-weight:800;color:var(--hc-brand-primary-strong);margin-block:0.5rem;">
              ${formatToman(p.priceToman)}
            </div>
            <div style="font-size:0.8rem;color:var(--hc-text-secondary);margin-bottom:0.85rem;">
              تخفیف نمونه: ${toPersianDigits(p.discountPercent)}٪ | اعتبار: ${toPersianDigits(p.validityDays)} روز
            </div>
            <button type="button" class="hc-btn hc-btn--secondary" disabled aria-disabled="true" style="width:100%;">
              انتخاب و پرداخت (قفل تا تایید OPEN-18 و فاز ۲)
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
      <div class="hc-card" style="margin-bottom:1rem;">
        <div style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:0.5rem;margin-bottom:0.85rem;">
          <div>
            <h1 style="margin:0;font-size:1.3rem;">دایرکتوری مراکز و پزشکان (داده مصنوعی)</h1>
            <p style="margin:0.25rem 0 0;font-size:0.84rem;color:var(--hc-text-secondary);">فیلتر بر اساس استان، تخصص و متن — بدون مسیریابی لحظه‌ای GPS مطابق بخش ۲.۲ PRD.</p>
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
            ? `<div class="hc-state-box" role="status"><strong>پزشک نمونه‌ای با فیلتر انتخابی یافت نشد.</strong> <button type="button" class="hc-btn hc-btn--secondary" id="hc-clear-doc-filter" style="margin-top:0.6rem;">پاک‌کردن فیلترها</button></div>`
            : `<div class="hc-grid hc-grid--3">
                ${filtered
                  .map(
                    (d) => `
                  <article class="hc-card">
                    <span class="hc-badge hc-badge--ok">تاییدشده نمایشی • ${toPersianDigits(d.discountPercent)}٪ تخفیف</span>
                    <h2 style="margin-top:0.6rem;font-size:1rem;">${escapeHtml(d.clinic)}</h2>
                    <p style="margin:0 0 0.35rem;font-size:0.86rem;color:var(--hc-text-secondary);">${escapeHtml(d.name)}</p>
                    <p style="margin:0 0 0.35rem;font-size:0.82rem;color:var(--hc-text-muted);">استان ${escapeHtml(d.province)} — شهر ${escapeHtml(d.city)} | تاریخ عضویت: ${formatJalaliDate(d.joinedIso)}</p>
                    <button type="button" class="hc-btn hc-btn--secondary" data-select-doctor="${escapeHtml(d.id)}" style="width:100%;margin-top:0.5rem;">مشاهده جزئیات مرکز</button>
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
              <div style="display:flex;justify-content:space-between;align-items:center;gap:0.5rem;">
                <h2 id="hc-doc-detail-heading" tabindex="-1" style="margin:0;font-size:1.1rem;">جزئیات مرکز: ${escapeHtml(detailDoc.clinic)}</h2>
                <button type="button" class="hc-btn hc-btn--secondary" id="hc-close-doc-detail">بستن</button>
              </div>
              <p style="color:var(--hc-text-secondary);margin-top:0.5rem;">تخصص: ${escapeHtml(detailDoc.specialty)} | تخفیف نمونه: ${toPersianDigits(detailDoc.discountPercent)}٪ (قاعده نهایی تابع OPEN-02) | تاریخ عضویت شمسی: ${formatJalaliDate(detailDoc.joinedIso)}</p>
              <button type="button" class="hc-btn hc-btn--primary" disabled aria-disabled="true">ارائه کارت دیجیتال برای این مرکز (موقوف به ورود تاییدشده)</button>
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
      <div style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:0.5rem;margin-bottom:1rem;">
        <h1 style="margin:0;font-size:1.3rem;">مقایسه طرح‌های تخفیف حامی‌کارت (واحد تومان — OPEN-18 PROPOSED)</h1>
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
      <div style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:0.5rem;margin-bottom:0.75rem;">
        <span class="hc-badge hc-badge--info">صفحه محتوایی عمومی (CONTENT-002)</span>
        <span style="font-size:0.82rem;color:var(--hc-text-muted);">آخرین بازنگری (شمسی): ${formatJalaliDate(page.updatedIso)}</span>
      </div>
      <h1 style="font-size:1.35rem;margin-top:0;">${escapeHtml(page.title)}</h1>
      ${page.body.map((para) => `<p style="color:var(--hc-text-secondary);">${escapeHtml(para)}</p>`).join('')}
    </article>
  `;
}

function renderAuthShellView() {
  const overrideState = renderStateBannerIfNeeded('اسکلت صفحات هویت و ورود');
  if (overrideState) return overrideState;

  return `
    <section class="hc-card" style="max-width:560px;margin-inline:auto;">
      <span class="hc-badge hc-badge--proposed">ایزوله — بدون اتصال به سرویس ورود فاز ۲ (T16-AC3)</span>
      <h1 style="margin-top:0.75rem;font-size:1.25rem;">کارت پیش‌نمایش ورود، OTP و بازیابی رمز (UX-006)</h1>
      <p style="font-size:0.875rem;color:var(--hc-text-secondary);">
        این کارت صرفاً ساختار ظاهری و دسترس‌پذیری فرم ورود را نمایش می‌دهد. هیچ رمز نمونه یا کد OTP آزمایشی در صفحه درج نشده و ارسال به اندپوینت‌های احراز هویت تا تایید HC-T13 مسدود است.
      </p>
      <div style="display:grid;gap:0.75rem;margin-block:1rem;">
        <label>
          <span style="display:block;font-size:0.84rem;font-weight:700;margin-bottom:0.25rem;">شماره موبایل (ورودی غیرفعال در محیط ایزوله)</span>
          <input class="hc-input" type="tel" placeholder="۰۹۰۰-۰۰۰-۰۰۰۰ (نمونه غیرواقعی)" disabled />
        </label>
        <div style="display:flex;flex-wrap:wrap;gap:0.5rem;">
          <button type="button" class="hc-btn hc-btn--primary" disabled aria-disabled="true">درخواست کد تایید (غیرفعال تا پذیرش T13)</button>
          <button type="button" class="hc-btn hc-btn--secondary" disabled aria-disabled="true">ورود با رمز / بازیابی (غیرفعال)</button>
        </div>
      </div>
    </section>
  `;
}

function renderRolePanel(roleKey) {
  const cfg = ROLE_SHELL_CONFIGS[roleKey] || ROLE_SHELL_CONFIGS.USER;
  const overrideState = renderStateBannerIfNeeded(cfg.roleTitle);
  if (overrideState) return overrideState;

  return `
    <section class="hc-workspace" aria-label="فضای کاری نقش ${escapeHtml(cfg.roleTitle)}">
      <aside class="hc-sidebar">
        <div style="margin-bottom:0.75rem;">
          <span class="hc-badge hc-badge--info">پنل ساختاری بخش ۲۷</span>
          <h2 style="font-size:1rem;margin:0.5rem 0 0.25rem;">${escapeHtml(cfg.roleTitle)}</h2>
          <p style="font-size:0.78rem;color:var(--hc-text-muted);margin:0;">مسیر مرجع: <code dir="ltr">${escapeHtml(cfg.route)}</code></p>
        </div>
        <ul class="hc-sidebar-list">
          ${cfg.navItems.map((item) => `<li class="hc-sidebar-item">${escapeHtml(item)}</li>`).join('')}
        </ul>
      </aside>

      <div style="display:grid;gap:1rem;min-width:0;">
        <div class="hc-card" style="background:var(--hc-status-warn-bg);border-color:var(--hc-status-warn-border);color:var(--hc-status-warn-fg);">
          <strong>مرز دسترسی و انزوای فاز ۳:</strong> ${escapeHtml(cfg.boundaryNotice)}
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
                <div style="font-size:0.8rem;color:var(--hc-text-secondary);font-weight:600;">${escapeHtml(m.label)}</div>
                <div style="font-size:1.05rem;font-weight:800;margin-top:0.3rem;color:var(--hc-brand-primary-strong);">${renderedVal}</div>
              </div>
            `;
            })
            .join('')}
        </div>

        <div class="hc-card">
          <div style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:0.5rem;margin-bottom:0.85rem;">
            <h2 style="margin:0;font-size:1.05rem;">فهرست نمونه با داده‌های مصنوعی (Synthetic Demo Rows)</h2>
            <span class="hc-badge hc-badge--proposed">تاریخ جلالی و مبالغ نمونه</span>
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
          <div style="margin-top:1rem;">
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

  let html = '';
  if (route === '#/home') {
    html = renderHomeView();
  } else if (route === '#/doctors') {
    html = renderDoctorsView();
  } else if (route === '#/plans') {
    html = renderPlansView();
  } else if (route === '#/auth/shell') {
    html = renderAuthShellView();
  } else if (route.startsWith('#/content/')) {
    const slug = route.replace('#/content/', '');
    html = renderContentPage(slug);
  } else if (route === '#/panel/user') {
    html = renderRolePanel('USER');
  } else if (route === '#/panel/doctor') {
    html = renderRolePanel('DOCTOR');
  } else if (route === '#/panel/agent') {
    html = renderRolePanel('AGENT');
  } else if (route === '#/panel/support') {
    html = renderRolePanel('SUPPORT');
  } else if (route === '#/panel/admin') {
    html = renderRolePanel('ADMIN');
  } else if (route === '#/panel/super-admin') {
    html = renderRolePanel('SUPER_ADMIN');
  } else {
    html = renderHomeView();
  }

  root.innerHTML = html;
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
    render();
    announceStatus(`مسیر صفحه به ${getParsedHash()} تغییر یافت.`);
  });
  render();
}

document.addEventListener('DOMContentLoaded', initShell);
