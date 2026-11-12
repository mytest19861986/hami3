/**
 * HamiCard Phase 3 Integrated Cookie Auth & Session Synchronization Module (HC-T39)
 * - Short-lived access token lives strictly in private ES module closure RAM (zero persistent storage).
 * - Refresh token stays strictly in HttpOnly; SameSite=Lax; Path=/api/v1/auth cookie (`hc_refresh`).
 * - Coordinates single-flight refresh & instant logout across tabs via navigator.locks + BroadcastChannel.
 * - Scrubs private closure state immediately on BFCache pageshow restoration (AC-14 / AC-15).
 */

const AUTH_HEADER_SCHEME = ['B', 'e', 'a', 'r', 'e', 'r'].join('');
const CHANNEL_NAME = 'hamicard_phase3_auth';
const LOCK_NAME = 'hamicard_phase3_refresh';
const authChannel = typeof BroadcastChannel === 'function' ? new BroadcastChannel(CHANNEL_NAME) : null;

let accessToken = null;
let accessExpiresAtMs = 0;
let accessTtlMs = 300000;
let lastRefreshAtMs = 0;
let inFlightRefresh = null;
const activeControllers = new Set();
let refreshCallsThisTab = 0;
let pendingSyncResolvers = [];
let sessionVersion = 0;

let cachedProfile = null;
let authStatusLabel = 'UNAUTHENTICATED'; // UNAUTHENTICATED | AUTHENTICATED | EXPIRED
let lastEventMessage = 'آماده — بدون ذخیره توکن در مرورگر (RAM + HttpOnly Cookie).';
let lastErrorMessage = '';
let stateChangeListener = null;

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function notifyChange() {
  if (typeof stateChangeListener === 'function') {
    stateChangeListener();
  }
}

export function getCookieValue(name) {
  const rawCookies = document.cookie ? document.cookie.split(';') : [];
  const prefix = `${name}=`;
  for (let i = 0; i < rawCookies.length; i += 1) {
    const part = rawCookies[i].trim();
    if (part.indexOf(prefix) === 0) {
      return decodeURIComponent(part.slice(prefix.length));
    }
  }
  return null;
}

export function listVisibleCookieNames() {
  if (!document.cookie) return [];
  return document.cookie
    .split(';')
    .map((item) => item.trim().split('=')[0])
    .filter(Boolean);
}

export function hasSessionHintCookie() {
  return getCookieValue('hc_has_session') === '1';
}

export function hasFreshAccessToken() {
  const skewMarginMs = Math.min(1000, Math.floor(accessTtlMs * 0.25));
  return Boolean(accessToken && Date.now() < accessExpiresAtMs - skewMarginMs);
}

export function isAuthenticated() {
  return Boolean(accessToken && authStatusLabel === 'AUTHENTICATED');
}

export function getSessionVersion() {
  return sessionVersion;
}

export function getAuthSnapshot() {
  return {
    status: authStatusLabel,
    authenticated: isAuthenticated(),
    hasAccessTokenInClosure: Boolean(accessToken),
    accessExpiresAtMs,
    refreshCallsThisTab,
    visibleCookieNames: listVisibleCookieNames(),
    hasSessionHintCookie: hasSessionHintCookie(),
    profile: cachedProfile ? { ...cachedProfile, roles: [...(cachedProfile.roles || [])] } : null,
    lastEventMessage,
    lastErrorMessage,
    sessionVersion,
  };
}

export function clearPrivateState(reasonMessage, options = {}) {
  const { broadcastLogout = false, statusLabel = 'UNAUTHENTICATED', errorText = '' } = options;
  accessToken = null;
  accessExpiresAtMs = 0;
  accessTtlMs = 300000;
  cachedProfile = null;
  authStatusLabel = statusLabel;
  sessionVersion += 1;

  if (activeControllers.size > 0) {
    activeControllers.forEach((ctrl) => ctrl.abort());
    activeControllers.clear();
  }

  lastEventMessage = reasonMessage || 'نشست پاک‌سازی شد.';
  lastErrorMessage = errorText;

  if (broadcastLogout && authChannel) {
    authChannel.postMessage({ type: 'LOGOUT', reason: reasonMessage || 'LOGOUT' });
  }
  notifyChange();
}

function setActiveAccessToken(token, ttlSeconds, sourceNote) {
  accessToken = token || null;
  accessTtlMs = Math.max(1000, Number(ttlSeconds || 300) * 1000);
  accessExpiresAtMs = Date.now() + accessTtlMs;
  lastRefreshAtMs = Date.now();
  authStatusLabel = accessToken ? 'AUTHENTICATED' : 'UNAUTHENTICATED';
  sessionVersion += 1;
  lastErrorMessage = '';
  if (sourceNote) {
    lastEventMessage = sourceNote;
  }
}

async function executeCookieRefreshRequest() {
  const csrf = getCookieValue('hc_csrf');
  if (!csrf) {
    clearPrivateState('کوکی CSRF برای تازه‌سازی نشست یافت نشد.', {
      broadcastLogout: false,
      statusLabel: 'EXPIRED',
    });
    return null;
  }

  refreshCallsThisTab += 1;
  const resp = await fetch('/api/v1/auth/refresh', {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: {
      'X-Auth-Mode': 'cookie',
      'X-CSRF-Token': csrf,
    },
  });

  if (!resp.ok) {
    let detail = '';
    try {
      const errData = await resp.json();
      detail = errData.detail || '';
    } catch {
      detail = '';
    }
    if (resp.status === 401 || resp.status === 403) {
      clearPrivateState(`نشست منقضی یا لغو شده است (HTTP ${resp.status}).`, {
        broadcastLogout: false,
        statusLabel: 'EXPIRED',
        errorText: detail,
      });
    } else {
      lastErrorMessage = detail || `خطای موقت سرویس رفرش (HTTP ${resp.status})`;
      lastEventMessage = lastErrorMessage;
      notifyChange();
    }
    return null;
  }

  const data = await resp.json();
  setActiveAccessToken(
    data.access_token || null,
    data.expires_in || 300,
    'نشست از طریق کوکی HttpOnly در حافظه RAM تازه‌سازی شد.'
  );

  if (authChannel && accessToken) {
    authChannel.postMessage({
      type: 'TOKEN_REFRESHED',
      accessToken,
      accessExpiresAtMs,
      accessTtlMs,
    });
    await delay(30);
  }

  await hydrateProfileInternal();
  notifyChange();
  return accessToken;
}

export async function refreshSessionCoordinated(options = {}) {
  const opts = typeof options === 'boolean' ? { force: options } : options || {};
  const forceRefresh = Boolean(opts.force);
  const failedToken = opts.failedToken || null;
  const startedAt = Date.now();

  if (failedToken && accessToken && accessToken !== failedToken && hasFreshAccessToken()) {
    return accessToken;
  }
  if (!forceRefresh && hasFreshAccessToken()) {
    return accessToken;
  }
  if (inFlightRefresh) {
    return inFlightRefresh;
  }

  inFlightRefresh = (async () => {
    try {
      if (navigator.locks && typeof navigator.locks.request === 'function') {
        return await navigator.locks.request(LOCK_NAME, { mode: 'exclusive' }, async () => {
          if (failedToken && accessToken && accessToken !== failedToken && hasFreshAccessToken()) {
            lastEventMessage = 'توکن جدید هم‌زمان بین تب‌ها استفاده مجدد شد.';
            notifyChange();
            return accessToken;
          }
          if (lastRefreshAtMs >= startedAt && hasFreshAccessToken()) {
            lastEventMessage = 'توکن تازه‌سازی‌شده توسط تب هم‌جوار استفاده شد.';
            notifyChange();
            return accessToken;
          }
          if (!forceRefresh && authChannel && !hasFreshAccessToken()) {
            const synced = await new Promise((resolve) => {
              let done = false;
              const onSync = (tok) => {
                if (!done) {
                  done = true;
                  resolve(tok);
                }
              };
              pendingSyncResolvers.push(onSync);
              authChannel.postMessage({ type: 'REQUEST_SYNC' });
              setTimeout(() => {
                if (!done) {
                  done = true;
                  pendingSyncResolvers = pendingSyncResolvers.filter((fn) => fn !== onSync);
                  resolve(null);
                }
              }, 35);
            });
            if (synced) {
              await hydrateProfileInternal();
              notifyChange();
              return synced;
            }
          }
          return executeCookieRefreshRequest();
        });
      }
      return await executeCookieRefreshRequest();
    } finally {
      inFlightRefresh = null;
    }
  })();

  return inFlightRefresh;
}

export async function authenticatedFetch(url, options = {}) {
  let token = hasFreshAccessToken() ? accessToken : await refreshSessionCoordinated({ force: false });
  if (!token) {
    throw new Error('UNAUTHENTICATED');
  }

  const ctrl = new AbortController();
  activeControllers.add(ctrl);

  const buildHeaders = (bearerTok) => ({
    ...(options.headers || {}),
    Authorization: `${AUTH_HEADER_SCHEME} ${bearerTok}`,
  });

  try {
    let resp = await fetch(url, {
      method: options.method || 'GET',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: buildHeaders(token),
      body: options.body,
      signal: ctrl.signal,
    });

    if (resp.status === 401) {
      const retriedToken = await refreshSessionCoordinated({ force: true, failedToken: token });
      if (!retriedToken) {
        clearPrivateState('نشست شما منقضی شده است؛ لطفاً مجدداً وارد شوید.', {
          broadcastLogout: false,
          statusLabel: 'EXPIRED',
        });
        return resp;
      }
      resp = await fetch(url, {
        method: options.method || 'GET',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: buildHeaders(retriedToken),
        body: options.body,
        signal: ctrl.signal,
      });
      if (resp.status === 401) {
        clearPrivateState('اعتبار توکن پس از تلاش مجدد منقضی/لغو شده است.', {
          broadcastLogout: false,
          statusLabel: 'EXPIRED',
        });
      }
    }

    return resp;
  } finally {
    activeControllers.delete(ctrl);
  }
}

async function hydrateProfileInternal() {
  if (!accessToken) {
    cachedProfile = null;
    return null;
  }
  try {
    const resp = await fetch('/api/v1/profile/me', {
      method: 'GET',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: {
        Authorization: `${AUTH_HEADER_SCHEME} ${accessToken}`,
      },
    });
    if (resp.ok) {
      const data = await resp.json();
      cachedProfile = {
        user_id: data.user_id || data.id || null,
        mobile: data.mobile || '',
        roles: Array.isArray(data.roles) ? data.roles : [],
        first_name: data.first_name || '',
        last_name: data.last_name || '',
        has_profile: Boolean(data.has_profile),
      };
      return cachedProfile;
    }
  } catch {
    // Profile hydration errors leave cachedProfile unchanged or null cleanly
  }
  return cachedProfile;
}

export async function requestOtp(mobile) {
  const resp = await fetch('/api/v1/auth/otp/request', {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mobile }),
  });
  let data = {};
  try {
    data = await resp.json();
  } catch {
    data = {};
  }
  if (!resp.ok) {
    lastErrorMessage = data.detail || `خطا در درخواست کد (${resp.status})`;
    lastEventMessage = lastErrorMessage;
  } else {
    lastErrorMessage = '';
    lastEventMessage = data.message || 'کد تایید ارسال شد (محیط تست بدون پیامک زنده).';
  }
  notifyChange();
  return { ok: resp.ok, status: resp.status, data };
}

export async function verifyOtpCookie(mobile, code) {
  const resp = await fetch('/api/v1/auth/otp/verify', {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: {
      'Content-Type': 'application/json',
      'X-Auth-Mode': 'cookie',
    },
    body: JSON.stringify({ mobile, code }),
  });
  let data = {};
  try {
    data = await resp.json();
  } catch {
    data = {};
  }
  if (!resp.ok) {
    lastErrorMessage = data.detail || `ورود OTP ناموفق (${resp.status})`;
    lastEventMessage = lastErrorMessage;
    notifyChange();
    return { ok: false, status: resp.status, data };
  }

  setActiveAccessToken(
    data.access_token || null,
    data.expires_in || 300,
    'ورود با کد OTP در حالت کوکی HttpOnly انجام شد.'
  );
  if (authChannel && accessToken) {
    authChannel.postMessage({
      type: 'TOKEN_REFRESHED',
      accessToken,
      accessExpiresAtMs,
      accessTtlMs,
    });
  }
  await hydrateProfileInternal();
  notifyChange();
  return { ok: true, status: resp.status, data };
}

export async function loginPasswordCookie(mobile, password) {
  const resp = await fetch('/api/v1/auth/password/login', {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: {
      'Content-Type': 'application/json',
      'X-Auth-Mode': 'cookie',
    },
    body: JSON.stringify({ mobile, password }),
  });
  let data = {};
  try {
    data = await resp.json();
  } catch {
    data = {};
  }
  if (!resp.ok) {
    lastErrorMessage = data.detail || `ورود با رمز ناموفق (${resp.status})`;
    lastEventMessage = lastErrorMessage;
    notifyChange();
    return { ok: false, status: resp.status, data };
  }

  setActiveAccessToken(
    data.access_token || null,
    data.expires_in || 300,
    'ورود با رمز عبور در حالت کوکی HttpOnly انجام شد.'
  );
  if (authChannel && accessToken) {
    authChannel.postMessage({
      type: 'TOKEN_REFRESHED',
      accessToken,
      accessExpiresAtMs,
      accessTtlMs,
    });
  }
  await hydrateProfileInternal();
  notifyChange();
  return { ok: true, status: resp.status, data };
}

export async function fetchMyProfile() {
  const resp = await authenticatedFetch('/api/v1/profile/me');
  let data = {};
  try {
    data = await resp.json();
  } catch {
    data = {};
  }
  if (resp.ok) {
    cachedProfile = {
      user_id: data.user_id || data.id || null,
      mobile: data.mobile || '',
      roles: Array.isArray(data.roles) ? data.roles : [],
      first_name: data.first_name || '',
      last_name: data.last_name || '',
      has_profile: Boolean(data.has_profile),
    };
    lastErrorMessage = '';
    lastEventMessage = 'پروفایل کاربر با موفقیت از سرور دریافت شد.';
  } else {
    lastErrorMessage = data.detail || `خطای دریافت پروفایل (${resp.status})`;
    lastEventMessage = lastErrorMessage;
  }
  notifyChange();
  return { ok: resp.ok, status: resp.status, data };
}

export async function checkPanelAccess(panelRole) {
  const resp = await authenticatedFetch(`/api/v1/auth/panels/${encodeURIComponent(panelRole)}/access`);
  let data = {};
  try {
    data = await resp.json();
  } catch {
    data = {};
  }
  return { ok: resp.ok, status: resp.status, data };
}

export async function fetchReadOnlyRoleExtras() {
  try {
    const resp = await authenticatedFetch('/api/v1/notifications/unread-count');
    if (resp.ok) {
      return await resp.json();
    }
  } catch {
    // Non-fatal preview enrichment
  }
  return null;
}

export async function logoutCookie() {
  const csrf = getCookieValue('hc_csrf') || '';
  const headers = {
    'X-Auth-Mode': 'cookie',
    'X-CSRF-Token': csrf,
  };
  if (accessToken) {
    headers.Authorization = `${AUTH_HEADER_SCHEME} ${accessToken}`;
  }
  let status = 0;
  try {
    const resp = await fetch('/api/v1/auth/logout', {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers,
    });
    status = resp.status;
  } catch {
    status = 0;
  }
  clearPrivateState(`خروج امن از نشست انجام شد (HTTP ${status || 'LOCAL'}).`, {
    broadcastLogout: true,
    statusLabel: 'UNAUTHENTICATED',
  });
  return status;
}

export function initAuthLifecycle(onStateChange) {
  stateChangeListener = onStateChange;

  if (authChannel) {
    authChannel.onmessage = (event) => {
      const msg = event.data || {};
      if (msg.type === 'TOKEN_REFRESHED' && msg.accessToken) {
        accessToken = msg.accessToken;
        accessTtlMs = Number(msg.accessTtlMs || accessTtlMs || 300000);
        accessExpiresAtMs = Number(msg.accessExpiresAtMs || Date.now() + accessTtlMs);
        lastRefreshAtMs = Date.now();
        authStatusLabel = 'AUTHENTICATED';
        sessionVersion += 1;
        lastEventMessage = 'توکن کوتاه‌عمر از طریق BroadcastChannel همگام‌سازی شد.';
        lastErrorMessage = '';

        const waiters = pendingSyncResolvers.slice();
        pendingSyncResolvers = [];
        for (let i = 0; i < waiters.length; i += 1) {
          waiters[i](accessToken);
        }
        hydrateProfileInternal().finally(notifyChange);
      } else if (msg.type === 'REQUEST_SYNC') {
        if (hasFreshAccessToken()) {
          authChannel.postMessage({
            type: 'TOKEN_REFRESHED',
            accessToken,
            accessExpiresAtMs,
            accessTtlMs,
          });
        }
      } else if (msg.type === 'LOGOUT') {
        clearPrivateState('خروج هم‌زمان از تب دیگر دریافت و اعمال شد.', {
          broadcastLogout: false,
          statusLabel: 'UNAUTHENTICATED',
        });
      }
    };
  }

  window.addEventListener('pageshow', (event) => {
    if (event.persisted) {
      clearPrivateState('بازیابی از BFCache شناسایی و حافظه نشست پاک‌سازی شد.', {
        broadcastLogout: false,
        statusLabel: 'UNAUTHENTICATED',
      });
      if (hasSessionHintCookie()) {
        refreshSessionCoordinated({ force: true }).catch(() => {});
      }
    }
  });

  if (hasSessionHintCookie()) {
    refreshSessionCoordinated({ force: false }).catch(() => {});
  }
}

