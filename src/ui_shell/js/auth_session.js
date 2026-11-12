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
let authEpoch = 0;
let logoutBarrierActive = false;
let canRetryLogout = false;

let cachedProfile = null;
let authStatusLabel = 'UNAUTHENTICATED'; // UNAUTHENTICATED | AUTHENTICATED | EXPIRED | REMOTE_REVOKE_FAILED
let lastEventMessage = 'آماده — بدون ذخیره توکن در مرورگر (RAM + HttpOnly Cookie).';
let lastErrorMessage = '';
let stateChangeListener = null;

function drainSyncResolvers(value = null) {
  if (!pendingSyncResolvers.length) return;
  const waiters = pendingSyncResolvers.slice();
  pendingSyncResolvers = [];
  for (let i = 0; i < waiters.length; i += 1) {
    try {
      waiters[i](value);
    } catch {
      // Ignore waiter errors during state scrub
    }
  }
}

function abortActiveControllers() {
  if (activeControllers.size > 0) {
    activeControllers.forEach((ctrl) => ctrl.abort());
    activeControllers.clear();
  }
}

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
    canRetryLogout,
    logoutBarrierActive,
    profile: cachedProfile ? { ...cachedProfile, roles: [...(cachedProfile.roles || [])] } : null,
    lastEventMessage,
    lastErrorMessage,
    sessionVersion,
  };
}

export function clearPrivateState(reasonMessage, options = {}) {
  const {
    broadcastLogout = false,
    statusLabel = 'UNAUTHENTICATED',
    errorText = '',
    logoutBarrier,
    retryableLogout = false,
  } = options;
  authEpoch += 1;
  if (typeof logoutBarrier === 'boolean') {
    logoutBarrierActive = logoutBarrier;
  }
  canRetryLogout = Boolean(retryableLogout);
  accessToken = null;
  accessExpiresAtMs = 0;
  accessTtlMs = 300000;
  cachedProfile = null;
  inFlightRefresh = null;
  authStatusLabel = statusLabel;
  sessionVersion += 1;

  abortActiveControllers();
  drainSyncResolvers(null);

  lastEventMessage = reasonMessage || 'نشست پاک‌سازی شد.';
  lastErrorMessage = errorText;

  if (broadcastLogout && authChannel) {
    authChannel.postMessage({
      type: 'LOGOUT',
      reason: reasonMessage || 'LOGOUT',
      authEpoch,
    });
  }
  notifyChange();
}

function setActiveAccessToken(token, ttlSeconds, sourceNote, options = {}) {
  const { explicitLogin = false } = options;
  if (explicitLogin) {
    logoutBarrierActive = false;
    canRetryLogout = false;
    authEpoch += 1;
  } else if (logoutBarrierActive) {
    return false;
  }
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
  return Boolean(accessToken);
}

async function executeCookieRefreshRequest() {
  if (logoutBarrierActive) {
    return null;
  }
  const csrf = getCookieValue('hc_csrf');
  if (!csrf) {
    clearPrivateState('کوکی CSRF برای تازه‌سازی نشست یافت نشد.', {
      broadcastLogout: false,
      statusLabel: 'EXPIRED',
    });
    return null;
  }

  const startedEpoch = authEpoch;
  const ctrl = new AbortController();
  activeControllers.add(ctrl);
  refreshCallsThisTab += 1;

  let resp;
  try {
    resp = await fetch('/api/v1/auth/refresh', {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      signal: ctrl.signal,
      headers: {
        'X-Auth-Mode': 'cookie',
        'X-CSRF-Token': csrf,
      },
    });
  } catch {
    return null;
  } finally {
    activeControllers.delete(ctrl);
  }

  if (logoutBarrierActive || authEpoch !== startedEpoch) {
    return null;
  }

  if (!resp.ok) {
    let detail = '';
    try {
      const errData = await resp.json();
      detail = errData.detail || '';
    } catch {
      detail = '';
    }
    if (logoutBarrierActive || authEpoch !== startedEpoch) {
      return null;
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

  let data = {};
  try {
    data = await resp.json();
  } catch {
    return null;
  }

  if (logoutBarrierActive || authEpoch !== startedEpoch) {
    return null;
  }

  const applied = setActiveAccessToken(
    data.access_token || null,
    data.expires_in || 300,
    'نشست از طریق کوکی HttpOnly در حافظه RAM تازه‌سازی شد.'
  );
  if (!applied || logoutBarrierActive || authEpoch !== startedEpoch) {
    return null;
  }

  if (authChannel && accessToken) {
    authChannel.postMessage({
      type: 'TOKEN_REFRESHED',
      accessToken,
      accessExpiresAtMs,
      accessTtlMs,
      explicitLogin: false,
      authEpoch,
    });
    await delay(30);
  }

  if (logoutBarrierActive || authEpoch !== startedEpoch) {
    return null;
  }

  await hydrateProfileInternal(startedEpoch);
  if (!logoutBarrierActive && authEpoch === startedEpoch) {
    notifyChange();
  }
  return accessToken;
}

export async function refreshSessionCoordinated(options = {}) {
  if (logoutBarrierActive) {
    return null;
  }
  const opts = typeof options === 'boolean' ? { force: options } : options || {};
  const forceRefresh = Boolean(opts.force);
  const failedToken = opts.failedToken || null;
  const startedAt = Date.now();
  const startedEpoch = authEpoch;

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
          if (logoutBarrierActive || authEpoch !== startedEpoch) {
            return null;
          }
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
            if (logoutBarrierActive || authEpoch !== startedEpoch) {
              return null;
            }
            if (synced) {
              await hydrateProfileInternal(authEpoch);
              if (!logoutBarrierActive && accessToken) {
                notifyChange();
              }
              return synced;
            }
          }
          if (logoutBarrierActive || authEpoch !== startedEpoch) {
            return null;
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
  if (logoutBarrierActive) {
    throw new Error('UNAUTHENTICATED');
  }
  const startedEpoch = authEpoch;
  let token = hasFreshAccessToken() ? accessToken : await refreshSessionCoordinated({ force: false });
  if (!token || logoutBarrierActive || authEpoch !== startedEpoch) {
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

    if (logoutBarrierActive || authEpoch !== startedEpoch) {
      return resp;
    }

    if (resp.status === 401) {
      const retriedToken = await refreshSessionCoordinated({ force: true, failedToken: token });
      if (logoutBarrierActive || authEpoch !== startedEpoch) {
        return resp;
      }
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
      if (logoutBarrierActive || authEpoch !== startedEpoch) {
        return resp;
      }
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

async function hydrateProfileInternal(expectedEpoch = authEpoch) {
  if (logoutBarrierActive || !accessToken || authEpoch !== expectedEpoch) {
    if (logoutBarrierActive || !accessToken) {
      cachedProfile = null;
    }
    return null;
  }
  const ctrl = new AbortController();
  activeControllers.add(ctrl);
  try {
    const resp = await fetch('/api/v1/profile/me', {
      method: 'GET',
      credentials: 'same-origin',
      cache: 'no-store',
      signal: ctrl.signal,
      headers: {
        Authorization: `${AUTH_HEADER_SCHEME} ${accessToken}`,
      },
    });
    if (logoutBarrierActive || authEpoch !== expectedEpoch || !accessToken) {
      return null;
    }
    if (resp.ok) {
      const data = await resp.json();
      if (logoutBarrierActive || authEpoch !== expectedEpoch || !accessToken) {
        return null;
      }
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
    // Profile hydration errors or aborts leave state untouched cleanly
  } finally {
    activeControllers.delete(ctrl);
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

  const applied = setActiveAccessToken(
    data.access_token || null,
    data.expires_in || 300,
    'ورود با کد OTP در حالت کوکی HttpOnly انجام شد.',
    { explicitLogin: true }
  );
  const loginEpoch = authEpoch;
  if (applied && authChannel && accessToken) {
    authChannel.postMessage({
      type: 'TOKEN_REFRESHED',
      accessToken,
      accessExpiresAtMs,
      accessTtlMs,
      explicitLogin: true,
      authEpoch: loginEpoch,
    });
  }
  await hydrateProfileInternal(loginEpoch);
  if (!logoutBarrierActive && authEpoch === loginEpoch) {
    notifyChange();
  }
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

  const applied = setActiveAccessToken(
    data.access_token || null,
    data.expires_in || 300,
    'ورود با رمز عبور در حالت کوکی HttpOnly انجام شد.',
    { explicitLogin: true }
  );
  const loginEpoch = authEpoch;
  if (applied && authChannel && accessToken) {
    authChannel.postMessage({
      type: 'TOKEN_REFRESHED',
      accessToken,
      accessExpiresAtMs,
      accessTtlMs,
      explicitLogin: true,
      authEpoch: loginEpoch,
    });
  }
  await hydrateProfileInternal(loginEpoch);
  if (!logoutBarrierActive && authEpoch === loginEpoch) {
    notifyChange();
  }
  return { ok: true, status: resp.status, data };
}

export async function fetchMyProfile() {
  const startedEpoch = authEpoch;
  let resp;
  try {
    resp = await authenticatedFetch('/api/v1/profile/me');
  } catch (err) {
    if (logoutBarrierActive || authEpoch !== startedEpoch) {
      return { ok: false, status: 0, data: {} };
    }
    throw err;
  }
  if (logoutBarrierActive || authEpoch !== startedEpoch || !accessToken) {
    return { ok: false, status: resp.status, data: {} };
  }
  let data = {};
  try {
    data = await resp.json();
  } catch {
    data = {};
  }
  if (logoutBarrierActive || authEpoch !== startedEpoch || !accessToken) {
    return { ok: false, status: resp.status, data };
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
  const bearerSnapshot = accessToken;
  const headers = {
    'X-Auth-Mode': 'cookie',
    'X-CSRF-Token': csrf,
  };
  if (bearerSnapshot) {
    headers.Authorization = `${AUTH_HEADER_SCHEME} ${bearerSnapshot}`;
  }

  // Engage pre-logout barrier immediately so concurrent in-flight refreshes, profile
  // hydrations, or cross-tab BroadcastChannel syncs cannot resurrect auth state while
  // POST /api/v1/auth/logout is in flight or after local scrub.
  logoutBarrierActive = true;
  canRetryLogout = false;
  authEpoch += 1;
  const logoutEpoch = authEpoch;
  accessToken = null;
  accessExpiresAtMs = 0;
  accessTtlMs = 300000;
  cachedProfile = null;
  inFlightRefresh = null;
  abortActiveControllers();
  drainSyncResolvers(null);

  let status = 0;
  let detail = '';
  let revokedOnServer = false;
  try {
    const resp = await fetch('/api/v1/auth/logout', {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers,
    });
    status = resp.status;
    revokedOnServer = Boolean(resp.ok);
    if (!revokedOnServer) {
      try {
        const errData = await resp.json();
        detail = errData.detail || '';
      } catch {
        detail = '';
      }
    }
  } catch {
    status = 0;
    revokedOnServer = false;
  }

  if (authEpoch !== logoutEpoch) {
    return {
      ok: false,
      revokedOnServer: false,
      canRetryLogout: false,
      status,
      detail: detail || 'Superseded by newer authentication state.',
    };
  }

  if (revokedOnServer) {
    clearPrivateState(`خروج امن از نشست با تأیید سرور انجام شد (HTTP ${status}).`, {
      broadcastLogout: true,
      logoutBarrier: true,
      retryableLogout: false,
      statusLabel: 'UNAUTHENTICATED',
      errorText: '',
    });
    return { ok: true, revokedOnServer: true, canRetryLogout: false, status, detail: '' };
  }

  const credsStillPresent = Boolean(getCookieValue('hc_csrf')) && hasSessionHintCookie();
  const errCodeText = status ? `HTTP ${status}` : 'خطای شبکه';

  if (!credsStillPresent && status === 401) {
    clearPrivateState(`نشست پیش‌تر منقضی شده و کوکی‌های مرورگر پاک شدند (${errCodeText}).`, {
      broadcastLogout: true,
      logoutBarrier: true,
      retryableLogout: false,
      statusLabel: 'EXPIRED',
      errorText: detail,
    });
    return { ok: false, revokedOnServer: false, canRetryLogout: false, status, detail };
  }

  const retryable = Boolean(credsStillPresent);
  const reasonMessage = retryable
    ? `هشدار: خروج محلی انجام شد اما لغو نشست روی سرور تأیید نشد (${errCodeText}).`
    : `هشدار: کوکی‌های مرورگر و نشست دیتابیس پاک شدند اما لغو فوری کش سروری تأیید نشد (${errCodeText}).`;
  const errorText = retryable
    ? `لغو نشست روی سرور تأیید نشد (${errCodeText}${detail ? ` - ${detail}` : ''}). نشست سروری ممکن است هنوز فعال باشد؛ لطفاً دوباره خروج سروری را بزنید.`
    : `سرور کوکی‌های نشست مرورگر را پاک کرد اما تأیید فوری سرویس ابطال در دسترس نبود (${errCodeText}${detail ? ` - ${detail}` : ''}). به دلیل پاک‌شدن کوکی‌ها امکان ارسال مجدد درخواست خروج وجود ندارد؛ در صورت نیاز دوباره وارد شوید.`;

  clearPrivateState(reasonMessage, {
    broadcastLogout: false,
    logoutBarrier: true,
    retryableLogout: retryable,
    statusLabel: 'REMOTE_REVOKE_FAILED',
    errorText,
  });
  if (authChannel) {
    authChannel.postMessage({
      type: 'LOGOUT_FAILED_LOCAL_SCRUB',
      status,
      canRetryLogout: retryable,
      reason: reasonMessage,
      errorText,
      authEpoch,
    });
  }
  return { ok: false, revokedOnServer: false, canRetryLogout: retryable, status, detail };
}

export function initAuthLifecycle(onStateChange) {
  stateChangeListener = onStateChange;

  if (authChannel) {
    authChannel.onmessage = (event) => {
      const msg = event.data || {};
      if (msg.type === 'TOKEN_REFRESHED' && msg.accessToken) {
        const isExplicit = Boolean(msg.explicitLogin);
        if (logoutBarrierActive && !isExplicit) {
          return;
        }
        const applied = setActiveAccessToken(
          msg.accessToken,
          Math.max(1, Math.round(Number(msg.accessTtlMs || accessTtlMs || 300000) / 1000)),
          'توکن کوتاه‌عمر از طریق BroadcastChannel همگام‌سازی شد.',
          { explicitLogin: isExplicit }
        );
        if (!applied) {
          return;
        }
        accessTtlMs = Number(msg.accessTtlMs || accessTtlMs || 300000);
        accessExpiresAtMs = Number(msg.accessExpiresAtMs || Date.now() + accessTtlMs);
        const syncEpoch = authEpoch;
        drainSyncResolvers(accessToken);
        hydrateProfileInternal(syncEpoch).finally(() => {
          if (!logoutBarrierActive && authEpoch === syncEpoch) {
            notifyChange();
          }
        });
      } else if (msg.type === 'REQUEST_SYNC') {
        if (!logoutBarrierActive && hasFreshAccessToken()) {
          authChannel.postMessage({
            type: 'TOKEN_REFRESHED',
            accessToken,
            accessExpiresAtMs,
            accessTtlMs,
            explicitLogin: false,
            authEpoch,
          });
        }
      } else if (msg.type === 'LOGOUT') {
        clearPrivateState('خروج هم‌زمان از تب دیگر دریافت و اعمال شد.', {
          broadcastLogout: false,
          logoutBarrier: true,
          retryableLogout: false,
          statusLabel: 'UNAUTHENTICATED',
        });
      } else if (msg.type === 'LOGOUT_FAILED_LOCAL_SCRUB') {
        clearPrivateState(
          msg.reason || 'هشدار: خروج هم‌زمان در تب دیگر روی سرور تأیید نشد؛ حافظه محلی پاک‌سازی شد.',
          {
            broadcastLogout: false,
            logoutBarrier: true,
            retryableLogout: Boolean(msg.canRetryLogout),
            statusLabel: 'REMOTE_REVOKE_FAILED',
            errorText: msg.errorText || '',
          }
        );
      }
    };
  }

  window.addEventListener('pageshow', (event) => {
    if (event.persisted) {
      const hasCookieHint = hasSessionHintCookie();
      clearPrivateState('بازیابی از BFCache شناسایی و حافظه نشست پاک‌سازی شد.', {
        broadcastLogout: false,
        logoutBarrier: !hasCookieHint,
        retryableLogout: false,
        statusLabel: 'UNAUTHENTICATED',
      });
      if (hasCookieHint) {
        refreshSessionCoordinated({ force: true }).catch(() => {});
      }
    }
  });

  if (hasSessionHintCookie()) {
    refreshSessionCoordinated({ force: false }).catch(() => {});
  }
}

