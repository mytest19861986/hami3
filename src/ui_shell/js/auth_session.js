/**
 * HamiCard Phase 3 Integrated Cookie Auth & Session Synchronization Module (HC-T49)
 * - Short-lived access token lives strictly in private ES module closure RAM (zero persistent storage).
 * - Refresh credential stays strictly in HttpOnly; SameSite=Lax; Path=/api/v1/auth cookie (`hc_refresh`).
 * - Coordinates single-flight refresh, monotonic login/logout causal ordering, and instant logout
 *   across tabs via navigator.locks + BroadcastChannel + non-secret monotonic `hc_coord` cookie.
 * - Scrubs private closure state immediately on logout initiation and BFCache pageshow (AC-14 / AC-15).
 */

const AUTH_HEADER_SCHEME = ['B', 'e', 'a', 'r', 'e', 'r'].join('');
const CHANNEL_NAME = 'hamicard_phase3_auth';
const LOCK_NAME = 'hamicard_phase3_refresh';
const COORD_LOCK_NAME = 'hamicard_phase3_coord';
const COORD_COOKIE_NAME = 'hc_coord';
const COORD_COOKIE_MAX_AGE_SECONDS = 86400;
const MAX_CANCEL_BATCH = 16;
const MAX_PENDING_LOGIN_ATTEMPTS = 64;
const authChannel = typeof BroadcastChannel === 'function' ? new BroadcastChannel(CHANNEL_NAME) : null;

let accessToken = null;
let accessExpiresAtMs = 0;
let accessTtlMs = 300000;
let lastRefreshAtMs = 0;
let inFlightRefresh = null;
const activeControllers = new Set();
const pendingLoginAttempts = new Set();
const cancelledAttemptIds = new Set();

let refreshCallsThisTab = 0;
let pendingSyncResolvers = [];
let sessionVersion = 0;
let authEpoch = 0;
let logoutBarrierActive = false;
let canRetryLogout = false;

let localCoordGlobalSeq = 0;
let localCoordLogoutSeq = 0;
let localCoordLoginSeq = 0;
let localCoordLogoutPendingSeq = 0;
let serverGlobalSeq = 0;
let serverLogoutSeq = 0;
let serverLoginSeq = 0;
let activeSessionLoginSeq = 0;
let activeSessionFamilyId = null;
let coordInitPromise = null;
let inFlightLogoutPromise = null;

let cachedProfile = null;
let authStatusLabel = 'UNAUTHENTICATED'; // UNAUTHENTICATED | LOGOUT_PENDING | AUTHENTICATED | EXPIRED | REMOTE_REVOKE_FAILED
let lastEventMessage = 'آماده — بدون ذخیره توکن در مرورگر (RAM + HttpOnly Cookie).';
let lastErrorMessage = '';
let stateChangeListener = null;

function generateAttemptId() {
  if (typeof crypto !== 'undefined') {
    if (typeof crypto.randomUUID === 'function') {
      return `hc_${crypto.randomUUID()}`;
    }
    if (typeof crypto.getRandomValues === 'function') {
      const bytes = new Uint8Array(16);
      crypto.getRandomValues(bytes);
      const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
      return `hc_${hex}`;
    }
  }
  return `hc_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 12)}`;
}

function parseCoordCookie(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const match =
    /^g\.(\d+)\.lo\.(\d+)\.li\.(\d+)(?:\.sg\.(\d+)\.slo\.(\d+)\.sli\.(\d+))?(?:\.lp\.(\d+))?$/.exec(
      raw.trim()
    );
  if (!match) return null;
  return {
    g: Number(match[1]) || 0,
    lo: Number(match[2]) || 0,
    li: Number(match[3]) || 0,
    sg: Number(match[4]) || 0,
    slo: Number(match[5]) || 0,
    sli: Number(match[6]) || 0,
    lp: Number(match[7]) || 0,
  };
}

function writeCoordCookie() {
  if (typeof document === 'undefined') return;
  const secureFlag =
    typeof window !== 'undefined' && window.location && window.location.protocol === 'https:'
      ? '; Secure'
      : '';
  const val = `g.${localCoordGlobalSeq}.lo.${localCoordLogoutSeq}.li.${localCoordLoginSeq}.sg.${serverGlobalSeq}.slo.${serverLogoutSeq}.sli.${serverLoginSeq}.lp.${localCoordLogoutPendingSeq}`;
  document.cookie = `${COORD_COOKIE_NAME}=${val}; Path=/; Max-Age=${COORD_COOKIE_MAX_AGE_SECONDS}; SameSite=Lax${secureFlag}`;
}

function syncCoordFromCookie() {
  const parsed = parseCoordCookie(getCookieValue(COORD_COOKIE_NAME));
  if (parsed) {
    if (parsed.g > localCoordGlobalSeq) {
      localCoordGlobalSeq = parsed.g;
      localCoordLogoutPendingSeq = parsed.lp || 0;
    } else if (parsed.g === localCoordGlobalSeq) {
      if (parsed.lp > localCoordLogoutPendingSeq) {
        localCoordLogoutPendingSeq = parsed.lp;
      } else if (parsed.lp === 0 && parsed.g >= localCoordLogoutPendingSeq) {
        localCoordLogoutPendingSeq = 0;
      }
    }
    if (parsed.lo > localCoordLogoutSeq) localCoordLogoutSeq = parsed.lo;
    if (parsed.li > localCoordLoginSeq) localCoordLoginSeq = parsed.li;
    if (parsed.sg > serverGlobalSeq) serverGlobalSeq = parsed.sg;
    if (parsed.slo > serverLogoutSeq) serverLogoutSeq = parsed.slo;
    if (parsed.sli > serverLoginSeq) serverLoginSeq = parsed.sli;
  }
  return {
    g: localCoordGlobalSeq,
    lo: localCoordLogoutSeq,
    li: localCoordLoginSeq,
    sg: serverGlobalSeq,
    slo: serverLogoutSeq,
    sli: serverLoginSeq,
    lp: localCoordLogoutPendingSeq,
  };
}

function syncServerCoord(serverCoord) {
  if (!serverCoord || typeof serverCoord !== 'object') return false;
  syncCoordFromCookie();
  const sg = Number(serverCoord.global_seq || 0);
  const slo = Number(serverCoord.logout_seq || 0);
  const sli = Number(serverCoord.login_seq || 0);
  let changed = false;
  if (Number.isFinite(sg) && sg > serverGlobalSeq) {
    serverGlobalSeq = sg;
    changed = true;
  }
  if (Number.isFinite(slo) && slo > serverLogoutSeq) {
    serverLogoutSeq = slo;
    changed = true;
  }
  if (Number.isFinite(sli) && sli > serverLoginSeq) {
    serverLoginSeq = sli;
    changed = true;
  }
  if (changed) {
    writeCoordCookie();
  }
  return changed;
}

function syncCoordFromSeq(seq, kind, serverCoord = null) {
  const n = Number(seq || 0);
  syncCoordFromCookie();
  let changed = false;
  if (Number.isFinite(n) && n > 0) {
    if (n > localCoordGlobalSeq) {
      localCoordGlobalSeq = n;
      changed = true;
    }
    if (kind === 'logout' && n > localCoordLogoutSeq) {
      localCoordLogoutSeq = n;
      changed = true;
    }
    if (kind === 'login' && n > localCoordLoginSeq) {
      localCoordLoginSeq = n;
      changed = true;
    }
  }
  if (serverCoord && typeof serverCoord === 'object') {
    const sg = Number(serverCoord.global_seq || 0);
    const slo = Number(serverCoord.logout_seq || 0);
    const sli = Number(serverCoord.login_seq || 0);
    if (Number.isFinite(sg) && sg > serverGlobalSeq) {
      serverGlobalSeq = sg;
      changed = true;
    }
    if (Number.isFinite(slo) && slo > serverLogoutSeq) {
      serverLogoutSeq = slo;
      changed = true;
    }
    if (Number.isFinite(sli) && sli > serverLoginSeq) {
      serverLoginSeq = sli;
      changed = true;
    }
  }
  if (changed) {
    writeCoordCookie();
  }
}

async function withCoordLock(fn) {
  if (
    typeof navigator !== 'undefined' &&
    navigator.locks &&
    typeof navigator.locks.request === 'function'
  ) {
    return navigator.locks.request(COORD_LOCK_NAME, { mode: 'exclusive' }, async () => {
      syncCoordFromCookie();
      return fn();
    });
  }
  syncCoordFromCookie();
  return fn();
}

async function bumpCoordLogoutSeqAtomic(minTargetSeq = 0, pending = false) {
  return withCoordLock(() => {
    const nextSeq = Math.max(localCoordGlobalSeq + 1, Number(minTargetSeq || 0));
    localCoordGlobalSeq = nextSeq;
    localCoordLogoutSeq = nextSeq;
    if (pending) {
      localCoordLogoutPendingSeq = nextSeq;
    }
    writeCoordCookie();
    return localCoordLogoutSeq;
  });
}

async function clearCoordLogoutPending(logoutSeq) {
  return withCoordLock(() => {
    if (localCoordLogoutPendingSeq > 0 && localCoordLogoutPendingSeq <= logoutSeq) {
      localCoordLogoutPendingSeq = 0;
      writeCoordCookie();
    }
  });
}

async function bumpCoordLoginSeqIfNotSuperseded(startedEpoch, startedLogoutSeq, startedServerLogoutSeq, attemptId) {
  return withCoordLock(() => {
    if (
      isExplicitLoginSuperseded(
        startedEpoch,
        startedLogoutSeq,
        attemptId,
        startedServerLogoutSeq
      )
    ) {
      return { superseded: true, seq: 0 };
    }
    localCoordGlobalSeq += 1;
    localCoordLoginSeq = localCoordGlobalSeq;
    localCoordLogoutPendingSeq = 0;
    writeCoordCookie();
    return { superseded: false, seq: localCoordLoginSeq };
  });
}

async function fetchLiveBrowserCoord() {
  try {
    const resp = await fetch('/api/v1/auth/coord/session', {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
    });
    if (resp.ok) {
      const data = await resp.json();
      if (data && data.coord) {
        await withCoordLock(() => {
          syncServerCoord(data.coord);
        });
      }
    }
  } catch {
    // Non-fatal init fallback; server /otp/verify and /password/login also issue hc_browser
  }
  return syncCoordFromCookie();
}

async function ensureBrowserCoordInitialized() {
  if (coordInitPromise) {
    return coordInitPromise;
  }
  coordInitPromise = fetchLiveBrowserCoord();
  return coordInitPromise;
}

function isExplicitLoginSuperseded(
  startedEpoch,
  startedLogoutSeq,
  attemptId,
  startedServerLogoutSeq = null
) {
  syncCoordFromCookie();
  const serverSuperseded =
    startedServerLogoutSeq !== null &&
    startedServerLogoutSeq !== undefined &&
    serverLogoutSeq > Number(startedServerLogoutSeq);
  return Boolean(
    authEpoch !== startedEpoch ||
      localCoordLogoutSeq > startedLogoutSeq ||
      serverSuperseded ||
      (attemptId && cancelledAttemptIds.has(attemptId))
  );
}

function isNonLoginInvalidated(startedEpoch, startedLogoutSeq, startedServerLogoutSeq = null) {
  syncCoordFromCookie();
  const serverSuperseded =
    startedServerLogoutSeq !== null &&
    startedServerLogoutSeq !== undefined &&
    serverLogoutSeq > Number(startedServerLogoutSeq);
  return Boolean(
    logoutBarrierActive ||
      authEpoch !== startedEpoch ||
      localCoordLogoutSeq > startedLogoutSeq ||
      serverSuperseded
  );
}

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
  return Boolean(accessToken && authStatusLabel === 'AUTHENTICATED' && !logoutBarrierActive);
}

export function getSessionVersion() {
  return sessionVersion;
}

export function getAuthSnapshot() {
  syncCoordFromCookie();
  return {
    status: authStatusLabel,
    authenticated: isAuthenticated(),
    hasAccessTokenInClosure: Boolean(accessToken),
    accessExpiresAtMs,
    refreshCallsThisTab,
    pendingAttemptCount: pendingLoginAttempts.size,
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
    logoutSeq = null,
    suppressBump = false,
    preservePendingAttempts = false,
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
  activeSessionLoginSeq = 0;
  activeSessionFamilyId = null;
  authStatusLabel = statusLabel;
  sessionVersion += 1;

  let effectiveLogoutSeq = Number(logoutSeq || 0);
  if (!effectiveLogoutSeq && broadcastLogout && !suppressBump) {
    syncCoordFromCookie();
    localCoordGlobalSeq += 1;
    localCoordLogoutSeq = localCoordGlobalSeq;
    effectiveLogoutSeq = localCoordLogoutSeq;
    bumpCoordLogoutSeqAtomic(effectiveLogoutSeq).catch(() => {});
  }

  if (!preservePendingAttempts) {
    pendingLoginAttempts.forEach((aid) => cancelledAttemptIds.add(aid));
    abortActiveControllers();
  }
  drainSyncResolvers(null);

  lastEventMessage = reasonMessage || 'نشست پاک‌سازی شد.';
  lastErrorMessage = errorText;

  if (broadcastLogout && authChannel) {
    authChannel.postMessage({
      type: 'LOGOUT',
      reason: reasonMessage || 'LOGOUT',
      authEpoch,
      authGenSeq: effectiveLogoutSeq || localCoordLogoutSeq,
      serverCoord: {
        global_seq: serverGlobalSeq,
        logout_seq: serverLogoutSeq,
        login_seq: serverLoginSeq,
      },
    });
  }
  notifyChange();
}

function setActiveAccessToken(token, ttlSeconds, sourceNote, options = {}) {
  const { explicitLogin = false, sessionLoginSeq = 0, familyId = null } = options;
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
  if (familyId) {
    activeSessionFamilyId = String(familyId);
  }
  if (sessionLoginSeq > 0) {
    activeSessionLoginSeq = Math.max(activeSessionLoginSeq, sessionLoginSeq);
  } else if (activeSessionLoginSeq === 0 && localCoordLoginSeq > localCoordLogoutSeq) {
    activeSessionLoginSeq = localCoordLoginSeq;
  }
  authStatusLabel = accessToken ? 'AUTHENTICATED' : 'UNAUTHENTICATED';
  sessionVersion += 1;
  lastErrorMessage = '';
  if (sourceNote) {
    lastEventMessage = sourceNote;
  }
  return Boolean(accessToken);
}

async function postCancelAttemptChunks(attemptIds = []) {
  if (!attemptIds.length) {
    return { allOk: true, lastStatus: 200, lastDetail: '' };
  }
  let allOk = true;
  let lastStatus = 200;
  let lastDetail = '';
  for (let i = 0; i < attemptIds.length; i += MAX_CANCEL_BATCH) {
    const chunk = attemptIds.slice(i, i + MAX_CANCEL_BATCH);
    try {
      const resp = await fetch('/api/v1/auth/login-attempts/cancel', {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attempt_ids: chunk }),
      });
      lastStatus = resp.status;
      if (!resp.ok) {
        allOk = false;
        try {
          const errData = await resp.json();
          lastDetail = errData.detail || lastDetail;
        } catch {
          // ignore json parse failure
        }
      } else {
        try {
          const okData = await resp.json();
          if (okData && okData.auth_coord) {
            await withCoordLock(() => {
              syncServerCoord(okData.auth_coord);
            });
          }
        } catch {
          // ignore
        }
      }
    } catch {
      allOk = false;
      lastStatus = 0;
    }
  }
  return { allOk, lastStatus, lastDetail };
}

async function revokeSupersededLoginOnServer(lateAccessToken = null, attemptId = null) {
  const cancelledIds = attemptId ? [attemptId] : [];
  if (attemptId) {
    cancelledAttemptIds.add(attemptId);
  }

  let bearerRevoked = false;
  if (lateAccessToken) {
    try {
      const bearerResp = await fetch('/api/v1/auth/logout', {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: {
          'Content-Type': 'application/json',
          'X-Auth-Mode': 'bearer',
          Authorization: `${AUTH_HEADER_SCHEME} ${lateAccessToken}`,
        },
        body: JSON.stringify({ cancelled_login_attempt_ids: cancelledIds }),
      });
      bearerRevoked = Boolean(bearerResp.ok);
    } catch {
      bearerRevoked = false;
    }
  }

  // Always run targeted attempt-id cancellation if bearer logout did not succeed or if attemptId exists,
  // ensuring a network error on /logout NEVER skips /login-attempts/cancel (R2-T50-H01).
  if (cancelledIds.length > 0 && !bearerRevoked) {
    await postCancelAttemptChunks(cancelledIds);
  }

  // Clear resurrected late Set-Cookies via cookie /logout ONLY when browser is still logged out;
  // NEVER call cookie /logout if a newer explicit login has taken over (prevents clobbering newer cookies).
  syncCoordFromCookie();
  const stillLoggedOut =
    logoutBarrierActive &&
    localCoordLoginSeq <= localCoordLogoutSeq &&
    serverLoginSeq <= serverLogoutSeq;
  const csrf = getCookieValue('hc_csrf') || '';
  if (stillLoggedOut && (csrf || hasSessionHintCookie())) {
    try {
      const headers = {
        'Content-Type': 'application/json',
        'X-Auth-Mode': 'cookie',
        'X-CSRF-Token': csrf,
      };
      if (lateAccessToken) {
        headers.Authorization = `${AUTH_HEADER_SCHEME} ${lateAccessToken}`;
      }
      const resp = await fetch('/api/v1/auth/logout', {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        headers,
        body: JSON.stringify({ cancelled_login_attempt_ids: cancelledIds }),
      });
      if (resp.ok) {
        try {
          const data = await resp.json();
          if (data && data.auth_coord) {
            await withCoordLock(() => {
              syncServerCoord(data.auth_coord);
            });
          }
        } catch {
          // ignore
        }
      }
    } catch {
      // Targeted bearer/attempt revocation above already executed independently
    }
  }
}

async function executeCookieRefreshRequest() {
  const coord = syncCoordFromCookie();
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
  const startedLogoutSeq = coord.lo;
  const startedServerLogoutSeq = coord.slo;
  const startedLoginSeq = activeSessionLoginSeq || coord.li;
  const startedFamilyId = activeSessionFamilyId;
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

  if (isNonLoginInvalidated(startedEpoch, startedLogoutSeq, startedServerLogoutSeq)) {
    if (resp.ok) {
      let lateTok = null;
      try {
        const lateData = await resp.json();
        lateTok = lateData.access_token || null;
      } catch {
        lateTok = null;
      }
      await revokeSupersededLoginOnServer(lateTok, null);
    }
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
    if (isNonLoginInvalidated(startedEpoch, startedLogoutSeq, startedServerLogoutSeq)) {
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

  if (isNonLoginInvalidated(startedEpoch, startedLogoutSeq, startedServerLogoutSeq)) {
    await revokeSupersededLoginOnServer(data.access_token || null, null);
    return null;
  }

  syncCoordFromCookie();
  if (
    (startedLoginSeq > 0 && localCoordLoginSeq > startedLoginSeq) ||
    (startedFamilyId && data.family_id && String(data.family_id) !== startedFamilyId)
  ) {
    return null;
  }

  const effectiveLoginSeq = startedLoginSeq || localCoordLoginSeq || 1;
  const effectiveFamilyId = data.family_id ? String(data.family_id) : startedFamilyId;
  const applied = setActiveAccessToken(
    data.access_token || null,
    data.expires_in || 300,
    'نشست از طریق کوکی HttpOnly در حافظه RAM تازه‌سازی شد.',
    { sessionLoginSeq: effectiveLoginSeq, familyId: effectiveFamilyId }
  );
  if (!applied || isNonLoginInvalidated(startedEpoch, startedLogoutSeq, startedServerLogoutSeq)) {
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
      authGenSeq: effectiveLoginSeq,
      familyId: effectiveFamilyId,
      startedLogoutSeq,
    });
    await delay(30);
  }

  if (isNonLoginInvalidated(startedEpoch, startedLogoutSeq, startedServerLogoutSeq)) {
    return null;
  }

  await hydrateProfileInternal(startedEpoch, startedLogoutSeq);
  if (!isNonLoginInvalidated(startedEpoch, startedLogoutSeq, startedServerLogoutSeq)) {
    notifyChange();
  }
  return isNonLoginInvalidated(startedEpoch, startedLogoutSeq, startedServerLogoutSeq)
    ? null
    : accessToken;
}

export async function refreshSessionCoordinated(options = {}) {
  const coord = syncCoordFromCookie();
  if (logoutBarrierActive) {
    return null;
  }
  const opts = typeof options === 'boolean' ? { force: options } : options || {};
  const forceRefresh = Boolean(opts.force);
  const failedToken = opts.failedToken || null;
  const startedAt = Date.now();
  const startedEpoch = authEpoch;
  const startedLogoutSeq = coord.lo;

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
          if (isNonLoginInvalidated(startedEpoch, startedLogoutSeq)) {
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
            if (isNonLoginInvalidated(startedEpoch, startedLogoutSeq)) {
              return null;
            }
            if (synced) {
              await hydrateProfileInternal(authEpoch, localCoordLogoutSeq);
              if (!isNonLoginInvalidated(startedEpoch, startedLogoutSeq) && accessToken) {
                notifyChange();
              }
              return isNonLoginInvalidated(startedEpoch, startedLogoutSeq) ? null : synced;
            }
          }
          if (isNonLoginInvalidated(startedEpoch, startedLogoutSeq)) {
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
  const coord = syncCoordFromCookie();
  if (logoutBarrierActive) {
    throw new Error('UNAUTHENTICATED');
  }
  const startedEpoch = authEpoch;
  const startedLogoutSeq = coord.lo;
  let token = hasFreshAccessToken() ? accessToken : await refreshSessionCoordinated({ force: false });
  if (!token || isNonLoginInvalidated(startedEpoch, startedLogoutSeq) || !accessToken) {
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

    if (isNonLoginInvalidated(startedEpoch, startedLogoutSeq) || !accessToken) {
      throw new Error('UNAUTHENTICATED');
    }

    if (resp.status === 401) {
      const retriedToken = await refreshSessionCoordinated({ force: true, failedToken: token });
      if (isNonLoginInvalidated(startedEpoch, startedLogoutSeq)) {
        throw new Error('UNAUTHENTICATED');
      }
      if (!retriedToken) {
        clearPrivateState('نشست شما منقضی شده است؛ لطفاً مجدداً وارد شوید.', {
          broadcastLogout: false,
          statusLabel: 'EXPIRED',
        });
        throw new Error('UNAUTHENTICATED');
      }
      resp = await fetch(url, {
        method: options.method || 'GET',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: buildHeaders(retriedToken),
        body: options.body,
        signal: ctrl.signal,
      });
      if (isNonLoginInvalidated(startedEpoch, startedLogoutSeq) || !accessToken) {
        throw new Error('UNAUTHENTICATED');
      }
      if (resp.status === 401) {
        clearPrivateState('اعتبار توکن پس از تلاش مجدد منقضی/لغو شده است.', {
          broadcastLogout: false,
          statusLabel: 'EXPIRED',
        });
        throw new Error('UNAUTHENTICATED');
      }
    }

    return resp;
  } finally {
    activeControllers.delete(ctrl);
  }
}

async function hydrateProfileInternal(expectedEpoch = authEpoch, expectedLogoutSeq = localCoordLogoutSeq) {
  if (
    isNonLoginInvalidated(expectedEpoch, expectedLogoutSeq) ||
    !accessToken
  ) {
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
    if (isNonLoginInvalidated(expectedEpoch, expectedLogoutSeq) || !accessToken) {
      return null;
    }
    if (resp.ok) {
      const data = await resp.json();
      if (isNonLoginInvalidated(expectedEpoch, expectedLogoutSeq) || !accessToken) {
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

async function performExplicitCookieLogin(endpoint, payload, successMessage, failPrefix) {
  if (inFlightLogoutPromise) {
    try {
      await inFlightLogoutPromise;
    } catch {
      // Proceed after prior logout request settles
    }
  }
  await ensureBrowserCoordInitialized();
  const coord = await fetchLiveBrowserCoord();
  const startedEpoch = authEpoch;
  const startedLogoutSeq = coord.lo;
  const startedServerLogoutSeq = coord.slo;

  while (pendingLoginAttempts.size >= MAX_PENDING_LOGIN_ATTEMPTS) {
    const oldestId = pendingLoginAttempts.values().next().value;
    if (!oldestId) break;
    pendingLoginAttempts.delete(oldestId);
    cancelledAttemptIds.add(oldestId);
    postCancelAttemptChunks([oldestId]).catch(() => {});
  }

  const attemptId = generateAttemptId();
  const ctrl = new AbortController();

  pendingLoginAttempts.add(attemptId);
  activeControllers.add(ctrl);

  let resp;
  try {
    resp = await fetch(endpoint, {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      signal: ctrl.signal,
      headers: {
        'Content-Type': 'application/json',
        'X-Auth-Mode': 'cookie',
      },
      body: JSON.stringify({
        ...payload,
        attempt_id: attemptId,
        started_server_logout_seq: startedServerLogoutSeq,
      }),
    });
  } catch {
    pendingLoginAttempts.delete(attemptId);
    activeControllers.delete(ctrl);
    if (
      isExplicitLoginSuperseded(
        startedEpoch,
        startedLogoutSeq,
        attemptId,
        startedServerLogoutSeq
      )
    ) {
      await revokeSupersededLoginOnServer(null, attemptId);
      return { ok: false, status: 0, superseded: true, data: {} };
    }
    lastErrorMessage = `${failPrefix} (خطای شبکه)`;
    lastEventMessage = lastErrorMessage;
    notifyChange();
    return { ok: false, status: 0, data: {} };
  } finally {
    pendingLoginAttempts.delete(attemptId);
    activeControllers.delete(ctrl);
  }

  let data = {};
  try {
    data = await resp.json();
  } catch {
    data = {};
  }

  if (
    isExplicitLoginSuperseded(
      startedEpoch,
      startedLogoutSeq,
      attemptId,
      startedServerLogoutSeq
    )
  ) {
    if (resp.ok || data.access_token) {
      await revokeSupersededLoginOnServer(data.access_token || null, attemptId);
    }
    return { ok: false, status: resp.status, superseded: true, data: {} };
  }

  if (!resp.ok) {
    lastErrorMessage = data.detail || `${failPrefix} (${resp.status})`;
    lastEventMessage = lastErrorMessage;
    notifyChange();
    return { ok: false, status: resp.status, data };
  }

  const lockOutcome = await bumpCoordLoginSeqIfNotSuperseded(
    startedEpoch,
    startedLogoutSeq,
    startedServerLogoutSeq,
    attemptId
  );
  if (lockOutcome.superseded) {
    await revokeSupersededLoginOnServer(data.access_token || null, attemptId);
    return { ok: false, status: resp.status, superseded: true, data: {} };
  }

  if (data.auth_coord) {
    await withCoordLock(() => {
      syncServerCoord(data.auth_coord);
    });
  }

  const loginSeq = lockOutcome.seq;
  const sessionFamilyId = data.family_id ? String(data.family_id) : null;
  const applied = setActiveAccessToken(
    data.access_token || null,
    data.expires_in || 300,
    successMessage,
    { explicitLogin: true, sessionLoginSeq: loginSeq, familyId: sessionFamilyId }
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
      authGenSeq: loginSeq,
      familyId: sessionFamilyId,
      startedLogoutSeq,
      serverCoord: data.auth_coord || {
        global_seq: serverGlobalSeq,
        logout_seq: serverLogoutSeq,
        login_seq: serverLoginSeq,
      },
      attemptId,
    });
  }
  await hydrateProfileInternal(loginEpoch, startedLogoutSeq);
  if (!isNonLoginInvalidated(loginEpoch, startedLogoutSeq, startedServerLogoutSeq)) {
    notifyChange();
  }
  return {
    ok: !isNonLoginInvalidated(loginEpoch, startedLogoutSeq, startedServerLogoutSeq),
    status: resp.status,
    data,
  };
}

export async function verifyOtpCookie(mobile, code) {
  return performExplicitCookieLogin(
    '/api/v1/auth/otp/verify',
    { mobile, code },
    'ورود با کد OTP در حالت کوکی HttpOnly انجام شد.',
    'ورود OTP ناموفق'
  );
}

export async function loginPasswordCookie(mobile, password) {
  return performExplicitCookieLogin(
    '/api/v1/auth/password/login',
    { mobile, password },
    'ورود با رمز عبور در حالت کوکی HttpOnly انجام شد.',
    'ورود با رمز ناموفق'
  );
}

export async function fetchMyProfile() {
  const coord = syncCoordFromCookie();
  const startedEpoch = authEpoch;
  const startedLogoutSeq = coord.lo;
  let resp;
  try {
    resp = await authenticatedFetch('/api/v1/profile/me');
  } catch (err) {
    if (isNonLoginInvalidated(startedEpoch, startedLogoutSeq)) {
      return { ok: false, status: 0, data: {} };
    }
    throw err;
  }
  if (isNonLoginInvalidated(startedEpoch, startedLogoutSeq) || !accessToken) {
    return { ok: false, status: resp.status, data: {} };
  }
  let data = {};
  try {
    data = await resp.json();
  } catch {
    data = {};
  }
  if (isNonLoginInvalidated(startedEpoch, startedLogoutSeq) || !accessToken) {
    return { ok: false, status: resp.status, data: {} };
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
  const coord = syncCoordFromCookie();
  const startedEpoch = authEpoch;
  const startedLogoutSeq = coord.lo;
  const resp = await authenticatedFetch(`/api/v1/auth/panels/${encodeURIComponent(panelRole)}/access`);
  if (isNonLoginInvalidated(startedEpoch, startedLogoutSeq) || !accessToken) {
    throw new Error('UNAUTHENTICATED');
  }
  let data = {};
  try {
    data = await resp.json();
  } catch {
    data = {};
  }
  if (isNonLoginInvalidated(startedEpoch, startedLogoutSeq) || !accessToken) {
    throw new Error('UNAUTHENTICATED');
  }
  return { ok: resp.ok, status: resp.status, data };
}

export async function fetchReadOnlyRoleExtras() {
  const coord = syncCoordFromCookie();
  const startedEpoch = authEpoch;
  const startedLogoutSeq = coord.lo;
  try {
    const resp = await authenticatedFetch('/api/v1/notifications/unread-count');
    if (isNonLoginInvalidated(startedEpoch, startedLogoutSeq) || !accessToken) {
      return null;
    }
    if (resp.ok) {
      const json = await resp.json();
      if (isNonLoginInvalidated(startedEpoch, startedLogoutSeq) || !accessToken) {
        return null;
      }
      return json;
    }
  } catch {
    // Non-fatal preview enrichment
  }
  return null;
}

export async function logoutCookie() {
  const csrf = getCookieValue('hc_csrf') || '';
  const hintPresent = hasSessionHintCookie();
  const bearerSnapshot = accessToken;
  const cancelledIdsToSend = Array.from(pendingLoginAttempts);
  cancelledIdsToSend.forEach((aid) => cancelledAttemptIds.add(aid));

  syncCoordFromCookie();
  const provisionalLogoutSeq = Math.max(localCoordGlobalSeq + 1, localCoordLogoutSeq + 1);
  localCoordGlobalSeq = provisionalLogoutSeq;
  localCoordLogoutSeq = provisionalLogoutSeq;
  localCoordLogoutPendingSeq = provisionalLogoutSeq;
  writeCoordCookie();

  // Engage immediate fail-closed LOGOUT_PENDING barrier & UI scrub BEFORE network wait (M02)
  logoutBarrierActive = true;
  canRetryLogout = false;
  authEpoch += 1;
  const logoutEpoch = authEpoch;
  activeSessionLoginSeq = 0;
  activeSessionFamilyId = null;
  accessToken = null;
  accessExpiresAtMs = 0;
  accessTtlMs = 300000;
  cachedProfile = null;
  inFlightRefresh = null;
  authStatusLabel = 'LOGOUT_PENDING';
  sessionVersion += 1;
  lastErrorMessage = '';
  lastEventMessage = 'در حال خروج امن و ابطال نشست در سرور...';

  abortActiveControllers();
  drainSyncResolvers(null);

  if (authChannel) {
    authChannel.postMessage({
      type: 'LOGOUT_PENDING',
      reason: lastEventMessage,
      authEpoch: logoutEpoch,
      authGenSeq: provisionalLogoutSeq,
      provisional: true,
    });
  }
  notifyChange();

  const runLogout = (async () => {
    const logoutSeq = await bumpCoordLogoutSeqAtomic(provisionalLogoutSeq, true);
    if (authChannel && logoutSeq !== provisionalLogoutSeq) {
      authChannel.postMessage({
        type: 'LOGOUT_PENDING',
        reason: lastEventMessage,
        authEpoch: logoutEpoch,
        authGenSeq: logoutSeq,
      });
    }

    let status = 0;
    let detail = '';
    let revokedOnServer = false;
    let serverCoordPayload = null;

    const isGuestAttemptCancelOnly =
      cancelledIdsToSend.length > 0 && !csrf && !hintPresent && !bearerSnapshot;
    const primaryBatch = cancelledIdsToSend.slice(0, MAX_CANCEL_BATCH);
    const overflowIds = cancelledIdsToSend.slice(MAX_CANCEL_BATCH);

    try {
      if (isGuestAttemptCancelOnly) {
        const cancelRes = await postCancelAttemptChunks(cancelledIdsToSend);
        status = cancelRes.lastStatus;
        detail = cancelRes.lastDetail;
        revokedOnServer = Boolean(cancelRes.allOk);
      } else {
        const headers = {
          'X-Auth-Mode': 'cookie',
          'X-CSRF-Token': csrf,
        };
        if (bearerSnapshot) {
          headers.Authorization = `${AUTH_HEADER_SCHEME} ${bearerSnapshot}`;
        }
        const fetchOpts = {
          method: 'POST',
          credentials: 'same-origin',
          cache: 'no-store',
          headers,
        };
        if (primaryBatch.length > 0) {
          headers['Content-Type'] = 'application/json';
          fetchOpts.body = JSON.stringify({ cancelled_login_attempt_ids: primaryBatch });
        }
        const resp = await fetch('/api/v1/auth/logout', fetchOpts);
        status = resp.status;
        revokedOnServer = Boolean(resp.ok);
        try {
          const respData = await resp.json();
          if (respData && respData.auth_coord) {
            serverCoordPayload = respData.auth_coord;
            await withCoordLock(() => {
              syncServerCoord(respData.auth_coord);
            });
          }
          if (!revokedOnServer) {
            detail = respData.detail || '';
          }
        } catch {
          if (!revokedOnServer) {
            detail = '';
          }
        }
        if (overflowIds.length > 0) {
          const extraCancelRes = await postCancelAttemptChunks(overflowIds);
          if (!extraCancelRes.allOk) {
            revokedOnServer = false;
            if (!detail && extraCancelRes.lastDetail) {
              detail = extraCancelRes.lastDetail;
            }
            if (status === 200 && extraCancelRes.lastStatus) {
              status = extraCancelRes.lastStatus;
            }
          }
        }
      }
    } catch {
      status = 0;
      revokedOnServer = false;
      if (overflowIds.length > 0) {
        await postCancelAttemptChunks(overflowIds).catch(() => {});
      }
    } finally {
      await clearCoordLogoutPending(logoutSeq).catch(() => {});
    }

    syncCoordFromCookie();
    if (authEpoch !== logoutEpoch || localCoordLoginSeq > logoutSeq) {
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
        logoutSeq,
        suppressBump: true,
        preservePendingAttempts: true,
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
        logoutSeq,
        suppressBump: true,
        preservePendingAttempts: true,
      });
      return { ok: false, revokedOnServer: false, canRetryLogout: false, status, detail };
    }

    const retryable = Boolean(credsStillPresent);
    const reasonMessage = retryable
      ? `هشدار: خروج محلی انجام شد اما لغو نشست روی سرور تأیید نشد (${errCodeText}).`
      : `هشدار: کوکی‌های قابل مشاهده نشست در مرورگر پاک شده‌اند اما لغو نشست در سرور و پایگاه‌داده تأیید نشد (${errCodeText}).`;
    const errorText = retryable
      ? `لغو نشست روی سرور تأیید نشد (${errCodeText}${detail ? ` - ${detail}` : ''}). نشست سروری ممکن است هنوز فعال باشد؛ لطفاً دوباره خروج سروری را بزنید.`
      : `سرور پاسخ تأییدشده‌ای برای ابطال کامل نشست بازنگرداند (${errCodeText}${detail ? ` - ${detail}` : ''}). به دلیل نبود کوکی‌های مرورگر امکان ارسال مجدد درخواست خروج وجود ندارد و وضعیت نهایی ابطال در سرور/پایگاه‌داده تأییدنشده است؛ در صورت نیاز دوباره وارد شوید.`;

    clearPrivateState(reasonMessage, {
      broadcastLogout: false,
      logoutBarrier: true,
      retryableLogout: retryable,
      statusLabel: 'REMOTE_REVOKE_FAILED',
      errorText,
      logoutSeq,
      suppressBump: true,
      preservePendingAttempts: true,
    });
    if (authChannel) {
      authChannel.postMessage({
        type: 'LOGOUT_FAILED_LOCAL_SCRUB',
        status,
        canRetryLogout: retryable,
        reason: reasonMessage,
        errorText,
        authEpoch,
        authGenSeq: logoutSeq,
        serverCoord: serverCoordPayload || {
          global_seq: serverGlobalSeq,
          logout_seq: serverLogoutSeq,
          login_seq: serverLoginSeq,
        },
      });
    }
    return { ok: false, revokedOnServer: false, canRetryLogout: retryable, status, detail };
  })();

  inFlightLogoutPromise = runLogout;
  try {
    return await runLogout;
  } finally {
    if (inFlightLogoutPromise === runLogout) {
      inFlightLogoutPromise = null;
    }
  }
}

export function initAuthLifecycle(onStateChange) {
  stateChangeListener = onStateChange;
  const initialCoord = syncCoordFromCookie();
  const isLogoutInFlight = initialCoord.lp > 0 && initialCoord.lp >= initialCoord.li;
  const isServerLogoutConfirmed = initialCoord.slo > initialCoord.sli;
  if (isLogoutInFlight || isServerLogoutConfirmed) {
    logoutBarrierActive = true;
  }

  if (authChannel) {
    authChannel.onmessage = (event) => {
      const msg = event.data || {};
      syncCoordFromCookie();
      if (msg.serverCoord) {
        syncServerCoord(msg.serverCoord);
      }

      if (msg.type === 'TOKEN_REFRESHED' && msg.accessToken) {
        const isExplicit = Boolean(msg.explicitLogin);
        const msgSeq = Number(msg.authGenSeq || 0);
        const msgStartedLogoutSeq = Number(msg.startedLogoutSeq || 0);
        const msgAttemptId = typeof msg.attemptId === 'string' ? msg.attemptId : null;
        const msgFamilyId = typeof msg.familyId === 'string' && msg.familyId ? msg.familyId : null;

        if (isExplicit) {
          if (
            msgSeq <= 0 ||
            msgSeq <= localCoordLogoutSeq ||
            msgStartedLogoutSeq < localCoordLogoutSeq ||
            (msgAttemptId && cancelledAttemptIds.has(msgAttemptId))
          ) {
            return;
          }
          syncCoordFromSeq(msgSeq, 'login', msg.serverCoord || null);
        } else {
          if (
            logoutBarrierActive ||
            msgSeq <= 0 ||
            msgSeq <= localCoordLogoutSeq ||
            msgSeq < localCoordLoginSeq ||
            (activeSessionLoginSeq > 0 && msgSeq < activeSessionLoginSeq) ||
            (activeSessionFamilyId && msgFamilyId && msgFamilyId !== activeSessionFamilyId)
          ) {
            return;
          }
          syncCoordFromSeq(msgSeq, 'login', msg.serverCoord || null);
        }

        const applied = setActiveAccessToken(
          msg.accessToken,
          Math.max(1, Math.round(Number(msg.accessTtlMs || accessTtlMs || 300000) / 1000)),
          'توکن کوتاه‌عمر از طریق BroadcastChannel همگام‌سازی شد.',
          { explicitLogin: isExplicit, sessionLoginSeq: msgSeq, familyId: msgFamilyId }
        );
        if (!applied) {
          return;
        }
        accessTtlMs = Number(msg.accessTtlMs || accessTtlMs || 300000);
        accessExpiresAtMs = Number(msg.accessExpiresAtMs || Date.now() + accessTtlMs);
        const syncEpoch = authEpoch;
        const syncLogoutSeq = localCoordLogoutSeq;
        drainSyncResolvers(accessToken);
        hydrateProfileInternal(syncEpoch, syncLogoutSeq).finally(() => {
          if (!isNonLoginInvalidated(syncEpoch, syncLogoutSeq)) {
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
            authGenSeq: activeSessionLoginSeq || localCoordLoginSeq || 1,
            familyId: activeSessionFamilyId,
            startedLogoutSeq: localCoordLogoutSeq,
            serverCoord: {
              global_seq: serverGlobalSeq,
              logout_seq: serverLogoutSeq,
              login_seq: serverLoginSeq,
            },
          });
        }
      } else if (msg.type === 'LOGOUT_PENDING') {
        const msgSeq = Number(msg.authGenSeq || 0);
        if (msgSeq > 0 && (activeSessionLoginSeq > msgSeq || localCoordLoginSeq > msgSeq)) {
          return;
        }
        if (msgSeq > 0) {
          syncCoordFromSeq(msgSeq, 'logout', msg.serverCoord || null);
        }
        clearPrivateState(msg.reason || 'خروج امن در تب دیگر آغاز شد...', {
          broadcastLogout: false,
          logoutBarrier: true,
          retryableLogout: false,
          statusLabel: 'LOGOUT_PENDING',
          logoutSeq: msgSeq,
          suppressBump: true,
        });
      } else if (msg.type === 'LOGOUT') {
        const msgSeq = Number(msg.authGenSeq || 0);
        if (msgSeq > 0 && (activeSessionLoginSeq > msgSeq || localCoordLoginSeq > msgSeq)) {
          return;
        }
        if (msgSeq > 0) {
          syncCoordFromSeq(msgSeq, 'logout', msg.serverCoord || null);
        }
        clearPrivateState('خروج هم‌زمان از تب دیگر دریافت و اعمال شد.', {
          broadcastLogout: false,
          logoutBarrier: true,
          retryableLogout: false,
          statusLabel: 'UNAUTHENTICATED',
          logoutSeq: msgSeq,
          suppressBump: true,
        });
      } else if (msg.type === 'LOGOUT_FAILED_LOCAL_SCRUB') {
        const msgSeq = Number(msg.authGenSeq || 0);
        if (msgSeq > 0 && (activeSessionLoginSeq > msgSeq || localCoordLoginSeq > msgSeq)) {
          return;
        }
        if (msgSeq > 0) {
          syncCoordFromSeq(msgSeq, 'logout', msg.serverCoord || null);
        }
        clearPrivateState(
          msg.reason || 'هشدار: خروج هم‌زمان در تب دیگر روی سرور تأیید نشد؛ حافظه محلی پاک‌سازی شد.',
          {
            broadcastLogout: false,
            logoutBarrier: true,
            retryableLogout: Boolean(msg.canRetryLogout),
            statusLabel: 'REMOTE_REVOKE_FAILED',
            errorText: msg.errorText || '',
            logoutSeq: msgSeq,
            suppressBump: true,
          }
        );
      }
    };
  }

  window.addEventListener('pageshow', (event) => {
    if (event.persisted) {
      const c = syncCoordFromCookie();
      const hasCookieHint = hasSessionHintCookie();
      const pageLogoutInFlight = c.lp > 0 && c.lp >= c.li;
      const pageServerConfirmed = c.slo > c.sli;
      const logoutBarred = !hasCookieHint || pageLogoutInFlight || pageServerConfirmed;
      clearPrivateState('بازیابی از BFCache شناسایی و حافظه نشست پاک‌سازی شد.', {
        broadcastLogout: false,
        logoutBarrier: logoutBarred,
        retryableLogout: false,
        statusLabel: 'UNAUTHENTICATED',
        suppressBump: true,
      });
      if (!logoutBarred) {
        refreshSessionCoordinated({ force: true }).catch(() => {});
      }
    }
  });

  if (hasSessionHintCookie() && !logoutBarrierActive) {
    refreshSessionCoordinated({ force: false }).catch(() => {});
  }
}
