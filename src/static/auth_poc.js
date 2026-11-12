(function () {
  "use strict";

  // Short-lived access credential lives strictly in private JS closure RAM (never web storage).
  let accessToken = null;
  let accessExpiresAtMs = 0;
  let accessTtlMs = 300000;
  let lastRefreshAtMs = 0;
  let inFlightRefresh = null;
  let activeFetchController = null;
  let refreshCallsThisTab = 0;
  let pendingSyncResolvers = [];

  const CHANNEL_NAME = "hamicard_auth_poc";
  const LOCK_NAME = "hamicard_auth_poc_refresh";
  const authChannel = typeof BroadcastChannel === "function" ? new BroadcastChannel(CHANNEL_NAME) : null;

  const elState = document.getElementById("poc-auth-state");
  const elProfileOut = document.getElementById("poc-profile-output");
  const elAudit = document.getElementById("poc-storage-audit");
  const elLog = document.getElementById("poc-event-log");

  function delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function getCookieValue(name) {
    const rawCookies = document.cookie ? document.cookie.split(";") : [];
    const prefix = name + "=";
    for (let i = 0; i < rawCookies.length; i += 1) {
      const part = rawCookies[i].trim();
      if (part.indexOf(prefix) === 0) {
        return decodeURIComponent(part.slice(prefix.length));
      }
    }
    return null;
  }

  function listVisibleCookieNames() {
    if (!document.cookie) {
      return [];
    }
    return document.cookie
      .split(";")
      .map((item) => item.trim().split("=")[0])
      .filter(Boolean);
  }

  function hasFreshAccessToken() {
    const skewMarginMs = Math.min(1000, Math.floor(accessTtlMs * 0.25));
    return Boolean(accessToken && Date.now() < accessExpiresAtMs - skewMarginMs);
  }

  function updateUiAudit(noteText) {
    if (elState) {
      elState.textContent = accessToken ? "AUTHENTICATED" : "UNAUTHENTICATED";
    }
    if (elAudit) {
      const auditSnapshot = {
        hasAccessTokenInClosure: Boolean(accessToken),
        accessExpiresAtMs: accessExpiresAtMs,
        refreshCallsThisTab: refreshCallsThisTab,
        visibleCookieNames: listVisibleCookieNames(),
        hasSessionHintCookie: getCookieValue("hc_has_session") === "1",
      };
      elAudit.textContent = JSON.stringify(auditSnapshot, null, 2);
    }
    if (noteText && elLog) {
      elLog.textContent = noteText;
    }
  }

  function clearPrivateState(reasonMessage, options) {
    const opts = options || {};
    accessToken = null;
    accessExpiresAtMs = 0;
    accessTtlMs = 300000;
    if (activeFetchController) {
      activeFetchController.abort();
      activeFetchController = null;
    }
    if (elProfileOut) {
      elProfileOut.textContent = reasonMessage || "Cleared.";
    }
    if (opts.broadcastLogout && authChannel) {
      authChannel.postMessage({ type: "LOGOUT", reason: reasonMessage || "Logout" });
    }
    updateUiAudit(reasonMessage || "Session cleared.");
  }

  async function executeCookieRefreshRequest() {
    const csrf = getCookieValue("hc_csrf");
    if (!csrf) {
      clearPrivateState("No CSRF cookie present for refresh.");
      return null;
    }

    refreshCallsThisTab += 1;
    const resp = await fetch("/api/v1/auth/refresh", {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: {
        "X-Auth-Mode": "cookie",
        "X-CSRF-Token": csrf,
      },
    });

    if (!resp.ok) {
      if (resp.status === 401 || resp.status === 403) {
        clearPrivateState("Session expired or revoked (HTTP " + resp.status + ").", {
          broadcastLogout: false,
        });
      } else {
        updateUiAudit("Refresh failed with HTTP " + resp.status);
      }
      return null;
    }

    const data = await resp.json();
    accessToken = data.access_token || null;
    accessTtlMs = Math.max(1000, Number(data.expires_in || 300) * 1000);
    accessExpiresAtMs = Date.now() + accessTtlMs;
    lastRefreshAtMs = Date.now();

    if (authChannel && accessToken) {
      authChannel.postMessage({
        type: "TOKEN_REFRESHED",
        accessToken: accessToken,
        accessExpiresAtMs: accessExpiresAtMs,
        accessTtlMs: accessTtlMs,
      });
      // Give Chromium IPC a brief turn so queued sibling tabs observe BroadcastChannel before lock handoff.
      await delay(30);
    }

    updateUiAudit("Session refreshed in RAM via HttpOnly cookie.");
    return accessToken;
  }

  async function refreshSessionCoordinated(options) {
    const opts = typeof options === "boolean" ? { force: options } : (options || {});
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
        if (navigator.locks && typeof navigator.locks.request === "function") {
          return await navigator.locks.request(LOCK_NAME, { mode: "exclusive" }, async () => {
            if (failedToken && accessToken && accessToken !== failedToken && hasFreshAccessToken()) {
              updateUiAudit("Reused newer access token synced during concurrent retry.");
              return accessToken;
            }
            if (lastRefreshAtMs >= startedAt && hasFreshAccessToken()) {
              updateUiAudit("Reused coordinated refresh token broadcast from sibling tab.");
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
                authChannel.postMessage({ type: "REQUEST_SYNC" });
                setTimeout(() => {
                  if (!done) {
                    done = true;
                    pendingSyncResolvers = pendingSyncResolvers.filter((fn) => fn !== onSync);
                    resolve(null);
                  }
                }, 35);
              });
              if (synced) {
                updateUiAudit("Reused fresh access token shared by sibling tab on boot.");
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

  async function authenticatedFetch(url, options) {
    const opts = options || {};
    let token = hasFreshAccessToken() ? accessToken : await refreshSessionCoordinated({ force: false });
    if (!token) {
      throw new Error("UNAUTHENTICATED");
    }

    if (activeFetchController) {
      activeFetchController.abort();
    }
    activeFetchController = new AbortController();

    const headers = Object.assign({}, opts.headers || {}, {
      Authorization: "Bearer " + token,
    });

    let resp = await fetch(url, {
      method: opts.method || "GET",
      credentials: "same-origin",
      cache: "no-store",
      headers: headers,
      body: opts.body,
      signal: activeFetchController.signal,
    });

    if (resp.status === 401) {
      token = await refreshSessionCoordinated({ force: true, failedToken: token });
      if (!token) {
        return resp;
      }
      const retryHeaders = Object.assign({}, opts.headers || {}, {
        Authorization: "Bearer " + token,
      });
      resp = await fetch(url, {
        method: opts.method || "GET",
        credentials: "same-origin",
        cache: "no-store",
        headers: retryHeaders,
        body: opts.body,
        signal: activeFetchController.signal,
      });
    }

    return resp;
  }

  if (authChannel) {
    authChannel.onmessage = function (event) {
      const msg = event.data || {};
      if (msg.type === "TOKEN_REFRESHED" && msg.accessToken) {
        accessToken = msg.accessToken;
        accessTtlMs = Number(msg.accessTtlMs || accessTtlMs || 300000);
        accessExpiresAtMs = Number(msg.accessExpiresAtMs || Date.now() + accessTtlMs);
        lastRefreshAtMs = Date.now();
        const waiters = pendingSyncResolvers.slice();
        pendingSyncResolvers = [];
        for (let i = 0; i < waiters.length; i += 1) {
          waiters[i](accessToken);
        }
        updateUiAudit("Synced short-lived access token via BroadcastChannel.");
      } else if (msg.type === "REQUEST_SYNC") {
        if (hasFreshAccessToken()) {
          authChannel.postMessage({
            type: "TOKEN_REFRESHED",
            accessToken: accessToken,
            accessExpiresAtMs: accessExpiresAtMs,
            accessTtlMs: accessTtlMs,
          });
        }
      } else if (msg.type === "LOGOUT") {
        clearPrivateState("Signed out across tabs (" + (msg.reason || "LOGOUT") + ").", {
          broadcastLogout: false,
        });
      }
    };
  }

  window.addEventListener("pageshow", function (event) {
    // Immediate scrub on BFCache restore before any rehydration (AC-14).
    if (event.persisted) {
      clearPrivateState("Scrubbed BFCache snapshot on pageshow.", { broadcastLogout: false });
      if (getCookieValue("hc_has_session") === "1") {
        refreshSessionCoordinated(true).catch(function () {});
      }
    } else if (!accessToken && elProfileOut) {
      elProfileOut.textContent = "Not loaded.";
      updateUiAudit();
    }
  });

  const otpReqForm = document.getElementById("poc-otp-req-form");
  if (otpReqForm) {
    otpReqForm.addEventListener("submit", async function (e) {
      e.preventDefault();
      const mobile = document.getElementById("poc-mobile").value.trim();
      const resp = await fetch("/api/v1/auth/otp/request", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mobile: mobile }),
      });
      const data = await resp.json();
      updateUiAudit("OTP request status " + resp.status + ": " + (data.message || data.detail || ""));
    });
  }

  const otpVerifyForm = document.getElementById("poc-otp-verify-form");
  if (otpVerifyForm) {
    otpVerifyForm.addEventListener("submit", async function (e) {
      e.preventDefault();
      const mobile = document.getElementById("poc-mobile").value.trim();
      const code = document.getElementById("poc-otp-code").value.trim();
      const resp = await fetch("/api/v1/auth/otp/verify", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-Auth-Mode": "cookie",
        },
        body: JSON.stringify({ mobile: mobile, code: code }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        updateUiAudit("OTP verify failed (" + resp.status + "): " + (data.detail || ""));
        return;
      }
      accessToken = data.access_token || null;
      accessTtlMs = Math.max(1000, Number(data.expires_in || 300) * 1000);
      accessExpiresAtMs = Date.now() + accessTtlMs;
      lastRefreshAtMs = Date.now();
      updateUiAudit("OTP verified in cookie mode; HttpOnly hc_refresh set.");
    });
  }

  const pwdForm = document.getElementById("poc-pwd-form");
  if (pwdForm) {
    pwdForm.addEventListener("submit", async function (e) {
      e.preventDefault();
      const mobile = document.getElementById("poc-pwd-mobile").value.trim();
      const password = document.getElementById("poc-pwd-input").value;
      const resp = await fetch("/api/v1/auth/password/login", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-Auth-Mode": "cookie",
        },
        body: JSON.stringify({ mobile: mobile, password: password }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        updateUiAudit("Password login failed (" + resp.status + "): " + (data.detail || ""));
        return;
      }
      accessToken = data.access_token || null;
      accessTtlMs = Math.max(1000, Number(data.expires_in || 300) * 1000);
      accessExpiresAtMs = Date.now() + accessTtlMs;
      lastRefreshAtMs = Date.now();
      updateUiAudit("Password login succeeded in cookie mode.");
    });
  }

  const btnProfile = document.getElementById("poc-fetch-profile-btn");
  if (btnProfile) {
    btnProfile.addEventListener("click", async function () {
      try {
        const resp = await authenticatedFetch("/api/v1/profile/me");
        const data = await resp.json();
        if (resp.ok) {
          elProfileOut.textContent = JSON.stringify(
            { status: resp.status, mobile: data.mobile, roles: data.roles, has_profile: data.has_profile },
            null,
            2
          );
        } else {
          elProfileOut.textContent = "HTTP " + resp.status + ": " + (data.detail || "Denied");
        }
        updateUiAudit("Profile fetch completed with HTTP " + resp.status);
      } catch (err) {
        elProfileOut.textContent = "Unauthenticated (" + err.message + ")";
        updateUiAudit("Profile fetch blocked: no active session.");
      }
    });
  }

  const btnRefresh = document.getElementById("poc-refresh-btn");
  if (btnRefresh) {
    btnRefresh.addEventListener("click", async function () {
      await refreshSessionCoordinated(true);
    });
  }

  const btnLogout = document.getElementById("poc-logout-btn");
  if (btnLogout) {
    btnLogout.addEventListener("click", async function () {
      const csrf = getCookieValue("hc_csrf") || "";
      const headers = {
        "X-Auth-Mode": "cookie",
        "X-CSRF-Token": csrf,
      };
      if (accessToken) {
        headers.Authorization = "Bearer " + accessToken;
      }
      const resp = await fetch("/api/v1/auth/logout", {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        headers: headers,
      });
      clearPrivateState("Logged out cleanly (HTTP " + resp.status + ").", { broadcastLogout: true });
    });
  }

  // Initial page boot hydration: only refresh if boolean non-sensitive session cookie hint exists.
  updateUiAudit("Initialized with zero web storage.");
  if (getCookieValue("hc_has_session") === "1") {
    refreshSessionCoordinated(false).catch(function () {});
  }
})();
