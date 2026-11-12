# Staging & Production Reverse-Proxy / CDN Release Gate (`R2-T46-V3-L03`)

**Status**: Mandatory pre-production infrastructure release gate for HamiCard Phase 3 Auth + UI Shell  
**Tracking**: `HC-T49` remediation for `R2-T46-V3-L03`  
**Invariant**: Cookie scoping (`hc_refresh` with `HttpOnly; SameSite=Lax; Path=/api/v1/auth; Secure`), strict CSP (`script-src 'self'`, `frame-ancestors 'none'`), Origin/CSRF enforcement, and `Cache-Control: no-store` headers MUST be preserved verbatim end-to-end across any reverse proxy, load balancer, or CDN before staging/production cutover.

---

## 1. Non-Negotiable Edge / Proxy Verification Checklist

1. **Zero Shared/CDN Caching on Auth, API, and Authenticated Shell Routes**
   - `/api/v1/*`, `/phase3/*`, and `/` (in `staging`/`production` restricted environments) MUST NEVER be cached by any CDN, reverse proxy, or edge cache (`proxy_no_cache 1; proxy_cache_bypass 1;`).
   - Upstream `Cache-Control: no-store, no-cache, must-revalidate, private`, `Pragma: no-cache`, and `Vary: Origin, Cookie` headers MUST be forwarded untouched without overwriting or stripping.
   - Any edge rule emitting `Set-Cookie` on cached responses is strictly forbidden.

2. **Exact `Set-Cookie` Attribute & Path Preservation**
   - `hc_refresh`: MUST retain `HttpOnly`, `SameSite=Lax`, `Path=/api/v1/auth`, and `Secure` (`_resolve_cookie_secure` enforces `Secure=True` whenever `ENVIRONMENT` is `production` or `staging`, or `COOKIE_SECURE=true`, or request scheme is `https`).
   - `hc_csrf`, `hc_has_session`, `hc_coord`: MUST retain `Path=/`, `SameSite=Lax`, and `Secure` on HTTPS without adding `HttpOnly` (since UI JS double-submit / session-hint / monotonic causal ordering intentionally reads `hc_csrf`, `hc_has_session`, and non-secret `hc_coord`).
   - Multiple `Set-Cookie` response headers on `/api/v1/auth/otp/verify`, `/password/login`, `/refresh`, and `/logout` MUST NOT be folded or deduplicated by the proxy.

3. **TLS Termination, Host & Origin Header Integrity**
   - TLS MUST terminate with trusted headers forwarded cleanly (`X-Forwarded-Proto: https`, `Host` preserved matching `CORS_ALLOWED_ORIGINS`) and client `Origin` / `Referer` headers MUST be passed unmodified to FastAPI so `validate_cookie_request_origin()` enforces fail-closed CSRF Origin parity.
   - Reverse proxy rewrites that strip `Origin`, alter `Host` to an internal hostname outside `CORS_ALLOWED_ORIGINS`, or downgrade `https` links fail closed (`HTTP 403`).

4. **Strict CSP & Security Headers Forwarding**
   - Proxy/CDN MUST NOT inject inline analytics `<script>` tags, inline `style=`, or relax `Content-Security-Policy` (`default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'`).
   - `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY` MUST reach the browser unmodified.

5. **Out-of-Order / Connection Cancellation Behavior**
   - Edge proxies SHOULD propagate client TCP aborts to upstream workers where supported; additionally, HamiCard's application-layer Redis cancellation fence (`/api/v1/auth/login-attempts/cancel` + `/logout` `cancelled_login_attempt_ids` + `hc:login_attempt_family:{attempt_id}`) + browser cookie coordinator (`hc_coord`) provide defense-in-depth revocation even when a proxy finishes forwarding an upstream login response after logout.

---

## 2. Live Staging Smoke Verification Gate (Run Before Production Promotion)

Run against the deployed staging URL (`https://staging.example`) behind the real TLS proxy:
- Verify `curl -i https://staging.example/api/v1/auth/refresh` preserves `Cache-Control: no-store`.
- Verify Chromium real browser login -> `POST /api/v1/auth/otp/verify` / `/password/login` sets `hc_refresh` (`HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/api/v1/auth`).
- Verify `POST /api/v1/auth/logout` returns multiple uncollapsed `Set-Cookie` deletion headers clearing `hc_refresh`, `hc_csrf`, and `hc_has_session` and returns `HTTP 401` on subsequent `/refresh`.
- Verify zero CDN cache hit headers (`CF-Cache-Status: BYPASS`/`DYNAMIC`, `X-Cache: MISS`) on `/api/v1/*` and `/phase3/*`.
