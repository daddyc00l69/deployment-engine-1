# VPSphere QA Checklist (Enterprise Auth Upgrade)

Generated: 2026-02-22

Goal: validate the full auth/session/risk/email stack like a production SaaS.

## Pre-flight (must pass)

- [ ] API health: `GET https://api.devtushar.uk/health` returns `200` and JSON says db/redis/docker up
- [ ] CORS: browser requests from `https://devtushar.uk` succeed with `credentials: include`
- [ ] Cookies: after login, browser has HttpOnly cookies:
  - `vpsphere_token` (access, ~15m)
  - `refreshToken` (refresh, ~7d, path `/auth/refresh`)
- [ ] Database: `user_sessions` has rows when you login (one per device)

## 1) Register -> OTP -> Verify (email verification)

### UI path
- [ ] Register with a new email/username
- [ ] Expected API: `POST /auth/register` returns `202` and does NOT auto-login
- [ ] Email received: Verification email renders correctly (your Stitch design)
  - [ ] OTP code present ({{otp}})
  - [ ] Verify button link present ({{verify_link}})
- [ ] Enter OTP in UI (or use verify link)
- [ ] Expected API: `POST /auth/otp/verify` returns `200`
- [ ] Expected DB: `users.status = active`, `email_verified = true`

### Negative tests
- [ ] Wrong OTP -> `401` / `400` and user stays `pending`
- [ ] Expired OTP -> clear error; user stays `pending`
- [ ] Reuse OTP after success -> blocked

## 2) Login -> Dashboard (safe path)

- [ ] Login with correct credentials
- [ ] Expected: API returns `200` (or `202` if 2FA enabled / high-risk OTP)
- [ ] Expected: cookies set (`vpsphere_token`, `refreshToken`)
- [ ] Expected: `GET /auth/me` returns user object and does not 401-loop
- [ ] Expected: dashboard does not auto-logout within 1-2 seconds

### New device email
- [ ] Login from a different browser/device (or clear cookies)
- [ ] Expected: “New Device Login Detected” email arrives

## 3) Refresh token rotation + reuse detection

### Happy path
- [ ] Wait until access token expires OR manually call refresh from UI
- [ ] `POST /auth/refresh` returns `200`
- [ ] Expected: new `refreshToken` cookie is set (rotated)
- [ ] Expected DB: session row has `previous_refresh_token_hash` updated and `refresh_token_hash` changed

### Reuse detection
Test idea (advanced):
- [ ] Capture refresh cookie value before refresh (cookie A)
- [ ] Refresh once (cookie rotates to cookie B)
- [ ] Attempt refresh again using cookie A (old token)
- [ ] Expected: `403` "reuse detected" and the session is revoked

## 4) Sessions API (Active Devices)

- [ ] With valid login cookies, call `GET /api/sessions`
- [ ] Expected: `200` and `{ sessions: [...] }`
- [ ] Expected: at least 1 session, and exactly one has `current_device: true`
- [ ] Expected: `last_active` updates over time (not every request; throttled)

### Revoke a device
- [ ] Revoke a non-current session: `POST /api/sessions/:id/revoke`
- [ ] Expected: `200` and session disappears from list
- [ ] Expected: “Device Removed” email is sent

### Revoke current device
- [ ] Revoke current session: `POST /api/sessions/:id/revoke` where id == current sid
- [ ] Expected: server clears cookies and UI returns to login

### Revoke all devices
- [ ] `POST /api/sessions/revoke-all`
- [ ] Expected: all sessions revoked except current

## 5) Risk scoring login (Phase 2 behavior)

### Medium risk (31-59)
- [ ] Trigger: login from a new device or new country (if `cf-ipcountry` is present)
- [ ] Expected: login still succeeds
- [ ] Expected: alert email “Suspicious Login Attempt Detected”
- [ ] Expected DB: `security_logs` row inserted

### High risk (>=60) OTP gating
- [ ] Trigger: new country within short window, or other conditions
- [ ] Expected: `POST /auth/login` returns `202 { requires_otp: true, challengeId }`
- [ ] Expected: “Login Blocked — Verification Required” email received with OTP
- [ ] Complete: `POST /auth/login/otp/verify { challengeId, otp }`
- [ ] Expected: `200`, cookies set, dashboard loads

### Negative tests
- [ ] Wrong OTP -> `401`
- [ ] Expired challenge -> `400`
- [ ] Reuse challenge -> blocked

## 6) Forgot password -> reset -> auto-login

- [ ] `POST /auth/forgot-password` with a valid email returns `200`
- [ ] Password reset email renders properly (Stitch design) with:
  - [ ] `{{reset_link}}`
  - [ ] `{{ip_address}}`, `{{request_time}}`
- [ ] Reset using UI -> password updated
- [ ] Expected: all old sessions revoked, new session created, cookies set
- [ ] Expected: password reset success email sent

## 7) 2FA flows

- [ ] Enable 2FA (generate + verify setup)
- [ ] Login -> should return `202 requires_2fa`
- [ ] 2FA login -> should set cookies and create `user_sessions` row with `sid`

## 8) Rate limiting + CSRF + CORS regressions

- [ ] `OPTIONS` preflights to `/auth/*` return `200/204` with correct CORS headers
- [ ] `/auth/logout` works without CSRF header (must clear cookies)
- [ ] `/auth/login/otp/verify` works without CSRF header (bootstrap step)
- [ ] Spam login attempts -> rate limit triggers; browser should NOT show fake “CORS error”

## 9) Security sanity checks

- [ ] No auth tokens in localStorage/sessionStorage
- [ ] Cookies are HttpOnly, Secure in production, SameSite strict where applicable
- [ ] Refresh tokens are not stored plaintext in DB (hashes only)
- [ ] DB: `user_sessions` revoked sessions do not work on refresh

