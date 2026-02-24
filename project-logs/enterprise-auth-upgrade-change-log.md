# Enterprise Auth Upgrade - Change Log (Code + Server)

Generated: 2026-02-22

Purpose: if you change IDE/agent, this file tells the next engineer exactly what changed, where, and why.

## Database / Scripts

- Updated `deployment-engine/scripts/init_db.js`
  - Added `CREATE EXTENSION IF NOT EXISTS pgcrypto`
  - Added tables:
    - `user_sessions` (refresh token hashes, device metadata, rotation fields)
    - `security_logs`
    - `login_challenges`
  - Added indexes on `user_sessions` and log tables

- Added `deployment-engine/scripts/migrate_refresh_tokens_to_user_sessions.js`
  - One-time migration: copies legacy `refresh_tokens.hashed_token` into `user_sessions.refresh_token_hash`
  - Safe to re-run due to unique index

- Added `deployment-engine/scripts/sync_stitch_email_templates.js`
  - Syncs `D:\antigravitey\VPSphere\email template\*\code.html` into `deployment-engine/email/templates/*.html`
  - Applies placeholder fixes for verification + reset flows

## Backend Auth / Sessions

- Updated `deployment-engine/routes/auth.js`
  - Login now creates `user_sessions` row and issues access JWT with `sid`
  - Refresh rotation now uses `user_sessions` with reuse detection
  - Logout revokes session (by refresh hash or sid) and clears cookies
  - Risk scoring integrated:
    - Medium risk -> security log + alert email
    - High risk -> creates `login_challenges`, sends OTP, returns `202 requires_otp`
  - Added `POST /auth/login/otp/verify` to complete high-risk login

- Updated `deployment-engine/routes/2fa.js`
  - 2FA login now creates `user_sessions` + `sid` (no legacy refresh_tokens)
  - 2FA setup routes switched to cookie-based auth middleware

- Added `deployment-engine/routes/sessions.js`
  - `GET /api/sessions`
  - `POST /api/sessions/:id/revoke` (sends device removed email best-effort)
  - `POST /api/sessions/revoke-all`

- Added `deployment-engine/middleware/sessionActivity.js`
  - Throttled updates of `user_sessions.last_active` based on `req.user.sid`

- Updated `deployment-engine/server.js`
  - Mounted `/api/sessions`
  - Wired `sessionActivity()` into `/deploy`, `/project`, `/payments`, `/api/sessions`

## Phase 2 Services

- Added `deployment-engine/services/riskScoring.js`
- Added `deployment-engine/services/securityLogger.js`

## Email Templates + Mailer

- Updated `deployment-engine/services/mailer-otp.js`
  - Uses synced templates in `deployment-engine/email/templates`
  - Added dedicated mail functions:
    - `sendNewDeviceLoginDetectedEmail`
    - `sendSuspiciousLoginAttemptEmail`
    - `sendLoginBlockedOtpEmail`
    - `sendDeviceRemovedEmail`
    - `sendAccountLockedEmail`

- Added runtime templates:
  - `deployment-engine/email/templates/vpsphere_login_blocked_verification_required_email.html`
  - `deployment-engine/email/templates/vpsphere_device_removed_email.html`

## CSRF

- Updated `deployment-engine/middleware/csrfProtection.js`
  - Exempted: `/auth/logout`, `/auth/login/otp/verify` (bootstrap + cookie clearing)

## On-Server Deploy Notes (Main Server)

Server used during work: `192.168.1.236`

Paths:
- Backend: `/home/tushar/deployment-engine-1`
- Frontend: `/home/tushar/vpsphere-2`

Services:
- PM2 process: `vpsphere-api`, `vpsphere-frontend`

Important:
- A previous deploy mistake copied `routes/sessions.js` into the wrong folder once, causing a crash (Cloudflare 502).
  - Fixed by placing `sessions.js` in `/routes/` and `sessionActivity.js` in `/middleware/`.

## Hardening Snapshot + Checklist

- Created `deployment-engine/project-logs/phase3-hardening-checklist.md`
  - Current gaps: UFW allows port `3000`, SSH `PasswordAuthentication yes`, HSTS missing on main domain, extra open ports `8000/6001/6002`

