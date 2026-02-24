# VPSphere Production Hardening Checklist

Generated: 2026-02-22

This is a practical production checklist focused on Nginx/SSH/firewall/Fail2ban/SPF-DKIM-DMARC and a snapshot of what is currently configured on the server (`192.168.1.236`).

## Current Snapshot (Observed)

- Host: `vpxphere-server` (Ubuntu kernel `6.8.0-100-generic`)
- Listening services (ss):
  - Public listeners detected: `:22` (SSH), `:80` (nginx), `:3000` (next), `:5000` (node api), `:8000`, `:6001`, `:6002`
  - Local-only (good): Postgres `127.0.0.1:5432`, Redis `127.0.0.1:6379`
- UFW:
  - Status: active, default deny incoming
  - Allowed inbound: `22/tcp`, `80`, `443`, `3000`
- Fail2ban:
  - Enabled with 1 jail: `sshd`
- SSHD effective config (via sudo):
  - `permitrootlogin without-password` (root via keys only)
  - `passwordauthentication yes` (needs hardening)
  - `pubkeyauthentication yes`
  - `kbdinteractiveauthentication no`
  - `maxauthtries 6`
  - `usepam yes`
- Nginx:
  - `listen 80 default_server` is enabled
  - `listen 443 ssl` appears commented (TLS likely handled at Cloudflare edge/tunnel)
  - `server_name vpsphere.devtushar.uk` proxies to `http://localhost:3000`
- HTTPS headers:
  - `https://api.devtushar.uk/health` returns `strict-transport-security: max-age=31536000; includeSubDomains`
  - `https://devtushar.uk/` does not currently return an HSTS header
- Email DNS:
  - No SPF/DMARC TXT records were returned for `devtushar.uk` / `_dmarc.devtushar.uk` from the local resolver during checks

## Network / Edge (Nginx + Ports)

- [ ] Close direct internet access to the Next.js port
  - Current: UFW allows inbound `3000`
  - Target: only `22`, `80`, `443` should be reachable from the internet
  - Action: remove the UFW rule for `3000` and ensure Cloudflare tunnel / Nginx is the only ingress
- [ ] Ensure API port `5000` is not directly reachable from the internet
  - Target: bind API to `127.0.0.1:5000` if Cloudflare tunnel runs on the same host, or only allow inbound from trusted reverse proxy
- [ ] Confirm what `:8000`, `:6001`, `:6002` are for, then restrict them
  - Target: if these are internal-only services, bind to localhost and/or block at firewall
- [ ] Add upstream request hardening in Nginx (even if Cloudflare is in front)
  - `client_max_body_size` (protect uploads)
  - timeouts (`proxy_read_timeout`, `proxy_send_timeout`)
  - websocket headers where needed
- [ ] HSTS for the main app domain (if Cloudflare is the TLS terminator)
  - Configure via Cloudflare “HSTS” / “Transform Rules” / “Response Headers”
  - Target: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` (only when ready)

## Firewall (UFW)

- [x] Default deny incoming is enabled (good baseline)
- [ ] Remove `3000` allow rule
- [ ] Consider restricting SSH (`22`) to your admin IP(s) only
- [ ] Confirm Docker published ports are not unintentionally exposed
  - Docker adds iptables rules; prefer explicit UFW rules + avoid `-p 0.0.0.0:PORT` unless required

## SSH Hardening

- [ ] Disable password authentication
  - Current: `passwordauthentication yes`
  - Target: `PasswordAuthentication no`
- [ ] Enforce key-only auth + disable root login fully
  - Current: `permitrootlogin without-password`
  - Target: `PermitRootLogin no` (recommended)
- [ ] Reduce `MaxAuthTries`
  - Current: `6`
  - Target: `3` to `5`
- [ ] Ensure strong ciphers/mac/kex defaults (optional but recommended)
- [ ] Ensure `AllowUsers tushar` (or explicit admin user list) (optional)

## Fail2ban

- [x] `sshd` jail is enabled
- [ ] Add a jail for Nginx/HTTP auth endpoints (optional, but helpful)
  - Protect `/auth/login`, `/auth/login/otp/verify`, `/auth/otp/*`
  - Ensure it works correctly behind Cloudflare (use real client IP headers in logs)

## Database Security

- [x] Postgres bound to localhost (`127.0.0.1:5432`)
- [ ] Ensure Postgres enforces TLS if accessed remotely (ideal: do not expose remotely at all)
- [ ] Backups: automated daily backups + restore test cadence
- [ ] Audit logging retention and access control

## VPS / Host Security

- [ ] SSH key-only, disable root login, least-privilege sudo rules
- [ ] OS updates: unattended security updates enabled (or manual patch window)
- [ ] File integrity + log rotation + disk monitoring
- [ ] Fail2ban + basic port scan monitoring

## Email Security (SPF / DKIM / DMARC)

- [ ] SPF TXT record for sending identity
  - Example: `v=spf1 include:_spf.google.com ~all` (if Gmail is the sender)
- [ ] DKIM enabled (if using Google Workspace/Gmail, publish Google DKIM selector)
- [ ] DMARC record at `_dmarc.devtushar.uk`
  - Start with monitoring: `v=DMARC1; p=none; rua=mailto:dmarc@devtushar.uk; fo=1`
  - Move to enforcement: `p=quarantine` then `p=reject`

## Quick Fix Priority (Recommended Order)

1. Remove UFW inbound `3000`
2. Disable SSH password authentication
3. Confirm API `5000` ingress path (Cloudflare tunnel vs direct) and bind/restrict accordingly
4. Add HSTS at Cloudflare for `devtushar.uk` (after confirming HTTPS-only is stable)
5. Publish SPF + DKIM + DMARC

