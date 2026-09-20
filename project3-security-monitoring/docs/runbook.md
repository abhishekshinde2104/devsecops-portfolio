# Security alert runbook

One entry per detection. Each links back to the Project 1 control it watches
and the ATT&CK technique it maps to. Alerts carry `team: security` so
Alertmanager routes them to the security webhook (the SOC's SIEM/chat stand-in).

How to read a firing alert:
1. Open Grafana → **Invoice API – Security Overview**; the top row shows which
   detection is hot and the trend.
2. Confirm in Prometheus with the alert's recording-rule expression.
3. Decide: real attack, abuse, or a threshold that needs tuning (thresholds are
   deliberately low for a low-traffic lab — see the bottom of this file).

---

## InvoiceApiBruteForceLogin <a id="bruteforce"></a>
- **Control:** SIA-06 (rate limiting) · **ATT&CK:** T1110 Brute Force
- **Fires when:** >20 failed logins in 5m (`invoice_api:login_failures:increase5m`).
- **Triage:** Grafana "Failed + throttled logins" and "Login outcomes". Is it
  one account (targeted) or many (spraying)? Check source IPs at the ingress.
- **Response:** the app already throttles per-IP+account and per-account
  (SIA-06); confirm 429s are being returned ("Rate limiter rejections by
  scope" panel). If a single account is targeted, notify its owner. Sustained
  distributed attempts → block at the ingress/WAF.
- **False positives:** a broken client looping on a bad password; a load test.

## InvoiceApiCredentialStuffingThrottled
- **Control:** SIA-06 · **ATT&CK:** T1110.004 Credential Stuffing
- **Fires when:** >30 login requests rejected by the rate limiter in 5m.
- **Meaning:** the throttle is doing its job at volume; treat as a stronger
  brute-force signal. Same response as above.

## InvoiceApiTokenTampering
- **Control:** SIA-02 (JWT hardening) · **ATT&CK:** T1550.001
- **Fires when:** >10 rejected JWTs in 5m (`token_rejected`).
- **Triage:** reasons split into expired vs invalid in "Rejected tokens by
  reason". A spike of `invalid` (bad signature / forged claims) is an active
  forgery attempt; `expired` alone is usually clients not refreshing.
- **Response:** the signing key is strong and env-sourced (SIA-02/07), so
  forged tokens fail closed. If `invalid` is sustained, check for a leaked
  older token or a client bug; rotating `APP_SECRET_KEY` invalidates all tokens.

## InvoiceApiBOLAProbing
- **Control:** SIA-01 (object-level authz) · **ATT&CK:** API1:2023 / T1078
- **Fires when:** >10 cross-tenant invoice lookups denied in 5m
  (`authz_denied_total{resource="invoice"}`).
- **Meaning:** someone authenticated is requesting invoice IDs they don't own.
  The owner check denies them (404), and the counter records the attempt.
- **Response:** identify the account from the app's `bola_attempt` security
  log events; a legitimate user does not enumerate others' IDs. Consider
  suspending the account. This is the headline attack the API defends against.

## InvoiceApiPrivilegeEscalationAttempts
- **Control:** SIA-08 (function-level authz) · **ATT&CK:** T1068
- **Fires when:** >5 admin-endpoint denials in 5m (`resource="admin"`).
- **Response:** a non-admin is hitting `/admin/*`. Identify the account; the
  router-level check denies them, but repeated attempts are reconnaissance.

## InvoiceApiSSRFAttempts
- **Control:** SIA-05 (SSRF guard) · **ATT&CK:** A10:2021 / T1090
- **Fires when:** >5 outbound requests blocked in 5m
  (`outbound_request_blocked_total`).
- **Meaning:** the URL-preview guard blocked requests to private IPs, the
  metadata endpoint, or bad schemes. Two independent layers stop these (the
  app guard and the Project 2 egress NetworkPolicy).
- **Response:** the block `reason` says what was attempted (metadata,
  loopback, etc.). Sustained attempts on one account = active SSRF probing;
  investigate that user.

## InvoiceApiReconScanning
- **ATT&CK:** T1595 Active Scanning
- **Fires when:** >50 `404`s in 5m — endpoint/path enumeration.
- **Response:** usually an internet background scanner. Confirm no `2xx`
  followed on sensitive paths; block noisy sources at the ingress.

## InvoiceApiAbnormalRequestRate
- **ATT&CK:** T1498 · **Fires when:** >50 req/s over 5m (baseline is ~0 in the lab).
- **Response:** correlate with the login/authz panels — volumetric abuse vs a
  legitimate spike. Rate limits (SIA-06) cap per-client load.

## InvoiceApiHigh5xxRate
- **Fires when:** >5% of requests are 5xx over 5m.
- **Meaning:** errors can indicate exploitation attempts or an overwhelmed
  service. The app returns generic 500s (SIA-09), so details are in the logs.

## InvoiceApiContainerRestarting
- **ATT&CK:** T1499 · **Fires when:** >2 restarts of the `api` container in 15m.
- **Response:** `kubectl -n invoice-api describe pod` and previous logs. Causes:
  crash, OOM (limits are tight by design, SIA/CIS), or tampering with the
  read-only rootfs.

## InvoiceApiDown
- **Fires when:** the target is unscrapable for 2m (`up == 0` or absent).
- **Response:** is the pod running? Is the Project 2 NetworkPolicy still
  admitting the `monitoring` namespace on 8000? A missing target is also how
  an attacker hides, so this is `critical`, not just an availability alert.

---

## Tuning thresholds

The lab generates almost no traffic, so thresholds are low and windows short
(5–15m). For real traffic, baseline each metric for 1–2 weeks and raise the
thresholds (or switch to rate-relative expressions) in
[`rules/security-alerts.rules.yaml`](../rules/security-alerts.rules.yaml).
Every change is covered by the promtool tests in
[`rules/tests/`](../rules/tests/security-alerts.test.yaml), so edit a threshold
and the test tells you which cases move. Alerts and the dashboard share the
recording rules, so a definition changes in one place.
