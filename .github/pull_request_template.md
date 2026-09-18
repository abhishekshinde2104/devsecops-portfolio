## What changed

## Security checklist
- [ ] New endpoints enforce authentication and object-level authorization (owner filter in the query)
- [ ] New input models use `StrictInput` (extra="forbid") and expose only client-writable fields
- [ ] No raw SQL string building; no outbound HTTP outside `app/ssrf.py`
- [ ] No secrets in code, tests or config; new settings come from the environment
- [ ] Regression test added for any security-relevant behaviour
- [ ] Security gate is green, or an exception with owner + expiry is added to `security-gate.toml`
