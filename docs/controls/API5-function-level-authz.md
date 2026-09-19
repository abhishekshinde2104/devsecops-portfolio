# SIA-08: Broken function-level authorization

| Field | Value |
|---|---|
| OWASP | API5:2023 Broken Function Level Authorization; A01:2021 |
| CWE | CWE-285 Improper Authorization |
| CVSS 3.1 (if absent) | **8.1 High**: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` |
| Affected surface | `/admin/*` |
| Status | Mitigated |

## Threat
Admin endpoints are often protected only by being undocumented, or the role
check is added per handler and forgotten on the next one.

## Control
- `require_admin` is a **router-level dependency** on the admin router
  ([admin.py](../../app/routers/admin.py)), so every current and future route
  under `/admin` inherits it.
- The role is read from the database, never from the token (SIA-02).
- Admins can't demote themselves (so the system can't be left without an
  admin), and every role change is audit-logged.
- Admin accounts are created only out-of-band (`python -m app.cli
  create-admin`), with the password read from the environment or a prompt,
  never from argv.
- Denials increment `authz_denied_total{resource="admin"}`.

## Verification
`tests/test_authorization.py`: a regular user gets `403` on list and role change;
admin success path; self-demotion blocked. `tests/test_cli.py`: admin bootstrap
and its password-length check.
