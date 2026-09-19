# SIA-04: Mass assignment

| Field | Value |
|---|---|
| OWASP | API3:2023 Broken Object Property Level Authorization |
| CWE | CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes |
| CVSS 3.1 (if absent) | **8.1 High**: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` (self-promotion to admin) |
| Affected surface | `POST /auth/register`, `PATCH /users/me`, `POST/PATCH /invoices` |
| Status | Mitigated |

## Threat
Binding a request body straight onto a model (`User(**body)`, a `setattr` loop
over all keys) lets clients set privileged attributes (`role`, `is_active`,
`owner_id`) by adding keys to the JSON: registering as admin, re-activating a
disabled account, or moving an invoice into another tenant.

## Control
- **Separate input and output schemas** ([schemas.py](../../app/schemas.py)).
  Input models contain only client-writable fields; privileged fields appear in
  no user-facing input model.
- **`extra="forbid"`** on every input model (the `StrictInput` base): unknown or
  privileged keys give `422` rather than being silently ignored, so tampering
  is visible.
- **Server-side assignment** of `role="user"` at registration and
  `owner_id=user.id` at invoice creation.
- **Role changes only through `PATCH /admin/users/{id}/role`**, which is
  admin-only (SIA-08) and audit-logged (`role_changed`).
- **Output schemas** never include `password_hash`.

## Verification
- `tests/test_input_handling.py`: `role`, `is_active`, `id`, `email` rejected on
  profile update; `role` on registration; `owner_id` on invoice create and
  update.
- Semgrep custom rules `pydantic-model-allows-extra-fields` and
  `orm-object-from-raw-request-body`.

## Residual risk
Low. A new input model that skips `StrictInput` is caught by the PR checklist,
and by Semgrep if it sets `extra="allow"`.
