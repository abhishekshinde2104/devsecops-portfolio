# SIA-01: Broken object-level authorization (BOLA / IDOR)

| Field | Value |
|---|---|
| OWASP | API1:2023 Broken Object Level Authorization; A01:2021 Broken Access Control |
| CWE | CWE-639 Authorization Bypass Through User-Controlled Key |
| CVSS 3.1 (if absent) | **8.1 High**: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` |
| Affected surface | `GET/PATCH/DELETE /invoices/{invoice_id}`, `GET /invoices`, `GET /invoices/search` |
| Status | Mitigated |

## Threat
Invoices are addressed by ID. If a handler loads an invoice by ID alone, any
authenticated user can read, change or delete another tenant's invoices by
supplying their IDs. Authentication succeeds; authorization of the *specific
object* is what's missing. This is the most common real-world API weakness.

## Control
- **Ownership is enforced inside the query**, not after it:
  `select(Invoice).where(Invoice.id == invoice_id, Invoice.owner_id == user.id)`
  ([`_get_owned_invoice`](../../app/routers/invoices.py)). There's no code path
  that loads an invoice without the owner filter.
- **List and search** are scoped the same way, so they can't be used to
  discover foreign objects.
- **Foreign and non-existent IDs both return `404`** with an identical body, so
  the API doesn't reveal which IDs exist.
- **Random UUIDv4 identifiers** as defence in depth against enumeration. The
  design's security does *not* depend on IDs being secret.
- **Detection**: a lookup of an ID that exists but belongs to someone else
  increments `authz_denied_total{resource="invoice",reason="not_owner"}` and
  emits a `bola_attempt` security event. Project 3 alerts on spikes.

## Verification
`tests/test_authorization.py`: cross-tenant read, update and delete; list and
search isolation; identical 404 for foreign vs missing IDs; metric emission.

## Residual risk
Object checks are per-handler. New resources must reuse the owner-scoped query
pattern (PR checklist item). A global tenant filter (SQLAlchemy
`with_loader_criteria`) would make this default-deny; recorded as a follow-up.
