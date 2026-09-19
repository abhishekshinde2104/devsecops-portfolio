# SIA-03: SQL injection

| Field | Value |
|---|---|
| OWASP | A03:2021 Injection |
| CWE | CWE-89 Improper Neutralization of Special Elements used in an SQL Command |
| CVSS 3.1 (if absent) | **8.8 High**: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| Affected surface | `GET /invoices/search?q=`, every database query |
| Status | Mitigated |

## Threat
Building SQL by concatenating or formatting user input lets the input change
the query's structure: read other tenants' rows, modify data, drop tables.
Search endpoints are the classic spot because they tempt hand-written `LIKE`
clauses.

## Control
- **All queries are SQLAlchemy ORM expressions**, which always send user values
  as bound parameters, never as SQL text.
- **LIKE wildcards are escaped** (`_escape_like` + `escape="\\"`), so `%` and
  `_` in the term are literals. That stops "match everything" queries and
  expensive wildcard scans.
- **Input bounds**: `q` is 1–100 characters; results are capped at 100.
- **The owner filter is always applied** (SIA-01), so even a logic bug in
  search can't cross tenants.

## Verification
- `tests/test_input_handling.py`: classic injection payloads return an empty
  result (not all rows and not a 500), the table is intact afterwards, and
  `100%` matches only the literal string.
- Semgrep custom rule `raw-sql-string-building` flags f-strings,
  concatenation, `.format()` and `%` passed to `text()` or `execute()`;
  community `p/python` and ruff `S608` form a second layer.

## Residual risk
Raw SQL remains possible through `text()` with bound parameters. That's
intended, and the rule only permits the parameterised form.
