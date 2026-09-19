# SIA-02: Broken authentication and weak JWT handling

| Field | Value |
|---|---|
| OWASP | API2:2023 Broken Authentication; A07:2021 Identification and Authentication Failures |
| CWE | CWE-347 Improper Verification of Cryptographic Signature; CWE-287 Improper Authentication; CWE-916 Weak Password Hash |
| CVSS 3.1 (if absent) | **9.1 Critical**: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (token forgery gives access to any account) |
| Affected surface | `POST /auth/login`, `POST /auth/register`, every authenticated endpoint |
| Status | Mitigated |

## Threat
JWT-based APIs are commonly broken by: accepting unsigned tokens (`alg: none`)
or an unexpected algorithm; weak or guessable signing keys; missing expiry, so
stolen tokens never die; trusting authorization claims such as `role` from the
token; and weak password storage.

## Control
- **Pinned algorithm**: `jwt.decode(..., algorithms=["HS256"])`. Unsigned and
  other-algorithm tokens are rejected ([security.py](../../app/security.py)).
- **Required claims**: `exp`, `iat`, `nbf`, `iss`, `aud`, `sub`, `jti` must be
  present and valid; a `typ=access` check stops other token types being
  replayed.
- **Short-lived tokens**: 15 minutes by default (settings cap it at 60).
- **Strong key from the environment**: ≥32 characters, placeholders rejected,
  and the app refuses to start otherwise (SIA-07).
- **Role never trusted from the token**: user and role are re-loaded from the
  database on every request, so deactivation and role changes apply
  immediately.
- **Argon2id password hashing** (salted, memory-hard), with transparent rehash
  on login when parameters change; 12-character minimum.
- **No user enumeration**: identical 401 for an unknown user and a wrong
  password; a dummy hash is verified for unknown users so timing matches
  (CWE-204).
- **Brute-force throttling**: see SIA-06.

## Verification
- `tests/test_auth.py`: alg=none token, wrong-key token, expired token, missing
  `exp`/`aud`/`iss`/`jti`, role claim not trusted, enumeration-safe errors,
  Argon2id format.
- Semgrep: custom `jwt-decode-without-algorithms` and
  `jwt-signature-verification-disabled`, plus community `p/jwt`.

## Residual risk
- No server-side revocation: a stolen token is valid until expiry (≤15 min). A
  `jti` denylist or token-version column is the next step for longer sessions.
- HS256 means every verifier holds the signing key. Move to RS256/EdDSA with a
  JWKS endpoint if other services need to verify tokens.
