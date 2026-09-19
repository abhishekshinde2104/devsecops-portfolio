# Test cases for fastapi-security.yml. Never imported or executed; every string
# here is an obvious placeholder. "ruleid" lines must match, "ok" lines must not.
# ruff: noqa
import jwt
import sqlalchemy
from fastapi.middleware.cors import CORSMiddleware
from pydantic import ConfigDict

# ruleid: jwt-decode-without-algorithms
jwt.decode(token, key)
# ok: jwt-decode-without-algorithms
jwt.decode(token, key, algorithms=["HS256"], audience="aud")

# ruleid: jwt-signature-verification-disabled
jwt.decode(token, key, algorithms=["HS256"], options={"verify_signature": False})
# ok: jwt-signature-verification-disabled
jwt.decode(token, key, algorithms=["HS256"], options={"require": ["exp"]})

# ruleid: raw-sql-string-building
sqlalchemy.text(f"SELECT * FROM invoices WHERE name = '{name}'")
# ruleid: raw-sql-string-building
db.execute("SELECT * FROM users WHERE id = " + user_id)
# ok: raw-sql-string-building
sqlalchemy.text("SELECT * FROM invoices WHERE name = :name").bindparams(name=name)

# ruleid: outbound-http-outside-ssrf-guard
requests.get(user_supplied_url)
# ruleid: outbound-http-outside-ssrf-guard
httpx.AsyncClient(follow_redirects=True)
# ok: outbound-http-outside-ssrf-guard
ssrf.fetch_preview(user_supplied_url, settings)

# ruleid: pydantic-model-allows-extra-fields
model_config = ConfigDict(extra="allow")
# ok: pydantic-model-allows-extra-fields
model_config = ConfigDict(extra="forbid")


async def handler(request):
    # ruleid: orm-object-from-raw-request-body
    user = User(**(await request.json()))
    # ok: orm-object-from-raw-request-body
    user = User(**body.model_dump())


# ruleid: hardcoded-signing-secret
SECRET_KEY = "placeholder"
# ruleid: hardcoded-signing-secret
jwt.encode(claims, "placeholder", algorithm="HS256")
# ok: hardcoded-signing-secret
SECRET_KEY = os.environ["APP_SECRET_KEY"]
# ok: hardcoded-signing-secret
APP_NAME = "placeholder"

# ruleid: cors-wildcard-with-credentials
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
# ok: cors-wildcard-with-credentials
app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"], allow_credentials=True)
