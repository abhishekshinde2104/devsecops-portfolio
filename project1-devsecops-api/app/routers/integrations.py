from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status

from app import ssrf
from app.logging_config import security_event
from app.ratelimit import enforce
from app.schemas import UrlPreviewRequest, UrlPreviewResponse
from app.security import CurrentUser, SettingsDep

router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.post("/url-preview", response_model=UrlPreviewResponse)
def url_preview(
    body: UrlPreviewRequest, request: Request, user: CurrentUser, settings: SettingsDep
) -> UrlPreviewResponse:
    """Fetch a remote page's status and <title> (e.g. to preview a payment link)."""
    enforce(request, "outbound", user.id, settings.outbound_rate_limit, settings.outbound_rate_window_seconds)
    try:
        result = ssrf.fetch_preview(body.url, settings)
    except ssrf.OutboundRequestBlocked as exc:
        security_event("outbound_blocked", user_id=user.id, reason=exc.reason)
        # The reason is returned because it is a fixed, non-sensitive string;
        # it never echoes resolved IPs or upstream error text.
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"URL not allowed: {exc.reason}") from None
    return UrlPreviewResponse(
        url=body.url,
        status_code=result.status_code,
        content_type=result.content_type,
        title=result.title,
        redirect_location=result.redirect_location,
    )
