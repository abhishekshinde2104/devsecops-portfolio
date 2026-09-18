"""Invoice endpoints.

Object-level authorization (OWASP API1:2023, CWE-639): every query that
touches an invoice is filtered by ``owner_id == current_user.id`` *in SQL*.
Objects owned by someone else are indistinguishable from objects that do not
exist (404), so the API does not confirm which IDs are valid.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from sqlalchemy import select

from app.logging_config import security_event
from app.metrics import AUTHZ_DENIED
from app.models import Invoice, User
from app.schemas import InvoiceCreate, InvoiceOut, InvoiceStatus, InvoiceUpdate
from app.security import CurrentUser, DbDep

router = APIRouter(prefix="/invoices", tags=["invoices"])

MAX_PAGE_SIZE = 100


def _escape_like(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _get_owned_invoice(db: DbDep, request: Request, invoice_id: str, user: User) -> Invoice:
    invoice = db.scalar(select(Invoice).where(Invoice.id == invoice_id, Invoice.owner_id == user.id))
    if invoice is None:
        # Record *that* a cross-tenant lookup happened (useful for BOLA
        # detection in Prometheus) without telling the caller.
        if db.scalar(select(Invoice.id).where(Invoice.id == invoice_id)) is not None:
            AUTHZ_DENIED.labels(resource="invoice", reason="not_owner").inc()
            security_event("bola_attempt", user_id=user.id, path=request.url.path)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invoice not found")
    return invoice


@router.get("", response_model=list[InvoiceOut])
def list_invoices(
    user: CurrentUser,
    db: DbDep,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 20,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    status_filter: Annotated[InvoiceStatus | None, Query(alias="status")] = None,
) -> list[Invoice]:
    stmt = select(Invoice).where(Invoice.owner_id == user.id)
    if status_filter is not None:
        stmt = stmt.where(Invoice.status == status_filter)
    stmt = stmt.order_by(Invoice.created_at.desc()).limit(limit).offset(offset)
    return list(db.scalars(stmt))


@router.get("/search", response_model=list[InvoiceOut])
def search_invoices(
    user: CurrentUser,
    db: DbDep,
    q: Annotated[str, Query(min_length=1, max_length=100)],
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 20,
) -> list[Invoice]:
    # Parameterised via the ORM (CWE-89); LIKE wildcards in user input are
    # escaped so "%" cannot be used to dump everything or cause slow scans.
    stmt = (
        select(Invoice)
        .where(Invoice.owner_id == user.id)
        .where(Invoice.customer_name.ilike(f"%{_escape_like(q)}%", escape="\\"))
        .order_by(Invoice.created_at.desc())
        .limit(limit)
    )
    return list(db.scalars(stmt))


@router.post("", response_model=InvoiceOut, status_code=status.HTTP_201_CREATED)
def create_invoice(body: InvoiceCreate, user: CurrentUser, db: DbDep) -> Invoice:
    invoice = Invoice(owner_id=user.id, **body.model_dump())
    db.add(invoice)
    db.commit()
    return invoice


@router.get("/{invoice_id}", response_model=InvoiceOut)
def get_invoice(invoice_id: str, request: Request, user: CurrentUser, db: DbDep) -> Invoice:
    return _get_owned_invoice(db, request, invoice_id, user)


@router.patch("/{invoice_id}", response_model=InvoiceOut)
def update_invoice(invoice_id: str, body: InvoiceUpdate, request: Request, user: CurrentUser, db: DbDep) -> Invoice:
    invoice = _get_owned_invoice(db, request, invoice_id, user)
    for field, value in body.model_dump(exclude_unset=True, exclude_none=True).items():
        setattr(invoice, field, value)  # fields limited to InvoiceUpdate's allowlist
    db.commit()
    return invoice


@router.delete("/{invoice_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_invoice(invoice_id: str, request: Request, user: CurrentUser, db: DbDep) -> Response:
    invoice = _get_owned_invoice(db, request, invoice_id, user)
    db.delete(invoice)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
