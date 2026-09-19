"""Mass assignment (API3:2023) and injection (A03:2021) regression tests."""

from __future__ import annotations

import pytest

from tests.conftest import TEST_PASSWORD


def test_register_rejects_privileged_fields(client):
    resp = client.post(
        "/auth/register",
        json={"email": "m@example.com", "full_name": "M", "password": TEST_PASSWORD, "role": "admin"},
    )
    assert resp.status_code == 422


@pytest.mark.parametrize("field,value", [("role", "admin"), ("is_active", False), ("id", "x"), ("email", "a@b.co")])
def test_profile_update_rejects_privileged_fields(client, alice, field, value):
    resp = client.patch("/users/me", json={field: value}, headers=alice)
    assert resp.status_code == 422
    assert client.get("/users/me", headers=alice).json()["role"] == "user"


def test_profile_update_allows_safe_fields(client, alice):
    resp = client.patch("/users/me", json={"full_name": "Alice Renamed"}, headers=alice)
    assert resp.status_code == 200 and resp.json()["full_name"] == "Alice Renamed"


def test_invoice_owner_cannot_be_set_by_client(client, alice, bob):
    bob_id = client.get("/users/me", headers=bob).json()["id"]
    resp = client.post("/invoices", json={"customer_name": "X", "amount_cents": 1, "owner_id": bob_id}, headers=alice)
    assert resp.status_code == 422
    inv = client.post("/invoices", json={"customer_name": "X", "amount_cents": 1}, headers=alice).json()
    assert client.patch(f"/invoices/{inv['id']}", json={"owner_id": bob_id}, headers=alice).status_code == 422


@pytest.mark.parametrize(
    "term",
    ["' OR '1'='1", "x'; DROP TABLE invoices; --", '" OR 1=1 --', "%", "_", "\\"],
)
def test_search_treats_input_as_literal(client, alice, term):
    client.post("/invoices", json={"customer_name": "Normal Customer", "amount_cents": 1}, headers=alice)
    resp = client.get("/invoices/search", params={"q": term}, headers=alice)
    assert resp.status_code == 200
    assert resp.json() == []  # neither matches everything nor errors
    assert len(client.get("/invoices", headers=alice).json()) == 1  # table intact


def test_search_matches_literal_substring(client, alice):
    client.post("/invoices", json={"customer_name": "100% Organic Ltd", "amount_cents": 1}, headers=alice)
    client.post("/invoices", json={"customer_name": "1000 Things", "amount_cents": 1}, headers=alice)
    names = [i["customer_name"] for i in client.get("/invoices/search", params={"q": "100%"}, headers=alice).json()]
    assert names == ["100% Organic Ltd"]


def test_amount_and_currency_validated(client, alice):
    assert client.post("/invoices", json={"customer_name": "X", "amount_cents": -5}, headers=alice).status_code == 422
    bad_currency = {"customer_name": "X", "amount_cents": 5, "currency": "eur1"}
    assert client.post("/invoices", json=bad_currency, headers=alice).status_code == 422
