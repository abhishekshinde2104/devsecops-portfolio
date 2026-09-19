"""Object- and function-level authorization (API1:2023 BOLA, API5:2023 BFLA)."""

from __future__ import annotations

from tests.conftest import login, register


def _create_invoice(client, headers, name="ACME GmbH") -> dict:
    resp = client.post("/invoices", json={"customer_name": name, "amount_cents": 12_500}, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_owner_can_read_update_delete(client, alice):
    inv = _create_invoice(client, alice)
    assert client.get(f"/invoices/{inv['id']}", headers=alice).status_code == 200
    assert client.patch(f"/invoices/{inv['id']}", json={"status": "sent"}, headers=alice).json()["status"] == "sent"
    assert client.delete(f"/invoices/{inv['id']}", headers=alice).status_code == 204


def test_other_user_cannot_read_invoice(client, alice, bob):
    inv = _create_invoice(client, alice)
    resp = client.get(f"/invoices/{inv['id']}", headers=bob)
    assert resp.status_code == 404  # indistinguishable from "does not exist"


def test_other_user_cannot_modify_or_delete_invoice(client, alice, bob):
    inv = _create_invoice(client, alice)
    assert client.patch(f"/invoices/{inv['id']}", json={"amount_cents": 1}, headers=bob).status_code == 404
    assert client.delete(f"/invoices/{inv['id']}", headers=bob).status_code == 404
    assert client.get(f"/invoices/{inv['id']}", headers=alice).json()["amount_cents"] == 12_500


def test_list_and_search_only_return_own_invoices(client, alice, bob):
    _create_invoice(client, alice, "Alice Customer")
    _create_invoice(client, bob, "Bob Customer")
    listed = client.get("/invoices", headers=bob).json()
    assert [i["customer_name"] for i in listed] == ["Bob Customer"]
    found = client.get("/invoices/search", params={"q": "Customer"}, headers=bob).json()
    assert [i["customer_name"] for i in found] == ["Bob Customer"]


def test_nonexistent_and_foreign_ids_return_same_response(client, alice, bob):
    inv = _create_invoice(client, alice)
    foreign = client.get(f"/invoices/{inv['id']}", headers=bob)
    missing = client.get("/invoices/00000000-0000-0000-0000-000000000000", headers=bob)
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json() == missing.json()


def test_cross_tenant_attempt_is_counted_in_metrics(client, alice, bob):
    inv = _create_invoice(client, alice)
    client.get(f"/invoices/{inv['id']}", headers=bob)
    metrics = client.get("/metrics").text
    assert 'authz_denied_total{reason="not_owner",resource="invoice"}' in metrics


def test_regular_user_cannot_use_admin_endpoints(client, alice):
    assert client.get("/admin/users", headers=alice).status_code == 403
    me = client.get("/users/me", headers=alice).json()
    assert client.patch(f"/admin/users/{me['id']}/role", json={"role": "admin"}, headers=alice).status_code == 403


def test_admin_can_manage_roles(client, make_admin):
    register(client, "root@example.com")
    make_admin("root@example.com")
    admin = login(client, "root@example.com")
    target = register(client, "promote-me@example.com")
    resp = client.patch(f"/admin/users/{target['id']}/role", json={"role": "admin"}, headers=admin)
    assert resp.status_code == 200 and resp.json()["role"] == "admin"
    assert client.get("/admin/users", headers=admin).status_code == 200


def test_admin_cannot_demote_self(client, make_admin):
    me = register(client, "solo-admin@example.com")
    make_admin("solo-admin@example.com")
    admin = login(client, "solo-admin@example.com")
    assert client.patch(f"/admin/users/{me['id']}/role", json={"role": "user"}, headers=admin).status_code == 400


def test_page_size_is_bounded(client, alice):
    assert client.get("/invoices", params={"limit": 10_000}, headers=alice).status_code == 422
