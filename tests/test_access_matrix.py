"""Exercise every protected route, including future routes in each router."""

import re

import pytest
from fastapi.routing import APIRoute

from netagent.api.admin_routes import admin_access
from tests.conftest import admin_headers, agent_headers, enroll


def protected_routes(app):
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        if route.path == "/health" or (
            route.path.startswith("/api/") and
            not route.path.startswith("/api/agent/") and route.path != "/api/docs"
        ):
            yield route


@pytest.mark.parametrize("identity", ["missing", "invalid", "non_ascii", "agent"])
def test_all_protected_routes_reject_non_admin(full_client, identity):
    headers = {}
    if identity == "invalid":
        headers = agent_headers("invalid-token")
    elif identity == "non_ascii":
        headers = {b"Authorization": b"Bearer invalid-\xff"}
    elif identity == "agent":
        _, token = enroll(full_client)
        headers = agent_headers(token)
    for route in protected_routes(full_client.app):
        assert any(d.call is admin_access for d in route.dependant.dependencies), route.path
        path = re.sub(r"\{[^}]+\}", "1", route.path)
        for method in route.methods:
            response = full_client.request(method, path, headers=headers, json={})
            assert response.status_code == 401, (method, route.path, response.text)
            assert response.headers["www-authenticate"] == "Bearer"


def test_public_health_and_documentation_are_minimal(full_client):
    assert full_client.get("/healthz").json() == {"status": "ok"}
    for path in ("/api/docs", "/openapi.json", "/docs"):
        assert full_client.get(path).status_code == 200
    assert full_client.get("/health").status_code == 401
    assert "components" in full_client.get("/health", headers=admin_headers()).json()


def test_valid_admin_reads_legacy_and_has_openapi_security(full_client):
    for path in ("/api/events", "/api/hosts", "/api/alerts", "/api/tools"):
        assert full_client.get(path, headers=admin_headers()).status_code == 200
    schema = full_client.get("/openapi.json").json()
    for route in protected_routes(full_client.app):
        for method in route.methods:
            assert {"AdministratorBearer": []} in schema["paths"][route.path][method.lower()]["security"]


def test_enrollment_rejects_oversized_payload_and_invalid_proof(full_client):
    for path in ("/api/agent/v1/enroll", "/api/agent/v1/register", "/api/agent/v1/register/test/claim"):
        assert full_client.post(path, json={"data": "x" * 65536}).status_code == 413
    assert full_client.post("/api/agent/v1/enroll", json={"enrollment_token": "wrong"}).status_code == 403


def test_direct_tool_unauthorized_does_not_execute(full_client, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("unauthorized tool reached execution")
    monkeypatch.setattr("netagent.api.routes.execute_tool", forbidden)
    assert full_client.post("/api/tools/ping", json={"host": "127.0.0.1"}).status_code == 401
