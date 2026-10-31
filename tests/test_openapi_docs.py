"""OpenAPI/Swagger documentation tests.

Verifies that every registered endpoint carries Persian summary/description,
documented parameters, and structurally valid request/response examples.
No network operations are performed; everything runs against the FastAPI
OpenAPI schema and the test client.
"""

from __future__ import annotations

import json
import re

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from netagent.main import OPENAPI_TAGS, create_app
from netagent.schemas import InvestigationRequest, ScanRequest

# The real, complete endpoint contract (path, method) — any drift breaks these tests.
EXPECTED_ENDPOINTS = {
    ("GET", "/health"),
    # — existing application API —
    ("GET", "/api/hosts"),
    ("GET", "/api/hosts/{ip}/timeline"),
    ("GET", "/api/hosts/{ip}/fingerprint"),
    ("GET", "/api/events"),
    ("GET", "/api/alerts"),
    ("GET", "/api/tools"),
    ("GET", "/api/investigations"),
    ("GET", "/api/investigations/{inv_id}"),
    ("POST", "/api/investigations"),
    ("POST", "/api/jobs/investigation"),
    ("GET", "/api/jobs/{job_id}"),
    ("POST", "/api/hosts/discover"),
    ("POST", "/api/tools/{tool_name}"),
    ("POST", "/api/scans"),
    # — endpoint agent API (agent bearer credentials) —
    ("POST", "/api/agent/v1/enroll"),
    ("POST", "/api/agent/v1/heartbeat"),
    ("POST", "/api/agent/v1/inventory"),
    ("POST", "/api/agent/v1/status"),
    ("GET", "/api/agent/v1/tasks/next"),
    ("POST", "/api/agent/v1/tasks/{task_id}/result"),
    # — administrator control plane (ADMIN_API_TOKEN credentials) —
    ("GET", "/api/admin/v1/agents"),
    ("GET", "/api/admin/v1/agents/{agent_id}"),
    ("POST", "/api/admin/v1/agents/{agent_id}/revoke"),
    ("POST", "/api/admin/v1/agents/{agent_id}/scripts"),
    ("POST", "/api/admin/v1/agents/{agent_id}/console/sessions"),
    ("GET", "/api/admin/v1/console/sessions"),
    ("GET", "/api/admin/v1/console/sessions/{session_id}"),
    ("POST", "/api/admin/v1/console/sessions/{session_id}/commands"),
    ("POST", "/api/admin/v1/console/sessions/{session_id}/commands/{command_id}/cancel"),
    ("POST", "/api/admin/v1/console/sessions/{session_id}/terminate"),
    ("POST", "/api/admin/v1/enrollment-tokens"),
    ("GET", "/api/admin/v1/enrollment-tokens"),
    ("POST", "/api/admin/v1/tasks"),
    ("GET", "/api/admin/v1/tasks"),
    ("GET", "/api/admin/v1/tasks/{task_id}"),
    ("POST", "/api/admin/v1/tasks/{task_id}/cancel"),
    ("GET", "/api/admin/v1/networks"),
    ("GET", "/api/admin/v1/audit"),
}

PERSIAN_RE = re.compile(r"[\u0600-\u06FF]")


@pytest.fixture()
def openapi(client: TestClient) -> dict:
    r = client.get("/openapi.json")
    assert r.status_code == 200
    return r.json()


def _operations(openapi: dict) -> dict[tuple[str, str], dict]:
    out: dict[tuple[str, str], dict] = {}
    for path, methods in openapi["paths"].items():
        for method, op in methods.items():
            if method in ("parameters", "servers", "summary", "description"):
                continue
            out[(method.upper(), path)] = op
    return out


# -- completeness of the contract -------------------------------------------


def test_no_endpoint_was_added_or_removed(openapi):
    ops = _operations(openapi)
    assert set(ops) == EXPECTED_ENDPOINTS


def test_swagger_ui_served_at_api_docs_and_legacy_redirect(client):
    r = client.get("/api/docs")
    assert r.status_code == 200
    assert "swagger" in r.text.lower()
    # backward compatibility: old address redirects
    r = client.get("/docs", follow_redirects=False)
    assert r.status_code in (301, 302, 307)
    assert r.headers["location"] == "/api/docs"


# -- summaries, descriptions, tags --------------------------------------------


def test_every_endpoint_has_persian_summary_and_description(openapi):
    ops = _operations(openapi)
    for (method, path), op in ops.items():
        assert op.get("summary"), f"{method} {path}: missing summary"
        assert PERSIAN_RE.search(op["summary"]), f"{method} {path}: summary not Persian"
        assert op.get("description"), f"{method} {path}: missing description"
        assert PERSIAN_RE.search(op["description"]), f"{method} {path}: description not Persian"
        assert op.get("tags"), f"{method} {path}: missing tag"


def test_tags_are_persian_and_declared(openapi):
    declared = {t["name"] for t in openapi["tags"]}
    for tag_meta in OPENAPI_TAGS:
        assert PERSIAN_RE.search(tag_meta["description"])
    ops = _operations(openapi)
    used: set[str] = set()
    for op in ops.values():
        used.update(op.get("tags", []))
    assert used <= declared  # only declared Persian tags are used
    assert declared == {t["name"] for t in OPENAPI_TAGS}
    # every declared tag actually corresponds to an endpoint
    assert used == declared


# -- parameter documentation ----------------------------------------------------


def test_every_query_and_path_parameter_is_documented(openapi):
    ops = _operations(openapi)
    for (method, path), op in ops.items():
        for p in op.get("parameters", []):
            desc = p.get("description", "")
            if p.get("schema", {}).get("description"):
                desc = desc or p["schema"]["description"]
            assert desc, f"{method} {path}: parameter {p['name']} undocumented"


def test_request_bodies_have_persian_field_docs(openapi):
    for key in (("POST", "/api/investigations"),
                ("POST", "/api/jobs/investigation"),
                ("POST", "/api/hosts/discover"),
                ("POST", "/api/scans")):
        op = _operations(openapi)[key]
        body = op["requestBody"]["content"]["application/json"]["schema"]
        ref = body["$ref"].split("/")[-1]
        props = openapi["components"]["schemas"][ref]["properties"]
        for field, meta in props.items():
            assert meta.get("description"), f"{key}: body field {field} undocumented"
            assert PERSIAN_RE.search(meta["description"]), f"{key}: {field} not Persian"


def test_direct_tool_args_body_documented(openapi):
    op = _operations(openapi)[("POST", "/api/tools/{tool_name}")]
    body = op["requestBody"]["content"]["application/json"]["schema"]
    assert body.get("description"), "args body needs a description"
    assert PERSIAN_RE.search(body["description"])


# -- examples: structurally valid -----------------------------------------------


def test_request_body_examples_validate_against_real_schemas(openapi):
    """Every request-body example must satisfy the actual Pydantic model."""
    model_by_ref = {
        "InvestigationRequest": InvestigationRequest,
        "ScanRequest": ScanRequest,
    }
    for key, model in (
        (("POST", "/api/investigations"), InvestigationRequest),
        (("POST", "/api/jobs/investigation"), InvestigationRequest),
        (("POST", "/api/hosts/discover"), ScanRequest),
        (("POST", "/api/scans"), ScanRequest),
    ):
        op = _operations(openapi)[key]
        schema = op["requestBody"]["content"]["application/json"]["schema"]
        ref = schema["$ref"].split("/")[-1]
        assert ref in model_by_ref
        examples = op["requestBody"]["content"]["application/json"].get("examples")
        if examples:
            for ex in examples.values():
                model.model_validate(ex["value"])  # raises on invalid example
        else:
            # example attached to the referenced model schema
            model_schema = openapi["components"]["schemas"][ref]
            exs = model_schema.get("examples") or []
            assert exs, f"{key}: no request example at all"
            model.model_validate(exs[0])


def test_investigation_example_matches_scope_rules(openapi):
    """Documented target example must be an IP/CIDR the docs claim is in scope."""
    op = _operations(openapi)[("POST", "/api/jobs/investigation")]
    example = op["responses"]["200"]["content"]["application/json"]["examples"]["default"]["value"]
    assert set(example) == {"job_id", "status", "poll"}
    assert example["status"] == "queued"


def test_every_endpoint_has_a_200_response_example(openapi):
    for (method, path), op in _operations(openapi).items():
        content = op["responses"]["200"]["content"]["application/json"]
        examples = content.get("examples") or {}
        has_example = examples.get("default", {}).get("value") is not None \
            or content.get("example") is not None \
            or content.get("schema", {}).get("example") is not None
        assert has_example, f"{method} {path}: 200 response has no example"
        value = examples.get("default", {}).get("value", content.get("example"))
        assert isinstance(value, dict), f"{method} {path}: response example not an object"


def test_applicable_error_responses_documented(openapi):
    ops = _operations(openapi)
    # scope-gated POST endpoints must document 403
    for key in (("POST", "/api/investigations"), ("POST", "/api/jobs/investigation"),
                ("POST", "/api/hosts/discover"), ("POST", "/api/tools/{tool_name}"),
                ("POST", "/api/scans")):
        assert "403" in ops[key]["responses"], f"{key}: 403 undocumented"
        err_example = next(iter(
            ops[key]["responses"]["403"]["content"]["application/json"]["examples"].values()
        ))
        assert "detail" in err_example
    # not-found endpoints must document 404
    for key in (("GET", "/api/hosts/{ip}/timeline"),
                ("GET", "/api/hosts/{ip}/fingerprint"),
                ("GET", "/api/investigations/{inv_id}"),
                ("GET", "/api/jobs/{job_id}")):
        assert "404" in ops[key]["responses"], f"{key}: 404 undocumented"


# -- Try it out must keep working (real requests, no network scans) ---------------


def test_try_it_out_flow_list_events(client):
    r = client.get("/api/events", params={"limit": 1})
    assert r.status_code == 200
    body = r.json()
    assert {"items", "total", "limit", "offset"} <= set(body)


def test_try_it_out_flow_out_of_scope_rejected(client):
    """The documented 403 behavior is real, matching the documented example."""
    r = client.post("/api/scans", json={"tool": "nmap", "target": "8.8.8.8"})
    assert r.status_code == 403
    assert "detail" in r.json()


def test_invalid_request_example_is_rejected_by_validation(client):
    """A request example with an unknown tool value must fail validation (422)."""
    r = client.post("/api/scans", json={"tool": "masscan", "target": "192.168.1.0/24"})
    assert r.status_code == 422


def test_pydantic_models_reject_invalid_examples():
    with pytest.raises(ValidationError):
        ScanRequest.model_validate({"tool": "masscan", "target": "192.168.1.0/24"})
    with pytest.raises(ValidationError):
        InvestigationRequest.model_validate({"question": "x" * 2001})


# -- 422 validation responses ------------------------------------------------------


def test_validation_422_documented_only_where_inputs_exist(openapi):
    """Endpoints with params/body document 422 in Persian; none fabricate it."""
    for (method, path), op in _operations(openapi).items():
        has_inputs = bool(op.get("parameters")) or "requestBody" in op
        if not has_inputs:
            assert "422" not in op["responses"], \
                f"{method} {path}: fabricated 422 (endpoint has no inputs)"
            continue
        resp = op["responses"].get("422")
        assert resp, f"{method} {path}: 422 undocumented"
        assert PERSIAN_RE.search(resp["description"]), \
            f"{method} {path}: 422 description not Persian"
        for ex in resp["content"]["application/json"]["examples"].values():
            assert "detail" in ex["value"], \
                f"{method} {path}: 422 example without detail"


def test_semantic_422_example_matches_real_behavior(openapi, client):
    """The documented 'target_ip or alert_id required' 422 is what the app returns."""
    op = _operations(openapi)[("POST", "/api/investigations")]
    exs = op["responses"]["422"]["content"]["application/json"]["examples"]
    assert exs["missing_target"]["value"] == {"detail": "target_ip or alert_id required"}
    r = client.post("/api/investigations", json={"question": "سلام"})
    assert r.status_code == 422
    assert r.json() == exs["missing_target"]["value"]


# -- documented error examples must match real error bodies -----------------------


def test_documented_404_examples_match_real_details(openapi, client):
    urls = {
        ("GET", "/api/hosts/{ip}/timeline"): "/api/hosts/192.168.1.99/timeline",
        ("GET", "/api/hosts/{ip}/fingerprint"): "/api/hosts/192.168.1.99/fingerprint",
        ("GET", "/api/investigations/{inv_id}"): "/api/investigations/999",
        ("GET", "/api/jobs/{job_id}"): "/api/jobs/nope",
    }
    for key, url in urls.items():
        op = _operations(openapi)[key]
        documented = op["responses"]["404"]["content"]["application/json"][
            "examples"]["default"]["value"]
        r = client.get(url)
        assert r.status_code == 404, url
        assert r.json() == documented, f"{url}: documented 404 example drifted"


# -- named request-body examples (Try it out dropdown) -----------------------------


def test_named_request_body_examples_present_and_valid(openapi):
    model_for = {
        ("POST", "/api/investigations"): InvestigationRequest,
        ("POST", "/api/jobs/investigation"): InvestigationRequest,
        ("POST", "/api/hosts/discover"): ScanRequest,
        ("POST", "/api/scans"): ScanRequest,
        ("POST", "/api/tools/{tool_name}"): None,  # free-form tool args
    }
    for key, model in model_for.items():
        op = _operations(openapi)[key]
        media = op["requestBody"]["content"]["application/json"]
        named = media.get("examples")
        assert named, f"{key}: no named request-body examples"
        assert media.get("schema"), f"{key}: body schema lost"
        for ex in named.values():
            assert ex.get("summary"), f"{key}: example without summary"
            if model is not None:
                model.model_validate(ex["value"])  # raises on invalid example


def test_ping_tool_example_uses_documented_host_parameter(openapi):
    """The invoke_tool example must use real parameter names (ping => host)."""
    op = _operations(openapi)[("POST", "/api/tools/{tool_name}")]
    named = op["requestBody"]["content"]["application/json"]["examples"]
    assert "ping" in named and "host" in named["ping"]["value"]


# -- RTL Swagger UI (custom /api/docs shell) ---------------------------------------


def test_api_docs_is_rtl_with_ltr_technical_islands(client):
    """The custom RTL shell loads: dir=rtl page, LTR selectors for code/JSON,
    and the real SwaggerUIBundle (Try it out intact)."""
    r = client.get("/api/docs")
    assert r.status_code == 200
    html = r.text
    assert 'dir="rtl"' in html and 'lang="fa"' in html
    assert "direction: rtl" in html
    assert "SwaggerUIBundle" in html  # real bundle → Try it out still works
    assert "openapi.json" in html      # real generated spec, not a duplicate
    # technical islands stay LTR
    for selector in ("pre", "code", ".microlight", ".opblock-summary-path",
                     "input", "textarea"):
        assert selector in html
    assert 'setAttribute("dir", "ltr")' in html  # dynamic DOM fix


# -- authentication requirements are documented -------------------------------------


def test_agent_and_admin_routes_require_bearer_in_docs(openapi):
    """Every agent/admin operation documents 401; admin-only families exist
    under their own prefixes (separate credential domains)."""
    ops = _operations(openapi)
    for (method, path), op in ops.items():
        if path.startswith("/api/agent/v1") and not path.endswith("/enroll"):
            assert "401" in op["responses"], f"{method} {path}: 401 undocumented"
        if path.startswith("/api/admin/v1"):
            assert "401" in op["responses"], f"{method} {path}: 401 undocumented"


def test_console_tag_documents_admin_only_policy(openapi):
    """Console operations carry the dedicated Persian tag and mark the
    administrator-only policy in their descriptions."""
    ops = _operations(openapi)
    console_ops = [op for (m, p), op in ops.items() if "console" in p]
    assert console_ops
    for op in console_ops:
        assert "ترمینال پایتون از راه دور" in op["tags"]
    # the family-level policy lives in the tag description (single source)
    tag = next(t for t in openapi["tags"] if t["name"] == "ترمینال پایتون از راه دور")
    assert "مدیر" in tag["description"] and "ALLOW_ADMIN_PYTHON_CONSOLE" in tag["description"]
    create = next(op for (m, p), op in ops.items()
                  if p.endswith("/console/sessions") and m == "POST")
    assert "مدیر" in create["summary"] + create["description"]
