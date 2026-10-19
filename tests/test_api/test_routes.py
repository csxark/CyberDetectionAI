"""Tests for FastAPI endpoints."""
from __future__ import annotations

import io

from fastapi.testclient import TestClient

from api.app import create_app


def test_health_endpoint() -> None:
    client = TestClient(create_app())
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "config_sha256" in data
    assert "demo_mode" in data


def test_investigation_upload_and_artifacts_flow() -> None:
    client = TestClient(create_app())
    sample_log = (
        "Oct 18 10:14:01 host sshd: Failed password for invalid user admin from 198.51.100.22 port 44821\n"
        "Oct 18 10:14:05 host sshd: Failed password for invalid user admin from 198.51.100.22 port 44824\n"
        "Oct 18 10:14:10 host sshd: Failed password for invalid user admin from 198.51.100.22 port 44828\n"
        "Oct 18 10:14:15 host sshd: Failed password for invalid user admin from 198.51.100.22 port 44832\n"
    )

    # 1. Upload log file
    files = {"file": ("auth_attack.log", io.BytesIO(sample_log.encode()), "text/plain")}
    resp = client.post("/api/v1/investigations", files=files, data={"force_approval": "false"})
    assert resp.status_code == 200
    data = resp.json()

    inv_id = data["investigation_id"]
    assert data["findings_count"] >= 1
    assert "198.51.100.22" in data["unique_ips"]
    assert "response_report.md" in data["available_artifacts"]
    assert "findings.json" in data["available_artifacts"]

    # 2. Retrieve investigation by ID
    get_resp = client.get(f"/api/v1/investigations/{inv_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["investigation_id"] == inv_id

    # 3. Retrieve response_report.md artifact
    art_resp = client.get(f"/api/v1/investigations/{inv_id}/artifacts/response_report.md")
    assert art_resp.status_code == 200
    assert "SentinelAI Investigation Report" in art_resp.text
    assert inv_id in art_resp.text

    # 4. Path traversal attempt on artifacts is rejected
    traversal_resp = client.get(f"/api/v1/investigations/{inv_id}/artifacts/..%2F..%2Fetc%2Fpasswd")
    assert traversal_resp.status_code == 400
    assert traversal_resp.json()["detail"]["code"] == "POLICY_PARAM_TRAVERSAL"


def test_approval_workflow() -> None:
    client = TestClient(create_app())
    sample_log = (
        "Oct 18 10:14:01 host sshd: Failed password for invalid user admin from 203.0.113.5 port 44821\n"
        "Oct 18 10:14:05 host sshd: Failed password for invalid user admin from 203.0.113.5 port 44824\n"
        "Oct 18 10:14:10 host sshd: Failed password for invalid user admin from 203.0.113.5 port 44828\n"
    )
    files = {"file": ("brute.log", io.BytesIO(sample_log.encode()), "text/plain")}
    resp = client.post("/api/v1/investigations", files=files, data={"force_approval": "true"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["approval_required"] is True
    inv_id = data["investigation_id"]

    # Approve the action
    app_resp = client.post(
        f"/api/v1/investigations/{inv_id}/approval",
        json={"decision": "approved", "reason": "Operator verified brute force attack source", "operator": "secops_alice"},
    )
    assert app_resp.status_code == 200
    app_data = app_resp.json()
    assert app_data["status"] == "approved"
    # lab_block_ip is disabled by default in immutable config, so policy engine accurately enforces DENY
    assert app_data["policy_decision"] == "deny"


def test_kill_switch_engagement() -> None:
    client = TestClient(create_app())

    # Engage kill switch
    ks_resp = client.post("/api/v1/kill-switch", json={"active": True, "operator": "lead_secops"})
    assert ks_resp.status_code == 200
    assert ks_resp.json()["kill_switch_active"] is True

    # Attempt investigation while kill switch is engaged -> 503
    files = {"file": ("test.log", io.BytesIO(b"log data\n"), "text/plain")}
    blocked_resp = client.post("/api/v1/investigations", files=files)
    assert blocked_resp.status_code == 503

    # Disengage kill switch
    client.post("/api/v1/kill-switch", json={"active": False, "operator": "lead_secops"})
