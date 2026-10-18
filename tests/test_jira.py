"""Cliente de Jira (RF-4.8): creación de incidencias con auth básica y descripción ADF."""
import base64
import json

import httpx
import pytest

from appsec_ai.service import jira

SITE = "https://acme.atlassian.net"


def jira_mock(captured):
    def handler(request):
        auth = request.headers.get("authorization", "")
        captured["auth"] = auth
        if request.url.path.startswith("/rest/api/3/project/"):
            key = request.url.path.rsplit("/", 1)[-1]
            return httpx.Response(200 if key == "SEC" else 404, json={})
        if request.url.path == "/rest/api/3/issue" and request.method == "POST":
            captured["issue"] = json.loads(request.content)
            return httpx.Response(201, json={"key": "SEC-42"})
        return httpx.Response(404)
    return httpx.MockTransport(handler)


def test_client_creates_issue_with_basic_auth_and_adf():
    captured = {}
    client = jira.Jira(SITE, "me@acme.com", "tok", transport=jira_mock(captured))
    adf = jira.finding_adf({"severity": "high", "title": "SQLi", "file": "app.py", "line": 7, "rule_id": "r1",
                            "message": "injection", "triage": {"fix": "use params"}}, "acme/shop", "es")
    issue = client.create_issue("SEC", "x", adf, ["appsec-ai", "high"])
    assert issue == {"key": "SEC-42", "url": f"{SITE}/browse/SEC-42"}
    assert base64.b64decode(captured["auth"].split()[1]).decode() == "me@acme.com:tok"
    fields = captured["issue"]["fields"]
    assert fields["project"]["key"] == "SEC" and fields["description"]["type"] == "doc"
    assert "appsec-ai" in fields["labels"]


def test_client_check_and_errors():
    captured = {}
    client = jira.Jira(SITE, "me@acme.com", "tok", transport=jira_mock(captured))
    assert client.check("SEC") is True and client.check("NOPE") is False
    boom = jira.Jira(SITE, "m", "t", transport=httpx.MockTransport(lambda r: httpx.Response(401, text="no")))
    with pytest.raises(jira.JiraError):
        boom.create_issue("SEC", "x", {"type": "doc", "version": 1, "content": []}, [])
