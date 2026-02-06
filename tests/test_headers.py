import requests
from analyzer.checks import check_security_headers
from analyzer.models import Severity


class MockResponse:
    def __init__(self, headers):
        self.headers = headers


def test_connection_failure(monkeypatch):
    def mock_head(*args, **kwargs):
        raise requests.RequestException("Connection failed")

    monkeypatch.setattr("requests.head", mock_head)

    findings = check_security_headers("https://example.com")

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "Failed to fetch" in findings[0].explanation
