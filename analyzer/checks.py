import requests
from analyzer.models import Finding, Severity


SECURITY_HEADERS = {
    "Content-Security-Policy": Severity.HIGH,
    "Strict-Transport-Security": Severity.HIGH,
    "X-Frame-Options": Severity.MEDIUM,
    "X-Content-Type-Options": Severity.MEDIUM,
}


def check_security_headers(url: str):
    findings = []

    try:
        response = requests.head(url, timeout=5, allow_redirects=True)

        # Fallback to GET if HEAD returns no headers
        if not response.headers:
            response = requests.get(url, timeout=5)

    except requests.RequestException as exc:
        return [
            Finding(
                scope="Web connectivity",
                observation=str(exc),
                severity=Severity.HIGH,
                explanation="Failed to fetch the target URL.",
                recommendation="Ensure the target is reachable over HTTP/HTTPS.",
            )
        ]

    headers_present = {h.lower() for h in response.headers}

    for header, severity in SECURITY_HEADERS.items():
        if header.lower() not in headers_present:
            findings.append(
                Finding(
                    scope="HTTP headers",
                    observation=f"{header} header is missing",
                    severity=severity,
                    explanation=f"The {header} security header is not present.",
                    recommendation=f"Configure the web server to include {header}.",
                )
            )

    return findings
