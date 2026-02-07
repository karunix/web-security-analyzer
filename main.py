import sys
import json

from analyzer.checks import check_security_headers
from analyzer.utils import exit_code_from_findings


def main():
    findings = check_security_headers("https://example.com")

    for f in findings:
        print(f.severity.value, "-", f.observation)

    sys.exit(exit_code_from_findings(findings))



if __name__ == "__main__":
    main()
