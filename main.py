from analyzer.checks import check_security_headers


def main():
    findings = check_security_headers("https://example.com")

    for f in findings:
        print(f.severity.value, "-", f.observation)


if __name__ == "__main__":
    main()
