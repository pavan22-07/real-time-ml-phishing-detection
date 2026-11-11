if __package__:
    from .security_validation_test import scan_static_url
else:
    from security_validation_test import scan_static_url

test_urls = [
    "https://secure-login-account.example.com/verify",
    "https://example.com/%256c%256f%2567%2569%256e",
    "https://example.com/%ZZ"
]

for url in test_urls:
    result = scan_static_url(url)

    print("\n" + "=" * 80)
    print("URL:", url)
    print("ENCODING:", result["features"].get("encoding_analysis"))
    print("KEYWORDS:", result["features"].get("suspicious_keywords"))
    print("FINDINGS:")

    for finding in result["findings"]:
        print(finding)

    print("RISK ASSESSMENT:", result["assessment"])
    print("FINAL DECISION:", result["decision"])