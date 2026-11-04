
from url_analyzer import analyze_url
from rule_engine import check_idn_homograph, run_security_rules

test_urls = [
    "https://paypal.com",
    "https://раypal.com",
    "https://google.com",
    "https://gооgle.com",
    "https://xn--ypal-43d9g.com",
    "https://例え.テスト",
    "https://localhost:5173"
]

for url in test_urls:

    features = analyze_url(url)

    idn_analysis = features["idn_analysis"]
    idn_result = check_idn_homograph(features)

    print("\n" + "=" * 60)
    print("URL:", url)
    print("Hostname:", features["hostname"])
    print("IDN Analysis:", idn_analysis)
    print("IDN Rule:", idn_result)

    all_findings = run_security_rules(features)

    print("Integrated Findings:", all_findings)
