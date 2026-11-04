from url_analyzer import analyze_url
from rule_engine import check_brand_impersonation

test_urls = [
    "https://paypal.com",
    "https://paypal.com.evil-site.com",
    "https://paypa1.com",
    "https://paypal-login.com",
    "https://google.com",
    "https://g00gle.com"
]

for url in test_urls:

    features = analyze_url(url)

    result = check_brand_impersonation(features)

    print("\nURL:", url)
    print("Result:", result)