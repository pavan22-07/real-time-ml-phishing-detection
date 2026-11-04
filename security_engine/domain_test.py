import tldextract

test_domains = [
    "www.google.com",
    "login.paypal.com",
    "example.co.uk",
    "shop.example.co.uk",
    "paypal.com.evil-site.com"
]

for domain in test_domains:

    result = tldextract.extract(domain)

    print("\nDomain:", domain)
    print("Subdomain:", result.subdomain)
    print("Registered domain:", result.domain)
    print("Public suffix:", result.suffix)