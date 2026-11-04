
from redirect_analyzer import analyze_redirects

test_cases = [
    {
        "name": "Normal HTTPS website",
        "url": "https://httpbin.org/get"
    },
    {
        "name": "Two redirects",
        "url": "https://httpbin.org/redirect/2"
    },
    {
        "name": "Absolute redirects",
        "url": "https://httpbin.org/absolute-redirect/2"
    },
    {
        "name": "Localhost rejection",
        "url": "http://localhost:5173"
    },
    {
        "name": "Private IP rejection",
        "url": "http://127.0.0.1"
    },
    {
        "name": "Invalid scheme",
        "url": "ftp://example.com"
    }
]

for test in test_cases:

    print("\n" + "=" * 65)
    print("TEST:", test["name"])
    print("URL:", test["url"])

    try:
        result = analyze_redirects(test["url"])

        print("Redirect count:", result["redirect_count"])
        print("Final URL:", result["final_url"])
        print("Loop detected:", result["loop_detected"])
        print("HTTPS downgrade:", result["https_downgrade"])
        print("External redirects:", result["external_redirects"])
        print("Error:", result["error"])
        print("Stop reason:", result["stop_reason"])

    except Exception as exc:
        print("Unexpected error:", type(exc).__name__, str(exc))
