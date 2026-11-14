import unittest
from pathlib import Path
import tldextract

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TLD_CACHE_DIR = PROJECT_ROOT / "data" / ".tld_cache"
TLD_CACHE_DIR.mkdir(parents=True, exist_ok=True)

_extractor = tldextract.TLDExtract(
    cache_dir=str(TLD_CACHE_DIR),
    fallback_to_snapshot=True,
    suffix_list_urls=None
)


class DomainExtractionTests(unittest.TestCase):
    def test_domain_extraction(self):
        cases = {
            "www.google.com": ("www", "google", "com"),
            "login.paypal.com": ("login", "paypal", "com"),
            "example.co.uk": ("", "example", "co.uk"),
            "shop.example.co.uk": ("shop", "example", "co.uk"),
            "paypal.com.evil-site.com": ("paypal.com", "evil-site", "com"),
        }
        for domain, (subdomain, reg_dom, suffix) in cases.items():
            with self.subTest(domain=domain):
                res = _extractor(domain)
                self.assertEqual(res.subdomain, subdomain)
                self.assertEqual(res.domain, reg_dom)
                self.assertEqual(res.suffix, suffix)


if __name__ == "__main__":
    unittest.main(verbosity=2)
