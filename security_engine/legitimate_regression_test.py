
import csv
import unittest
from pathlib import Path

if __package__:
    from .security_validation_test import scan_static_url
else:
    from security_validation_test import scan_static_url


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATASET_PATH = (
    PROJECT_ROOT
    / "data"
    / "legitimate_regression_urls.csv"
)


class LegitimateURLRegressionTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):

        if not DATASET_PATH.exists():
            raise FileNotFoundError(
                f"Regression dataset not found: {DATASET_PATH}"
            )

        with DATASET_PATH.open(
            "r",
            encoding="utf-8-sig",
            newline=""
        ) as file:

            reader = csv.DictReader(file)
            reader.fieldnames = [
                name.strip().lower()
                for name in reader.fieldnames
            ]

            cls.cases = list(reader)

        if not cls.cases:
            raise ValueError("Regression dataset contains no URLs")

        required_columns = {"url", "label", "test_category"}

        if not required_columns.issubset(cls.cases[0]):
            raise ValueError(
                f"Dataset must contain columns: {required_columns}"
            )

    def test_all_legitimate_urls_are_allowed(self):

        for case in self.cases:

            with self.subTest(
                category=case["test_category"],
                url=case["url"]
            ):

                self.assertEqual(case["label"], "legitimate")

                result = scan_static_url(case["url"])

                self.assertEqual(
                    result["decision"]["decision"],
                    "ALLOW",
                    msg=(
                        f"Legitimate URL received "
                        f"{result['decision']['decision']}: "
                        f"{case['url']}. "
                        f"Risk score: "
                        f"{result['assessment']['risk_score']}. "
                        f"Findings: {result['findings']}"
                    )
                )

    def test_dataset_contains_expected_number_of_cases(self):
        self.assertEqual(len(self.cases), 15)


if __name__ == "__main__":
    unittest.main(verbosity=2)
