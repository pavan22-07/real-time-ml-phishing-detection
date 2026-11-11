
import csv
from pathlib import Path

if __package__:
    from .security_validation_test import scan_static_url
else:
    from security_validation_test import scan_static_url

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET_PATH = PROJECT_ROOT / "data" / "cybersecurity_test_urls.csv"



def evaluate():

    # Read the complete CSV into memory
    csv_content = DATASET_PATH.read_text(
        encoding="utf-8-sig"
    )

    # Parse directly from in-memory lines
    cases = list(
        csv.DictReader(csv_content.splitlines())
    )

    if not cases:
        raise ValueError("CSV contains no data rows")

    # Normalize CSV column names
    cases = [
        {
            key.strip().lower(): value.strip()
            for key, value in case.items()
            if key is not None
        }
        for case in cases
    ]

    print("CSV columns:", list(cases[0].keys()))
    print("Total URLs:", len(cases))

    # Continue with your existing evaluation logic

    tp = fp = tn = fn = 0

    # Keep the rest of your existing evaluation code here.


    # Normalize column names
    

    print("Total URLs:", len(cases))

    tp = fp = tn = fn = 0

    print("\nCYBERSECURITY DATASET EVALUATION")
    print("-" * 75)

    for case in cases:

        actual = case["label"] == "phishing"

        result = scan_static_url(case["url"])

        # WARN and BLOCK count as suspicious detections.
        predicted = (
            result["decision"]["decision"] in {"WARN", "BLOCK"}
        )

        if actual and predicted:
            tp += 1
            outcome = "TRUE POSITIVE"

        elif not actual and predicted:
            fp += 1
            outcome = "FALSE POSITIVE"

        elif not actual and not predicted:
            tn += 1
            outcome = "TRUE NEGATIVE"

        else:
            fn += 1
            outcome = "FALSE NEGATIVE"

        print(
            f"{outcome:16} | "
            f"{result['decision']['decision']:5} | "
            f"{case['url']}"
        )

    total = tp + fp + tn + fn

    accuracy = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0

    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0
    )

    print("\nCONFUSION MATRIX")
    print("-" * 35)
    print(f"True Positives  : {tp}")
    print(f"False Positives : {fp}")
    print(f"True Negatives  : {tn}")
    print(f"False Negatives : {fn}")

    print("\nPERFORMANCE METRICS")
    print("-" * 35)
    print(f"Accuracy  : {accuracy:.2%}")
    print(f"Precision : {precision:.2%}")
    print(f"Recall    : {recall:.2%}")
    print(f"F1 Score  : {f1:.2%}")


if __name__ == "__main__":
    evaluate()
