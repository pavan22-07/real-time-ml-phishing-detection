"""
Dataset Loader for Phishing URL Detection.
Handles automatic discovery, download, integrity verification, and loading of the dataset.
"""

import os
import sys
import json
import hashlib
from datetime import datetime
from pathlib import Path
import urllib.request
import pandas as pd

from ml_engine.config import (
    RAW_DATA_DIR,
    RAW_DATASET_PATH,
    DATASET_METADATA_PATH,
    DATASET_INFO,
    PROJECT_ROOT
)


def compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(65536), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def download_dataset(force: bool = False) -> Path:
    """
    Download the official dataset automatically if not present or corrupted.
    """
    RAW_DATA_DIR.mkdir(parents=True, exist_ok=True)

    if RAW_DATASET_PATH.exists() and not force:
        file_size = RAW_DATASET_PATH.stat().st_size
        if file_size > 1000:
            print(f"[+] Dataset already exists at: {RAW_DATASET_PATH} ({file_size:,} bytes)")
            return RAW_DATASET_PATH

    download_url = DATASET_INFO["download_url"]
    print(f"[+] Downloading official dataset from: {download_url}")
    print(f"    Target path: {RAW_DATASET_PATH}")

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    req = urllib.request.Request(download_url, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=60) as response, open(RAW_DATASET_PATH, "wb") as out_file:
            total_size = response.length
            downloaded = 0
            block_size = 1024 * 64

            while True:
                buffer = response.read(block_size)
                if not buffer:
                    break
                downloaded += len(buffer)
                out_file.write(buffer)
                if total_size:
                    percent = downloaded * 100 / total_size
                    print(f"\r    Progress: {downloaded:,} / {total_size:,} bytes ({percent:.1f}%)", end="")
            print()

        print(f"[+] Download complete: {RAW_DATASET_PATH}")
    except Exception as exc:
        print(f"[-] Download from primary source failed: {exc}")
        if RAW_DATASET_PATH.exists():
            RAW_DATASET_PATH.unlink()
        raise RuntimeError(
            f"Failed to download official dataset from {download_url}. Error: {exc}\n"
            f"Please ensure network access is enabled, or manually place the CSV at {RAW_DATASET_PATH}."
        ) from exc

    # Compute hash and write metadata
    sha256 = compute_sha256(RAW_DATASET_PATH)
    file_size = RAW_DATASET_PATH.stat().st_size

    # Verify CSV readability
    df_head = pd.read_csv(RAW_DATASET_PATH, nrows=5)
    columns = list(df_head.columns)

    metadata = {
        "dataset_name": DATASET_INFO["name"],
        "dataset_version": DATASET_INFO["version"],
        "doi": DATASET_INFO["doi"],
        "licence": DATASET_INFO["licence"],
        "authors": DATASET_INFO["authors"],
        "institution": DATASET_INFO["institution"],
        "source_url": DATASET_INFO["download_url"],
        "local_file": str(RAW_DATASET_PATH.relative_to(PROJECT_ROOT)),
        "download_timestamp": datetime.utcnow().isoformat() + "Z",
        "file_size_bytes": file_size,
        "sha256": sha256,
        "columns": columns,
        "integrity_verified": True
    }

    with open(DATASET_METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4)

    print(f"[+] Metadata written to: {DATASET_METADATA_PATH}")
    print(f"    SHA-256: {sha256}")
    print(f"    Columns detected: {len(columns)} columns")
    return RAW_DATASET_PATH


def load_raw_dataset(nrows: int = None) -> pd.DataFrame:
    """
    Load the raw dataset from data/raw/.
    Automatically downloads if not present.
    """
    if not RAW_DATASET_PATH.exists():
        download_dataset()

    df = pd.read_csv(RAW_DATASET_PATH, nrows=nrows, low_memory=False)
    return df


if __name__ == "__main__":
    download_dataset()
    df = load_raw_dataset(nrows=10)
    print("\nDataset sample preview:")
    print(df.head())
    print("\nColumns:", list(df.columns))
