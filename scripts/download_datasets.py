"""
Helper script to download APKs listed in a URL file into `data/raw/`.

Usage:
  - Fill `data/download_list.txt` with one URL per line.
  - Run: `python scripts/download_datasets.py`

Note: this script uses standard-library `urllib` so no extra deps are required.
You may need to obtain APKs from sources that require API keys (AndroZoo) —
this script does not automate those protected downloads.
"""

import os
import urllib.request
from urllib.parse import urlsplit


DEST_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "raw")
URL_LIST = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "download_list.txt")


def ensure_dest():
    os.makedirs(DEST_DIR, exist_ok=True)


def download_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
        filename = os.path.basename(parsed.path) or "downloaded.apk"
        dest_path = os.path.join(DEST_DIR, filename)
        print(f"Downloading {url} -> {dest_path}")
        urllib.request.urlretrieve(url, dest_path)
        return dest_path
    except Exception as e:
        print(f"Failed to download {url}: {e}")
        return ""


def main():
    ensure_dest()
    if not os.path.exists(URL_LIST):
        print(f"No URL list found at {URL_LIST}. Create it with one APK URL per line.")
        return

    with open(URL_LIST, "r", encoding="utf-8") as fh:
        urls = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

    for url in urls:
        download_url(url)


if __name__ == "__main__":
    main()
