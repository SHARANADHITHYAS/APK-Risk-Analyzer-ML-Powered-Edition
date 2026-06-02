"""
Prepare features CSV from labeled APKs listed in data/labels.csv.

Output: data/features.csv

Usage:
  python dataset/prepare_features.py
"""

import csv
import os
import sys
import hashlib

# allow importing src package
ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, ROOT)

from src import analyzer


LABELS_CSV = os.path.join(ROOT, "data", "labels.csv")
OUT_CSV = os.path.join(ROOT, "data", "features.csv")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    if not os.path.exists(LABELS_CSV):
        print("labels.csv not found. Create data/labels.csv with headers: apk_path,label,source,sha256")
        return

    rows = []
    with open(LABELS_CSV, newline='', encoding='utf-8') as fh:
        reader = csv.DictReader(fh)
        for r in reader:
            apk_path = r.get('apk_path') or r.get('apk') or r.get('path')
            label = r.get('label')
            if not apk_path or not label:
                print('Skipping malformed row:', r)
                continue
            apk_path = os.path.abspath(apk_path)
            if not os.path.exists(apk_path):
                print('Missing APK file:', apk_path)
                continue

            # extract features
            try:
                features = analyzer._extract_ml_features(apk_path)
            except Exception as e:
                print('Failed to extract features for', apk_path, e)
                continue

            rows.append((apk_path, int(label)) + tuple(features))

    # write header
    headers = [
        'apk_path', 'label',
        'has_manifest','has_signature','dex_count','native_lib_count',
        'asset_count','suspicious_permissions','file_count','has_obfuscation','avg_complexity'
    ]

    with open(OUT_CSV, 'w', newline='', encoding='utf-8') as fh:
        writer = csv.writer(fh)
        writer.writerow(headers)
        for row in rows:
            writer.writerow(row)

    print(f'Wrote features to {OUT_CSV} ({len(rows)} rows)')


if __name__ == '__main__':
    main()
