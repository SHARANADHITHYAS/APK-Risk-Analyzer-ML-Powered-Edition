"""
Validate `data/labels.csv` entries: existence of APKs and label sanity.

Usage:
  python dataset/validate_labels.py
"""

import csv
import os
import sys

ROOT = os.path.dirname(os.path.dirname(__file__))
LABELS = os.path.join(ROOT, 'data', 'labels.csv')


def main():
    if not os.path.exists(LABELS):
        print('labels.csv not found at', LABELS)
        return

    bad = 0
    total = 0
    with open(LABELS, newline='', encoding='utf-8') as fh:
        reader = csv.DictReader(fh)
        for r in reader:
            total += 1
            apk = r.get('apk_path') or r.get('apk') or r.get('path')
            label = r.get('label')
            if not apk or not label:
                print('Malformed row:', r)
                bad += 1
                continue
            if not os.path.exists(apk):
                print('Missing file:', apk)
                bad += 1
                continue
            if label.strip() not in ('0', '1'):
                print('Invalid label (must be 0 or 1):', label, 'for', apk)
                bad += 1

    print(f'Checked {total} rows: {bad} problems')
    if bad == 0:
        print('labels.csv looks OK')


if __name__ == '__main__':
    main()
