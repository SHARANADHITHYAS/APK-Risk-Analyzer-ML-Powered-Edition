"""
Train model from `data/features.csv` and save model/scaler to project root.

Usage:
  python retrain/train_from_features.py
"""

import os
import csv
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score


ROOT = os.path.dirname(os.path.dirname(__file__))
FEATURES_CSV = os.path.join(ROOT, 'data', 'features.csv')


def load_features(path):
    X = []
    y = []
    with open(path, newline='', encoding='utf-8') as fh:
        reader = csv.DictReader(fh)
        for r in reader:
            y.append(int(r['label']))
            X.append([
                float(r['has_manifest']), float(r['has_signature']), float(r['dex_count']), float(r['native_lib_count']),
                float(r['asset_count']), float(r['suspicious_permissions']), float(r['file_count']), float(r['has_obfuscation']), float(r['avg_complexity'])
            ])
    return np.array(X), np.array(y)


def main():
    if not os.path.exists(FEATURES_CSV):
        print('features.csv not found. Run dataset/prepare_features.py first')
        return

    X, y = load_features(FEATURES_CSV)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    model = RandomForestClassifier(n_estimators=200, max_depth=20, random_state=42, n_jobs=-1)
    model.fit(X_train_s, y_train)

    preds = model.predict(X_test_s)
    acc = accuracy_score(y_test, preds)
    print('Test Accuracy:', acc)
    print(classification_report(y_test, preds))

    joblib.dump(model, os.path.join(ROOT, 'apk_malware_model.pkl'))
    joblib.dump(scaler, os.path.join(ROOT, 'apk_scaler.pkl'))
    print('Saved model and scaler to project root')


if __name__ == '__main__':
    main()
