"""
ML-based APK analyzer module.
Placed in `src/` and loads model files from the project root.
"""

from __future__ import annotations

import os
import re
import zipfile
import joblib


# Resolve model paths relative to project root
ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
MODEL_PATH = os.path.join(ROOT, "apk_malware_model.pkl")
SCALER_PATH = os.path.join(ROOT, "apk_scaler.pkl")


# Load pre-trained ML model and scaler
try:
    ML_MODEL = joblib.load(MODEL_PATH)
    ML_SCALER = joblib.load(SCALER_PATH)
    ML_AVAILABLE = True
except Exception:
    ML_MODEL = None
    ML_SCALER = None
    ML_AVAILABLE = False


def _extract_printable_strings(blob):
    matches = re.findall(rb"[ -~]{4,}", blob)
    return {match.decode("utf-8", errors="ignore") for match in matches}


def _extract_ml_features(file_path):
    SUSPICIOUS_PERMISSIONS = {
        "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS", "android.permission.WRITE_SMS",
        "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
        "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
        "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.REQUEST_INSTALL_PACKAGES",
    }

    with zipfile.ZipFile(file_path, "r") as zip_ref:
        names = zip_ref.namelist()

        has_manifest = 0
        manifest_bytes = b""
        for name in names:
            if name.endswith("AndroidManifest.xml"):
                manifest_bytes = zip_ref.read(name)
                has_manifest = 1
                break

        has_signature = 1 if any(n.upper().startswith("META-INF/") for n in names) else 0
        dex_count = sum(1 for n in names if n.endswith(".dex"))
        native_lib_count = sum(1 for n in names if n.endswith(".so"))
        asset_count = sum(1 for n in names if n.startswith("assets/"))

        manifest_strings = _extract_printable_strings(manifest_bytes) if manifest_bytes else set()
        permissions = {v for v in manifest_strings if v.startswith("android.permission.")}
        suspicious_permissions = sum(1 for p in permissions if p in SUSPICIOUS_PERMISSIONS)

        file_count = len(names)
        name_blob = " ".join(n.lower() for n in names)
        obfuscation_hints = [
            "payload", "shell", "dropper", "inject", "stub", "loader",
            "exploit", "trojan", "malware", "obfus", "packer"
        ]
        has_obfuscation = 1 if any(hint in name_blob for hint in obfuscation_hints) else 0

        avg_complexity = min(1.0, dex_count * 0.2 + (native_lib_count * 0.1))

    return [
        has_manifest, has_signature, dex_count, native_lib_count,
        asset_count, suspicious_permissions, file_count,
        has_obfuscation, avg_complexity
    ]


def analyze_apk_with_ml(file_path: str) -> dict:
    try:
        if not os.path.isfile(file_path):
            return {
                "verdict": "dangerous",
                "label": "Dangerous",
                "malware_probability": 0.0,
                "summary": "The selected file does not exist.",
                "reasons": ["The selected file does not exist."],
                "ml_prediction": False,
                "model_used": "File Not Found",
            }

        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                _ = zf.namelist()
        except zipfile.BadZipFile:
            return {
                "verdict": "dangerous",
                "label": "Dangerous",
                "malware_probability": 1.0,
                "summary": "The file is not a valid APK archive.",
                "reasons": ["The file is not a valid APK archive."],
                "ml_prediction": False,
                "model_used": "Invalid APK",
            }

        features = _extract_ml_features(file_path)

        if ML_AVAILABLE and ML_MODEL is not None:
            features_scaled = ML_SCALER.transform([features])
            malware_prob = ML_MODEL.predict_proba(features_scaled)[0][1]

            if malware_prob >= 0.75:
                verdict = "dangerous"
                label = "Dangerous / malware suspected"
            elif malware_prob >= 0.5:
                verdict = "suspicious"
                label = "Potentially dangerous"
            else:
                verdict = "safe"
                label = "Safe to use"

            malware_probability = float(malware_prob)
            model_used = f"Random Forest ML Model ({os.path.basename(MODEL_PATH)})"
            ml_prediction = True
        else:
            # simple heuristic fallback
            risk_score = -1.6
            if not features[0]:
                risk_score += 2.0
            if not features[1]:
                risk_score += 1.1
            if features[2] > 1:
                risk_score += min(1.0, (features[2] - 1) * 0.25)
            if features[3]:
                risk_score += min(1.0, features[3] * 0.2)
            if features[5] > 0:
                risk_score += features[5] * 0.5

            import math
            malware_probability = 1.0 / (1.0 + math.exp(-risk_score)) if -60 < risk_score < 60 else (1.0 if risk_score >= 60 else 0.0)

            if malware_probability >= 0.75:
                verdict = "dangerous"
                label = "Dangerous / malware suspected"
            elif malware_probability >= 0.5:
                verdict = "suspicious"
                label = "Potentially dangerous"
            else:
                verdict = "safe"
                label = "Safe to use"

            model_used = "Heuristic Fallback (ML model not available)"
            ml_prediction = False

        reasons = []
        if not features[0]:
            reasons.append("AndroidManifest.xml was not found in the APK.")
        if not features[1]:
            reasons.append("No META-INF signature files were found.")
        if features[5] > 0:
            if features[5] == 1:
                reasons.append("1 suspicious permission detected")
            else:
                reasons.append(f"{int(features[5])} suspicious permissions detected")
        if features[2] > 1:
            reasons.append(f"Multiple DEX files detected ({int(features[2])}).")
        if features[3] > 0:
            reasons.append(f"Native libraries found ({int(features[3])}).")
        if features[7]:
            reasons.append("Suspicious naming patterns and obfuscation hints detected.")
        if not reasons:
            reasons.append("ML model prediction: benign APK with low risk indicators.")

        summary = f"{label} (malware probability: {malware_probability * 100:.1f}%). Analyzed by: {model_used}"

        return {
            "verdict": verdict,
            "label": label,
            "malware_probability": malware_probability,
            "summary": summary,
            "reasons": reasons,
            "file_size_kb": os.path.getsize(file_path) / 1024,
            "file_name": os.path.basename(file_path),
            "ml_prediction": ml_prediction,
            "model_used": model_used,
        }

    except Exception as exc:
        return {
            "verdict": "dangerous",
            "label": "Dangerous",
            "malware_probability": 1.0,
            "summary": f"Analysis error: {str(exc)}",
            "reasons": [str(exc)],
            "file_name": os.path.basename(file_path),
            "ml_prediction": False,
            "model_used": "Error",
        }


def format_report(report: dict) -> str:
    lines = [
        f"File: {report.get('file_name', 'Unknown')}",
        f"Verdict: {report['label']}",
        f"Malware Probability: {report['malware_probability'] * 100:.1f}%",
        f"APK Size: {report.get('file_size_kb', 0.0):.2f} KB",
        f"Analysis Method: {report.get('model_used', 'Unknown')}",
        "",
        report["summary"],
        "",
        "Reasons:",
    ]
    lines.extend(f"- {reason}" for reason in report.get("reasons", []))
    return "\n".join(lines)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python analyzer.py <path-to-apk>")
    else:
        print(format_report(analyze_apk_with_ml(sys.argv[1])))
