# APK ML Analyzer - Dataset and Retraining Guide

## Project Structure

```
apk-risk-analyzer/
├── src/
│   ├── app.py              # ML GUI (main entry point)
│   ├── analyzer.py         # ML backend analyzer
│   ├── train.py            # Synthetic training script
│   └── __init__.py
├── scripts/
│   └── download_datasets.py # Download APK helper
├── dataset/
│   ├── prepare_features.py # Extract features from labeled APKs
│   └── validate_labels.py  # Validate labels.csv
├── retrain/
│   └── train_from_features.py # Retrain model on real data
├── data/
│   ├── labels.csv          # Labeling template
│   ├── download_list.txt   # URLs for downloading APKs
│   ├── raw/                # Raw downloaded APK files (created after download)
│   └── features.csv        # Feature extraction output (created after prepare_features.py)
├── apk_malware_model.pkl   # Pre-trained Random Forest model
├── apk_scaler.pkl          # Feature scaler
├── requirements.txt        # Python dependencies
├── README.md               # This file
└── .gitignore              # Ignore rules
```

## Running the ML GUI

From the project root:

```bash
cd src
python app.py
```

Or without `__pycache__`:

```bash
cd src
python -B app.py
```

## Full Dataset Preparation Workflow

### Step 1: Prepare APK Files

**Option A: Download from Public Sources**

1. Open `data/download_list.txt`
2. Uncomment example URLs or add your own APK URLs (one per line)
3. Run the downloader:

```bash
python scripts/download_datasets.py
```

Downloaded APKs will be saved to `data/raw/`

**Option B: Manually Add APKs**

Simply place your APK files in `data/raw/` folder.

### Step 2: Label Your APKs

Edit `data/labels.csv` and add one row per APK:

```csv
apk_path,label,source,sha256
data/raw/app1.apk,0,manual,
data/raw/malware1.apk,1,manual,
data/raw/app2.apk,0,viral_share,
```

Where:
- `apk_path`: relative or absolute path to APK
- `label`: 0 = benign/safe; 1 = malware/suspicious
- `source`: where the APK came from (manual, viral_share, androzoo, github, etc.)
- `sha256`: optional—can leave empty

### Step 3: Validate Labels

Check for missing files and label errors:

```bash
python dataset/validate_labels.py
```

### Step 4: Extract Features

Convert labeled APKs into feature vectors for training:

```bash
python dataset/prepare_features.py
```

Output: `data/features.csv` (one row per APK with 9 ML features)

### Step 5: Retrain the Model

Train a fresh Random Forest on your labeled data:

```bash
python retrain/train_from_features.py
```

This will:
- Load features from `data/features.csv`
- Train/test split (80/20)
- Train RandomForest (200 trees, max_depth=20)
- Print test accuracy and classification report
- Save `apk_malware_model.pkl` and `apk_scaler.pkl` to project root

The GUI will then use the retrained model.

## Public APK Sources

### Open-Source (Recommended for testing)

1. **GitHub Releases**
   - Many open-source Android apps publish releases on GitHub
   - Example: [Termux](https://github.com/termux/termux-app/releases)
   - Example: [AnkiDroid](https://github.com/ankidroid/Anki-Android/releases)
   - Example: [VLC](https://github.com/videolabs/vlc) (though main on F-Droid)

2. **F-Droid** (free and open-source)
   - https://f-droid.org/repo/
   - Direct download links: `https://f-droid.org/repo/{package_name}_{version}.apk`

### Requires API Keys (not auto-supported yet)

1. **AndroZoo** (requires registration)
   - Contact: https://androzoo.uni.lu/
   - Largest APK dataset; requires academic/research credentials

2. **VirusTotal** (requires API key)
   - Not an APK source but useful for threat intel integration (future enhancement)

3. **APKPure/APKMirror** (has rate limits)
   - Mostly require manual download or have dynamic URLs

## Next Steps

1. Add APKs to `data/raw/` (manually or via downloader)
2. Create labels in `data/labels.csv`
3. Run the pipeline:
   ```bash
   python dataset/validate_labels.py
   python dataset/prepare_features.py
   python retrain/train_from_features.py
   ```
4. Test the GUI with your retrained model:
   ```bash
   cd src
   python app.py
   ```

## Troubleshooting

**"labels.csv not found"** → Create `data/labels.csv` with headers and at least one row

**"Missing APK file"** → Check that paths in labels.csv are correct (relative to project root)

**"Failed to extract features"** → The APK file might be corrupted; validate with `validate_labels.py`

**Empty features.csv** → No valid labeled APKs were found; check labels.csv and APK file validity

**Model doesn't improve** → You need more diverse labeled data (currently: 1000 synthetic samples); add 100+ real benign and malware APKs

## Disclaimer

This project is for educational and research purposes. Always ensure you have permission to download and analyze APKs. Do not distribute malware or pirated apps.
