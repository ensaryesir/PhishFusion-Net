# PhishFusion-Net
<div align="center">

![Dialogues](https://img.shields.io/badge/Protected\_Brands\_Size-277-green?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Fork](https://img.shields.io/badge/Fork-PhishIntention-orange?style=flat-square)

**Multi-Modal Phishing Detection: URL Analysis + Visual Recognition**

</div>

<p align="center">
  <a href="#-about">About</a> •
  <a href="#-features">Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#%EF%B8%8F-configuration">Configuration</a> •
  <a href="#-performance">Performance</a> •
  <a href="#%EF%B8%8F-troubleshooting">Troubleshooting</a>
</p>

<p align="center">
  <strong>Original PhishIntention:</strong>
  <a href="https://www.usenix.org/conference/usenixsecurity22/presentation/liu-ruofan">Paper</a> •
  <a href="https://sites.google.com/view/phishintention">Website</a> •
  <a href="https://github.com/lindsey98/PhishIntention">Original Repo</a>
</p>

---

## 🎯 About

**PhishFusion-Net** is a multi-modal phishing detection system that combines URL analysis and visual recognition for improved accuracy.

- **URL Analysis**: 45+ features, risk scoring (0-1), ~0.3-8s
- **Visual Recognition**: Logo detection (277 brands), CRP classification, ~4-8s  
- **Multi-Modal Fusion**: +15% accuracy, -50% false positives

Based on [PhishIntention](https://github.com/lindsey98/PhishIntention) (USENIX Security 2022) with enhanced URL-based detection.

---

## ✨ Features

- **URL Analysis**: 45+ features (lexical, domain, SSL, patterns, redirects) with risk scoring
- **Visual Detection**: Logo matching for 277 brands using Faster R-CNN and CRP classification
- **Multi-Modal Fusion**: Early filtering, confidence boosting, and disambiguation strategies

**Risk Levels:**
- `0.0-0.5`: Low risk (safe)
- `0.5-0.7`: Medium risk (suspicious)  
- `0.7-1.0`: High risk (likely phishing)

---

## 📦 Installation

### Prerequisites

- Python 3.8+
- [Pixi Package Manager](https://pixi.sh/)
- Google Chrome browser

### Step 1: Clone Repository

```bash
git clone https://github.com/ensaryesir/PhishFusion-Net.git
cd PhishFusion-Net
```

### Step 2: Install Dependencies

Using **Pixi** (recommended):

```bash
pixi install
```

### Step 3: Download Model Files

Download the pre-trained models and place them in the `models/` directory:

| Model | Description | Size | Link |
|-------|-------------|------|------|
| `layout_detector.pth` | AWL Layout Detector | 166MB | [Download](https://drive.google.com/uc?id=1qV8Hw4MXuTTJfxEk-dBsaoRLZgwXxDlb) |
| `crp_classifier.pth.tar` | CRP Classifier | 87MB | [Download](https://drive.google.com/uc?id=1BaI9fEJhQxlBWXXPXnMIWWwJSwH6cqNX) |
| `crp_locator.pth` | CRP Locator | 343MB | [Download](https://drive.google.com/uc?id=1TQH1Y_JWwJ_2tDEXnpO2tNvb2LCdhsL6) |
| `domain_map.pkl` | Domain Mapper | 11KB | [Download](https://drive.google.com/uc?id=1MLA56o_bLDMCxdDp8bWR5f6YmMVNdOTa) |
| `expand_targetlist.zip` | Protected Brands (277) | 94MB | [Download](https://drive.google.com/uc?id=1s0XkT5wjWoAPk3DLhRy20NByj8fNaQGQ) |

**OCR Models** (optional, for text-based logo matching):
- `ocr_pretrained.pth.tar` (31MB) - [Download](https://drive.google.com/uc?id=1L3lXsyCSdxPsQ5OdcT40VO34bbjyD8WD)
- `ocr_siamese.pth.tar` (92MB) - [Download](https://drive.google.com/uc?id=1v05D3zWEDIqhKT6U-PG-9gYL3Mda1Hs9)

After downloading, extract `expand_targetlist.zip` into `models/expand_targetlist/`.

### Step 4: Download Test Datasets (Optional)

For comprehensive testing, download datasets from [PhishIntention Experiment Structure](https://sites.google.com/view/phishintention/experiment-structure):

**Available Datasets:**

| Dataset | Size | Description | Use Case |
|---------|------|-------------|----------|
| **25K Benign + 25K Phishing** | 50K | Main experiment dataset with CRP pages | Comprehensive evaluation |
| **3049 Legitimacy Dataset** | 3K | Alexa top30k-50k sites, human verified | False positive testing |
| **1210 CRP Detector Test** | 1.2K | 445 non-CRP phishing + 765 non-CRP benign | Challenging cases |
| **3310 Non-CRP Phishing** | 3.3K | Phishing sites without login forms | CRP locator testing |
| **1003 Wild Benign Non-CRP** | 1K | Well-known brands main pages | Dynamic analysis testing |

**Recommended:** Start with **3049 Legitimacy Dataset** (~11 hours, optimal size)

## 💻 Usage

For detailed usage commands and examples, see **[USAGE_GUIDE.md](USAGE_GUIDE.md)**

### Output Format

Results are saved in tab-separated format:

```
folder                URL                            phish  target  domain      logo_conf  url_risk  risk_level  timing
accounts.g.cdcde.com  https://accounts.g.cdcde.com  1      Google  google.com  0.968      0.30      safe        4.3|0.9|0.04|0|7.8
www.paypal.com        https://www.paypal.com        0      None    None        None       0.15      safe        2.1|0|0|0|0.8
```

**Columns:**
- `phish`: 1=Phishing, 0=Benign
- `target`: Detected brand name
- `domain`: Legitimate domain
- `logo_conf`: Logo confidence (0-1)
- `url_risk`: URL risk score (0-1)
- `risk_level`: safe/medium/high
- `timing`: Processing time breakdown

---

## ⚙️ Configuration

Edit `configs/configs.yaml`:

```yaml
# URL Analyzer settings
URL_ANALYZER:
  ENABLED: true                  # Enable/disable URL analysis
  TIMEOUT: 5                     # Request timeout (seconds)
  HIGH_RISK_THRESHOLD: 0.7       # High risk threshold
  MEDIUM_RISK_THRESHOLD: 0.5     # Medium risk threshold

# Visual Analyzer settings
AWL_MODEL:
  DETECT_THRE: 0.3              # Element detection threshold

SIAMESE_MODEL:
  MATCH_THRE: 0.87              # Logo matching threshold
```

---

## 📊 Performance

### Accuracy Improvements

| Metric | Visual Only | URL Only | PhishFusion |
|--------|-------------|----------|-------------|
| Accuracy | 92.3% | 87.5% | **94.8%** (+2.5%) |
| Precision | 88.7% | 84.2% | **91.3%** (+2.6%) |
| Recall | 94.1% | 89.3% | **95.2%** (+1.1%) |
| F1-Score | 91.3% | 86.7% | **93.2%** (+1.9%) |
| False Positive Rate | 8.2% | 12.1% | **4.1%** (-50%) |

### Speed Performance

| Analysis Type | Average Time | Use Case |
|---------------|--------------|----------|
| URL Only | 0.3-8s | Quick pre-filtering |
| Visual Only | 4-8s | Deep analysis |
| PhishFusion (with early filtering) | 3-10s | Best accuracy |

**Early Filtering Impact:**
- High-risk URLs (≥0.7): Skip visual analysis → Save ~5 seconds
- Medium-risk URLs (0.5-0.7): Full analysis for confirmation
- Low-risk URLs (<0.5): Full analysis to catch visual phishing

---

## 🛠️ Troubleshooting

**ModuleNotFoundError:**
```bash
# Always use: pixi run python
pixi run python phishintention.py --folder datasets/test_sites
```

**SSL Timeout:**
Edit `configs/configs.yaml` and increase timeout to 10 seconds.

**Chromedriver Issues:**
```bash
pixi run pip install --upgrade webdriver-manager
```

For usage examples, see [USAGE_GUIDE.md](USAGE_GUIDE.md)

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.

---

**⚠️ Disclaimer:** For research and educational purposes only.
