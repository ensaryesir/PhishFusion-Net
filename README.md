# PhishFusion-Net
<div align="center">

![Dialogues](https://img.shields.io/badge/Protected\_Brands\_Size-277-green?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Fork](https://img.shields.io/badge/Fork-PhishIntention-orange?style=flat-square)

</div>

<p align="center">
  <a href="https://www.usenix.org/conference/usenixsecurity22/presentation/liu-ruofan">Paper</a> •
  <a href="https://sites.google.com/view/phishintention">Website</a> •
  <a href="https://www.youtube.com/watch?v=yU7FrlSJ818">Video</a> •
  <a href="https://github.com/lindsey98/PhishIntention">Original Repo</a>
</p>

## About PhishFusion-Net

**PhishFusion-Net** is an enhanced fork of the original [PhishIntention](https://github.com/lindsey98/PhishIntention) project, with additional **URL-based detection** features for improved phishing detection accuracy.

### Original Project

This project is based on the official implementation of **"Inferring Phishing Intention via Webpage Appearance and Dynamics: A Deep Vision-Based Approach"** published at USENIX Security 2022.

- **Original Paper:** [http://linyun.info/publications/usenix22.pdf](http://linyun.info/publications/usenix22.pdf)
- **Original Repository:** [https://github.com/lindsey98/PhishIntention](https://github.com/lindsey98/PhishIntention)
- **Project Website:** [https://sites.google.com/view/phishintention/home](https://sites.google.com/view/phishintention/home)

### Enhancements in PhishFusion-Net

This fork extends the original PhishIntention with:

- 🔗 **URL-based Detection Module**: Advanced URL analysis for suspicious patterns
- 📊 **Improved Detection Pipeline**: Combined vision-based and URL-based analysis
- 🚀 **Enhanced Performance**: Multi-layered approach for higher accuracy
- 🛠️ **Better Integration**: Streamlined setup and improved cross-platform support

### Key Innovations (Original Paper)

**Our contributions:**
- :white_check_mark: We propose a reference-based phishing detection system that captures both **brand intention** and **credential-taking intention**.

---

## Framework

<img src="big_pic/Screenshot 2021-08-13 at 9.15.56 PM.png" style="width:2000px;height:350px"/>

**Input:** A screenshot | **Output:** Phish/Benign, Phishing target

### Pipeline Overview

- **Step 1: Abstract Layout Detector**
  - Get predicted elements (logo, input fields, buttons, etc.)

- **Step 2: Siamese Logo Comparison**
  - If no target detected → `Return Benign, None`
  - If target detected → Proceed to Step 3

- **Step 3: CRP Classifier** (Credential Request Page)
  - If CRP page detected → Go to Step 5
  - If not CRP and haven't run CRP Locator → Go to Step 4
  - If not CRP and already ran CRP Locator → `Return Benign, None`

- **Step 4: CRP Locator** (Dynamic Analysis)
  - Find and click login/signup links
  - If CRP page reached → Go back to Step 1 with new URL and screenshot
  - If no CRP found → `Return Benign, None`

- **Step 5: Final Decision**
  - If CRP + Logo match → `Return Phish, Phishing target`
  - Else → `Return Benign, None`

---

## Project Structure

```
PhishFusion-Net/
├── configs/              # Configuration files for detection models
│   ├── configs.yaml      # Global configurations (thresholds, paths)
│   ├── faster_rcnn_web.yaml
│   └── faster_rcnn_login_lr0.001_finetune.yaml
├── modules/              # Core inference modules
│   ├── awl_detector.py   # Abstract layout detector (Faster R-CNN)
│   ├── crp_classifier.py # Credential page classifier
│   ├── crp_locator.py    # Dynamic analysis for login pages
│   └── logo_matching.py  # OCR-aided Siamese logo matcher
├── models/               # Model weights and reference list
│   ├── layout_detector.pth
│   ├── crp_classifier.pth.tar
│   ├── crp_locator.pth
│   ├── ocr_pretrained.pth.tar
│   ├── ocr_siamese.pth.tar
│   ├── domain_map.pkl
│   └── expand_targetlist/  # 277 protected brands
├── ocr_lib/              # External OCR encoder code
├── utils/                # Utility functions
│   ├── utils.py
│   └── web_utils.py      # Selenium/Chrome automation
├── datasets/test_sites/  # Example test sites
├── chromedriver-linux64/ # Chromedriver directory
├── configs.py            # Configuration loader
├── phishintention.py     # Main entry point
└── pixi.toml             # Dependency management
```

---

## Installation & Setup

### Prerequisites

- **[Pixi Package Manager](https://pixi.sh/latest/)** (Recommended)
- **Google Chrome**

### Step 1: Clone the Repository

```bash
git clone https://github.com/ensaryesir/PhishFusion-Net.git
cd PhishFusion-Net
```

### Step 2: Install Dependencies

#### Using Pixi

```bash
pixi install
```

This will automatically:
- Create a Python 3.8+ environment
- Install PyTorch, Detectron2, Selenium, and all dependencies
- Set up the environment properly

### Step 3: Download Model Weights

Due to Google Drive download limits, you need to manually download these files and place them in the `models/` directory:

| File | Download Link | Size | Description |
|------|---------------|------|-------------|
| `layout_detector.pth` | [Download](https://drive.google.com/uc?id=1HWjE5Fv-c3nCDzLCBc7I3vClP1IeuP_I) | ~330 MB | Layout detection model |
| `crp_classifier.pth.tar` | [Download](https://drive.google.com/uc?id=1igEMRz0vFBonxAILeYMRWTyd7A9sRirO) | ~188 MB | CRP classifier |
| `crp_locator.pth` | [Download](https://drive.google.com/uc?id=1_O5SALqaJqvWoZDrdIVpsZyCnmSkzQcm) | ~200 MB | CRP locator (rename from `model_final.pth`) |
| `ocr_pretrained.pth.tar` | [Download](https://drive.google.com/uc?id=15pfVWnZR-at46gqxd50cWhrXemP8oaxp) | ~50 MB | OCR pretrained model (rename from `demo_downgrade.pth.tar`) |
| `ocr_siamese.pth.tar` | [Download](https://drive.google.com/uc?id=1BxJf5lAcNEnnC0In55flWZ89xwlYkzPk) | ~50 MB | OCR Siamese model |
| `expand_targetlist.zip` | [Download](https://drive.google.com/uc?id=1fr5ZxBKyDiNZ_1B6rRAfZbAHBBoUjZ7I) | ~100 MB | Reference brand logos |
| `domain_map.pkl` | [Download](https://drive.google.com/uc?id=1qSdkSSoCYUkZMKs44Rup_1DPBxHnEKl1) | ~211 KB | Domain mapping |

**After downloading:**

1. Place all `.pth`, `.tar`, and `.pkl` files in `models/`
2. Extract `expand_targetlist.zip`:

```bash
# Windows PowerShell
cd models
Expand-Archive -Force expand_targetlist.zip -DestinationPath .

# Linux/Mac
cd models
unzip expand_targetlist.zip
```

3. Delete cache files if they exist (for first-time setup):

```bash
# Windows
Remove-Item LOGO_FEATS.npy, LOGO_FILES.npy -ErrorAction SilentlyContinue

# Linux/Mac
rm -f LOGO_FEATS.npy LOGO_FILES.npy
```

### Step 4: Setup Chromedriver

The project uses **webdriver-manager** which automatically downloads the correct chromedriver version. No manual setup needed!

**Alternative manual setup:**

1. Check your Chrome version: `chrome://version/` in browser
2. Download matching chromedriver from [chrome-for-testing](https://googlechromelabs.github.io/chrome-for-testing/)
3. Extract `chromedriver.exe` (Windows) or `chromedriver` (Linux/Mac)
4. Place in `chromedriver-linux64/` directory

---

## Usage

### Running PhishIntention

```bash
pixi run python phishintention.py --folder datasets/test_sites --output_txt results.txt
```

**Parameters:**
- `--folder`: Directory containing test websites
- `--output_txt`: Output file for results (default: `{date}_results.txt`)

### First Run

⏳ **Important:** The first run takes ~30 minutes because it loads and processes the reference list (2996 logos from 277 brands). Subsequent runs use cached data and complete in seconds.

You'll see:
```
Load protected logo list
100%|███████████| 271/271 [30:54<00:00, 6.84s/it]
Finish loading protected logo list
Length of reference list = 2996
```

### Test Folder Structure

Organize your test sites as follows:

```
datasets/test_sites/
├── example.com/
│   ├── info.txt       # Contains: https://example.com
│   ├── shot.png       # Screenshot (1920x1080 recommended)
│   └── html.txt       # HTML source code (optional)
├── phishing-site.com/
│   ├── info.txt
│   ├── shot.png
│   └── html.txt
└── ...
```

**Creating test data:**
- `info.txt`: Single line with the URL
- `shot.png`: Full-page screenshot (use Selenium or browser tools)
- `html.txt`: Page HTML source (optional, helps with heuristics)

### Output Format

Results are saved in tab-separated format:

```
folder_name    URL    phish(0/1)    target_brand    matched_domain    confidence    timing
```

**Example:**
```
accounts.g.cdcde.com    https://accounts.g.cdcde.com    1    Google    google.com    0.968    4.38|1.43|0.05|0
www.paypal.com          https://www.paypal.com          0    None      None          None     2.77|1.64|0|0
```

**Fields:**
- **phish**: `0` = Benign, `1` = Phishing
- **target_brand**: Detected brand name (e.g., "Google", "PayPal")
- **matched_domain**: Associated legitimate domain(s)
- **confidence**: Logo matching confidence score (0-1)
- **timing**: `AWL|LogoMatch|CRP_Classifier|CRP_Locator` (seconds)

---

## Configuration

Edit `configs/configs.yaml` to adjust detection thresholds:

```yaml
AWL_MODEL:
  DETECT_THRE: 0.3      # Layout detection confidence threshold

CRP_CLASSIFIER:
  MODEL_TYPE: 'mixed'   # HTML heuristic + visual classifier

CRP_LOCATOR:
  DETECT_THRE: 0.05     # Login button detection threshold

SIAMESE_MODEL:
  MATCH_THRE: 0.87      # Logo matching threshold (0-1)
  NUM_CLASSES: 277      # Number of protected brands
```

**Tuning tips:**
- **Lower `MATCH_THRE`**: More sensitive (more detections, potential false positives)
- **Higher `MATCH_THRE`**: More conservative (fewer false positives, may miss some phishing)

---

## Troubleshooting

### Common Issues

**1. "Length of reference list = 0"**
- **Solution:** Ensure `expand_targetlist.zip` is extracted to `models/expand_targetlist/`
- Delete `LOGO_FEATS.npy` and `LOGO_FILES.npy`, then re-run

**2. Chromedriver errors**
- **Solution:** The project uses automatic chromedriver management
- If issues persist, manually download matching version for your Chrome

**3. CUDA/GPU errors**
- **Solution:** The project automatically uses CPU if no GPU is available
- No changes needed; CPU mode works fine

**4. Out of memory**
- **Solution:** Requires ~8 GB RAM minimum
- Close other applications or reduce batch size

**5. "Import detectron2" errors**
- **Solution:** Reinstall detectron2:
  ```bash
  pixi run pip install 'git+https://github.com/facebookresearch/detectron2.git'
  ```

---

## Related Work

- **Original PhishIntention:** [https://github.com/lindsey98/PhishIntention](https://github.com/lindsey98/PhishIntention)
- **Phishing Baselines:** [https://github.com/lindsey98/PhishingBaseline](https://github.com/lindsey98/PhishingBaseline)

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Note:** This is a fork of the original PhishIntention project. Please refer to the original repository for their licensing terms.

---

## Contact & Support

### For PhishFusion-Net (This Fork)
- **Repository:** [GitHub Issues](https://github.com/ensaryesir/PhishFusion-Net/issues)
- **Maintainer:** Ensar Yesir

### For Original PhishIntention
- **Authors:** [liu.ruofan16@u.nus.edu](mailto:liu.ruofan16@u.nus.edu), [lin_yun@sjtu.edu.cn](mailto:lin_yun@sjtu.edu.cn), [dcsdjs@nus.edu.sg](mailto:dcsdjs@nus.edu.sg)
- **Repository:** [https://github.com/lindsey98/PhishIntention](https://github.com/lindsey98/PhishIntention)

---

**⚠️ Disclaimer:** This tool is for research and educational purposes only. Always follow ethical guidelines and obtain proper authorization before testing websites.
