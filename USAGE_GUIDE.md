# PhishFusion-Net Usage Guide

## 🎯 Analysis Modes

PhishFusion-Net can operate in three different modes:

- **`visual`** - Visual analysis only (Logo + CRP detection)
- **`url`** - URL analysis only (fast, ideal for batch processing) ⚡
- **`fusion`** - URL + Visual (most accurate, recommended) 🎯

---

## 🚀 Basic Usage

### 1️⃣ Single Site Analysis

```bash
# Visual-only mode (URL analysis disabled)
pixi run python phishintention.py --folder datasets/legitimacy_3049/about.google --mode visual

# URL-only mode (fast, models not loaded)
pixi run python phishintention.py --folder datasets/legitimacy_3049/about.google --mode url

# Fusion mode (URL + Visual - most accurate)
pixi run python phishintention.py --folder datasets/legitimacy_3049/about.google --mode fusion
```

### 2️⃣ Batch Processing

```bash
# Entire dataset - Fusion mode
pixi run python phishintention.py --folder datasets/legitimacy_3049 --mode fusion --output_txt results.txt

# URL analysis only (1000x faster!)
pixi run python phishintention.py --folder datasets/legitimacy_3049 --mode url --output_txt url_results.txt
```

---

## 📊 Results File Format

`results.txt` file in tab-separated values (TSV) format:

```
folder_name	url	phish_category	pred_target	matched_domain	siamese_conf	url_risk_score	risk_level	runtime
```

**Columns:**
1. `folder_name` - Site folder name
2. `url` - Analyzed URL
3. `phish_category` - 0 (benign) or 1 (phishing)
4. `pred_target` - Detected brand (if any)
5. `matched_domain` - Matched domain
6. `siamese_conf` - Logo matching confidence (0-1)
7. `url_risk_score` - URL risk score (0-1)
8. `risk_level` - low/medium/high
9. `runtime` - awl|logo_match|crp_class|crp_locator|url_analysis (seconds)

---

## 🔄 Resume Support

Program automatically tracks processed URLs:

```bash
# First run - processes 100 sites
pixi run python phishintention.py --folder datasets/big --mode fusion --output_txt results.txt

# If interrupted, resumes from where it left off
# Output: "Loaded 100 already processed URLs"
pixi run python phishintention.py --folder datasets/big --mode fusion --output_txt results.txt
```

**Performance:**
- ✅ O(1) set-based lookup
- ✅ 10,000 URL check → ~0.01 seconds
- ✅ NO reprocessing

---

## 🔍 Analyzing Results

### Simple Filtering
```powershell
# Show only phishing sites
Select-String -Path results.txt -Pattern "1`t" | Select-Object -First 10

# Find high-risk URLs
Select-String -Path results.txt -Pattern "high"

# Find specific brand impersonations
Select-String -Path results.txt -Pattern "paypal"
```

---

## 📈 Performance Comparison

| Dataset Size | Visual Mode | URL Mode | Fusion Mode |
|--------------|-------------|----------|-------------|
| 1 site | ~2 sec | ~0.01 sec | ~2 sec |
| 10 sites | ~20 sec | ~0.1 sec | ~20 sec |
| 100 sites | ~3 min | ~1 sec | ~3 min |
| 1,000 sites | ~30 min | ~5 sec | ~30 min |
| 10,000 sites | ~5 hours | ~10 sec | ~5 hours |
| 100,000 sites | ~2 days | ~1 min | ~2 days |

**Note:** Performance varies based on RAM, CPU, GPU.

---

## 🎓 Advanced Usage

### Parallel Processing (Manual)
```bash
# Split dataset and run in parallel
# Terminal 1:
pixi run python phishintention.py --folder datasets/part1 --mode url --output_txt results1.txt

# Terminal 2:
pixi run python phishintention.py --folder datasets/part2 --mode url --output_txt results2.txt

# Terminal 3:
pixi run python phishintention.py --folder datasets/part3 --mode url --output_txt results3.txt

# Then combine:
cat results1.txt results2.txt results3.txt > combined.txt
```

---

## 📝 Notes

1. **First run may be slow** (loading models)
2. **GPU is used automatically if available** (CUDA)
3. **Results.txt uses UTF-8 encoding**
4. **Processed URLs are tracked automatically** (O(1) performance)
5. **Visualization is saved only if phishing is detected**

---

## 🆘 Help

```bash
# Show all options
pixi run python phishintention.py --help

# See example commands
# (Available in argparse epilog)
```
