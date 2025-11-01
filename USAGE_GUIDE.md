# PhishFusion-Net Kullanım Rehberi

## 🚀 Kullanım Komutları

```bash
# Sadece Visual - Tek site
pixi run python phishintention.py --folder datasets/legitimacy_3049/about.google --mode visual

# Sadece URL - Tek site
pixi run python phishintention.py --folder datasets/legitimacy_3049/about.google --mode url

# PhishFusion (URL + Visual) - Tek site
pixi run python phishintention.py --folder datasets/legitimacy_3049/about.google --mode fusion

# Tüm veriseti
pixi run python phishintention.py --folder datasets/legitimacy_3049 --mode fusion --output_txt results.txt
```