# PhishFusion-Net Kullanım Rehberi

## 📚 İçindekiler
1. [Kurulum](#kurulum)
2. [URL Analyzer (Tek Başına)](#url-analyzer-tek-başına)
3. [Visual Analyzer (Tek Başına)](#visual-analyzer-tek-başına)
4. [Birlikte Kullanım (PhishFusion)](#birlikte-kullanım-phishfusion)
5. [Örnekler ve Test Senaryoları](#örnekler-ve-test-senaryoları)

---

## Kurulum

### Gereksinimler
- Python 3.8+
- Pixi package manager
- Google Chrome tarayıcı

### 1. Depoyu Klonlayın
```bash
git clone https://github.com/ensaryesir/PhishFusion-Net.git
cd PhishFusion-Net
```

### 2. Bağımlılıkları Yükleyin
```bash
pixi install
```

### 3. Model Dosyalarını İndirin
Model dosyalarını `models/` klasörüne yerleştirin. Detaylar için README.md'ye bakın.

---

## URL Analyzer (Tek Başına)

URL Analyzer, bir web sitesinin URL'sini analiz ederek phishing olma ihtimalini değerlendirir.

### Python Kodu İle Kullanım

```python
from modules.url_analyzer import URLAnalyzer

# Analyzer oluştur
analyzer = URLAnalyzer(timeout=5)

# URL'yi analiz et
url = "https://paypal-secure-verify.tk"
features = analyzer.analyze(url)

# Sonuçları göster
print(f"Risk Score: {features['risk_score']:.2f}")
print(f"Risk Level: {features['risk_level']}")
print(f"Uses HTTPS: {features['uses_https']}")
print(f"Is IP Address: {features['is_ip_address']}")
print(f"Brand Impersonation: {features.get('brand_impersonation', 'None')}")

# Özet rapor
summary = analyzer.get_summary(features)
print(summary)
```

**Örnek Çıktı:**
```
URL Risk Analysis Summary:
Risk Score: 0.75 (HIGH)

Suspicious Indicators:
  ⚠ URL contains suspicious keywords
  ⚠ Suspicious TLD (.tk)
  ⚠ Brand impersonation detected (PayPal)
  ✓ Uses HTTPS encryption
```

### Hızlı Kontrol

```python
from modules.url_analyzer import quick_url_check

url = "https://suspicious-site.tk"
risk_score, risk_level = quick_url_check(url)

if risk_level == 'high':
    print(f"⚠️ YÜKSEK RİSK: {risk_score:.2f}")
elif risk_level == 'medium':
    print(f"⚠️ ORTA RİSK: {risk_score:.2f}")
else:
    print(f"✅ GÜVENLİ: {risk_score:.2f}")
```

### Toplu URL Analizi

```python
from modules.url_analyzer import URLAnalyzer
import json

analyzer = URLAnalyzer()

# URL listesi
urls = [
    "https://www.google.com",
    "http://192.168.1.1/login",
    "https://paypal-verify.tk",
    "https://www.amazon.com"
]

# Tüm URL'leri analiz et
results = []
for url in urls:
    features = analyzer.analyze(url)
    results.append({
        'url': url,
        'risk_score': features['risk_score'],
        'risk_level': features['risk_level']
    })

# JSON olarak kaydet
with open('url_analysis_results.json', 'w') as f:
    json.dump(results, f, indent=2)

# Sonuçları göster
for result in results:
    print(f"{result['url']:50} | Score: {result['risk_score']:.2f} | {result['risk_level'].upper()}")
```

### URL Analyzer Özellikleri

**45+ Özellik Çıkarımı:**

1. **Lexical Features (15)**
   - URL uzunluğu, karakter sayıları
   - Entropy (rastgelelik ölçütü)
   - Rakam/harf oranları

2. **Domain Features (10)**
   - TLD analizi (.tk, .ml gibi şüpheli TLD'ler)
   - Subdomain yapısı
   - IP adresi tespiti
   - Punycode (IDN) kontrolü

3. **SSL/Certificate Features (8)**
   - HTTPS kullanımı
   - Sertifika geçerliliği
   - Sertifika yaşı
   - Son kullanma tarihi

4. **Pattern Features (12)**
   - Homograph saldırıları (а vs a)
   - Marka taklidi tespiti
   - URL kısaltıcılar
   - @ sembolü varlığı

5. **Redirect Analysis (5)**
   - Yönlendirme zinciri
   - Domain değişimi
   - Final destination

---

## Visual Analyzer (Tek Başına)

Visual Analyzer, web sitesinin ekran görüntüsünü analiz ederek logo eşleştirme ve CRP (Credential Request Page) tespiti yapar.

### Gerekli Dosyalar

Her test için şu dosyalar gereklidir:
```
test_folder/
├── shot.png      # Ekran görüntüsü (1920x1080 önerilen)
├── html.txt      # HTML kaynak kodu (opsiyonel)
└── info.txt      # URL bilgisi
```

### Python Kodu İle Kullanım

```python
from phishintention import PhishIntentionWrapper

# Visual analyzer'ı başlat (URL analysis olmadan)
detector = PhishIntentionWrapper(enable_url_analysis=False)

# Tek bir site analizi
url = "https://accounts.g.cdcde.com"
screenshot_path = "datasets/test_sites/accounts.g.cdcde.com/shot.png"

# Analiz et
phish_category, pred_target, matched_domain, plotvis, confidence, \
    timing, pred_boxes, pred_classes, _, _ = detector.test_orig_phishintention(url, screenshot_path)

# Sonuçları göster
if phish_category == 1:
    print(f"⚠️ PHISHING TESPİT EDİLDİ!")
    print(f"Hedef Marka: {pred_target}")
    print(f"Domain: {matched_domain}")
    print(f"Güven Skoru: {confidence:.3f}")
else:
    print(f"✅ Benign (Zararsız)")

print(f"İşlem Süresi: {timing}")

# Görselleştirilmiş sonucu kaydet
import cv2
cv2.imwrite("result_visualization.png", plotvis)
```

### Klasör Bazlı Analiz

```bash
# Bir klasördeki tüm siteleri analiz et
pixi run python -c "
from phishintention import PhishIntentionWrapper
import os

detector = PhishIntentionWrapper(enable_url_analysis=False)

folder = 'datasets/test_sites/accounts.g.cdcde.com'
url = open(os.path.join(folder, 'info.txt')).read().strip()
screenshot = os.path.join(folder, 'shot.png')

result = detector.test_orig_phishintention(url, screenshot)
print(f'Phishing: {result[0]}, Target: {result[1]}')
"
```

### Visual Analyzer Pipeline

**5 Adımlı İşlem:**

1. **Layout Detection (AWL Model)**
   - Logo, input, button elementlerini tespit eder
   - Faster R-CNN kullanır
   - Confidence threshold: 0.3

2. **Logo Matching (Siamese Model)**
   - Tespit edilen logoyu 2996 referans logo ile karşılaştırır
   - 277 marka koruması
   - OCR destekli eşleştirme
   - Threshold: 0.87

3. **CRP Classification**
   - Credential Request Page (giriş sayfası) tespiti
   - HTML heuristic + CNN classifier
   - Mixed model (görsel + layout grid)

4. **Dynamic Analysis (CRP Locator)**
   - Login/signup linklerini bulur
   - Selenium ile otomatik navigasyon
   - 100+ dilde keyword arama

5. **Final Decision**
   - Logo match + CRP = Phishing
   - Domain tutarlılık kontrolü

### Görselleştirme

```python
from phishintention import PhishIntentionWrapper
import cv2

detector = PhishIntentionWrapper(enable_url_analysis=False)

url = "https://example.com"
screenshot = "path/to/screenshot.png"

phish_cat, target, domain, plotvis, conf, timing, boxes, classes, _, _ = \
    detector.test_orig_phishintention(url, screenshot)

# Sonuç görselini kaydet
if phish_cat == 1:
    cv2.imwrite("phishing_detected.png", plotvis)
    print(f"Görselleştirilmiş sonuç kaydedildi: phishing_detected.png")
```

---

## Birlikte Kullanım (PhishFusion)

PhishFusion, URL ve Visual analizleri birleştirerek en yüksek doğruluğu sağlar.

### Komut Satırı Kullanımı

```bash
# Tek klasör analizi
pixi run python phishintention.py --folder datasets/test_sites --output_txt results.txt
```

**Çıktı Formatı:**
```
folder  URL  phish  target  domain  logo_conf  url_risk  risk_level  timing
```

**Örnek:**
```
accounts.g.cdcde.com  https://accounts.g.cdcde.com  1  Google  google.com  0.968  0.30  safe  4.3|0.9|0.04|0|7.8
```

### Python Kodu İle Kullanım

```python
from phishintention import PhishIntentionWrapper

# PhishFusion (URL + Visual)
detector = PhishIntentionWrapper(enable_url_analysis=True)

url = "https://suspicious-site.com"
screenshot = "path/to/screenshot.png"

# Multi-modal analiz
phish_cat, target, domain, plotvis, visual_conf, timing, \
    boxes, classes, url_risk, url_features = detector.test_orig_phishintention(url, screenshot)

# Sonuçlar
print(f"=== PhishFusion Analiz Sonuçları ===")
print(f"URL: {url}")
print(f"\n--- URL Analysis ---")
print(f"Risk Score: {url_risk:.3f}")
print(f"Risk Level: {url_features.get('risk_level', 'unknown').upper()}")
print(f"HTTPS: {url_features.get('uses_https', False)}")
print(f"IP Address: {url_features.get('is_ip_address', False)}")
print(f"Brand Impersonation: {url_features.get('brand_impersonation', 'None')}")

print(f"\n--- Visual Analysis ---")
if phish_cat == 1:
    print(f"Phishing: YES")
    print(f"Target Brand: {target}")
    print(f"Domain: {domain}")
    print(f"Logo Confidence: {visual_conf:.3f}")
else:
    print(f"Phishing: NO (Benign)")

print(f"\n--- Combined Decision ---")
if phish_cat == 1 and url_risk > 0.5:
    print(f"⚠️ HIGH CONFIDENCE PHISHING")
    print(f"Both URL and Visual analysis detected threats!")
elif phish_cat == 1:
    print(f"⚠️ Phishing detected by Visual analysis")
    print(f"URL appears safe but visual is suspicious")
elif url_risk > 0.7:
    print(f"⚠️ URL highly suspicious")
    print(f"Visual analysis did not detect phishing")
else:
    print(f"✅ Site appears safe")

print(f"\nTiming: {timing}")
```

### Karşılaştırmalı Analiz

```python
from phishintention import PhishIntentionWrapper
from modules.url_analyzer import URLAnalyzer

# URL-only
url_analyzer = URLAnalyzer()
url_features = url_analyzer.analyze(url)
print(f"URL-only Risk: {url_features['risk_score']:.3f}")

# Visual-only
visual_detector = PhishIntentionWrapper(enable_url_analysis=False)
result_visual = visual_detector.test_orig_phishintention(url, screenshot)
print(f"Visual-only: Phishing={result_visual[0]}, Target={result_visual[1]}")

# Combined (PhishFusion)
fusion_detector = PhishIntentionWrapper(enable_url_analysis=True)
result_fusion = fusion_detector.test_orig_phishintention(url, screenshot)
print(f"PhishFusion: Phishing={result_fusion[0]}, URL Risk={result_fusion[8]:.3f}")
```

### Multi-Modal Fusion Stratejileri

**1. Early Filtering (Erken Süzme)**
```python
if url_risk >= 0.7:
    print("⚠️ High risk URL - Marked as phishing immediately")
    # Visual analysis atlanabilir
```

**2. Confidence Boosting (Güven Artırma)**
```python
if url_risk >= 0.5 and visual_phishing:
    combined_confidence = 0.8 * visual_conf + 0.2 * url_risk
    print(f"Combined Confidence: {combined_confidence:.3f}")
```

**3. Disambiguation (Belirsizlik Giderme)**
```python
if 0.4 < visual_conf < 0.6:  # Belirsiz
    if url_risk > 0.5:
        print("URL risk helps: Likely phishing")
    else:
        print("URL appears safe: Likely benign")
```

---

## Örnekler ve Test Senaryoları

### Senaryo 1: URL Yakalıyor, Visual Kaçırıyor

```python
# Örnek: IP adresi + meşru görünümlü sayfa
url = "http://192.168.1.1/paypal-login.php"
screenshot = "legitimate_looking_page.png"

# URL analysis
from modules.url_analyzer import quick_url_check
url_score, url_level = quick_url_check(url)
print(f"URL Risk: {url_score:.2f} ({url_level})")  # 0.85 (high)

# Visual analysis (tek başına)
from phishintention import PhishIntentionWrapper
detector = PhishIntentionWrapper(enable_url_analysis=False)
result = detector.test_orig_phishintention(url, screenshot)
print(f"Visual: {result[1]}")  # Might miss it

# PhishFusion (birlikte)
fusion = PhishIntentionWrapper(enable_url_analysis=True)
result_fusion = fusion.test_orig_phishintention(url, screenshot)
print(f"PhishFusion: Phishing={result_fusion[0]}")  # Catches it!
```

### Senaryo 2: Visual Yakalıyor, URL Normal

```python
# Örnek: Sahte PayPal logosu, ama güvenli görünümlü domain
url = "https://secure-payment-portal.com"
screenshot = "fake_paypal_logo.png"

# URL analysis
url_score, url_level = quick_url_check(url)
print(f"URL Risk: {url_score:.2f} ({url_level})")  # 0.35 (low)

# Visual analysis
result = detector.test_orig_phishintention(url, screenshot)
print(f"Visual: Phishing={result[0]}, Target={result[1]}")  # Detects fake logo

# PhishFusion - Visual wins
result_fusion = fusion.test_orig_phishintention(url, screenshot)
print(f"PhishFusion: Phishing={result_fusion[0]}")  # Confirmed phishing
```

### Senaryo 3: Her İkisi de Uyarıyor (Yüksek Güven)

```python
# Örnek: Şüpheli TLD + sahte logo
url = "https://paypal-account-verify.tk/signin"
screenshot = "fake_paypal_complete.png"

# URL analysis
url_score, url_level = quick_url_check(url)
print(f"URL Risk: {url_score:.2f} ({url_level})")  # 0.75 (high)

# Visual analysis
result = detector.test_orig_phishintention(url, screenshot)
print(f"Visual: Phishing={result[0]}")  # Detects phishing

# PhishFusion - Very high confidence
result_fusion = fusion.test_orig_phishintention(url, screenshot)
print(f"PhishFusion: VERY HIGH CONFIDENCE PHISHING")
print(f"URL Risk: {result_fusion[8]:.2f}, Visual Conf: {result_fusion[4]:.2f}")
```

### Senaryo 4: Toplu Test

```python
import os
from phishintention import PhishIntentionWrapper

detector = PhishIntentionWrapper(enable_url_analysis=True)

test_sites = [
    "accounts.g.cdcde.com",      # Phishing
    "www.paypal.com",             # Legitimate
    "suspicious-site.tk"          # Suspicious
]

results = []
for site in test_sites:
    folder = f"datasets/test_sites/{site}"
    if not os.path.exists(folder):
        continue
    
    url = open(os.path.join(folder, "info.txt")).read().strip()
    screenshot = os.path.join(folder, "shot.png")
    
    phish, target, domain, _, conf, timing, _, _, url_risk, url_feats = \
        detector.test_orig_phishintention(url, screenshot)
    
    results.append({
        'site': site,
        'phishing': phish,
        'target': target,
        'url_risk': url_risk,
        'visual_conf': conf
    })
    
    print(f"\n{'='*60}")
    print(f"Site: {site}")
    print(f"Phishing: {'YES' if phish else 'NO'}")
    print(f"Target: {target if target else 'None'}")
    print(f"URL Risk: {url_risk:.3f}")
    print(f"Visual Confidence: {conf if conf else 'N/A'}")

# Özet rapor
print(f"\n{'='*60}")
print(f"SUMMARY: {len(results)} sites analyzed")
phishing_count = sum(1 for r in results if r['phishing'] == 1)
print(f"Phishing detected: {phishing_count}/{len(results)}")
```

---

## Yapılandırma

### configs/configs.yaml

```yaml
# URL Analyzer ayarları
URL_ANALYZER:
  ENABLED: true                  # URL analysis açık/kapalı
  TIMEOUT: 5                     # İstek zaman aşımı (saniye)
  HIGH_RISK_THRESHOLD: 0.7       # Yüksek risk eşiği
  MEDIUM_RISK_THRESHOLD: 0.5     # Orta risk eşiği

# Visual Analyzer ayarları
AWL_MODEL:
  DETECT_THRE: 0.3              # Element tespit eşiği

SIAMESE_MODEL:
  MATCH_THRE: 0.87              # Logo eşleştirme eşiği
```

### Threshold Ayarlama

```python
# URL Analyzer threshold'larını özelleştir
from modules.url_analyzer import URLAnalyzer

analyzer = URLAnalyzer(timeout=10)  # Daha uzun timeout

# Veya configs.yaml'ı düzenleyin
```

---

## Performans İpuçları

### 1. Hızlandırma
```python
# Sadece URL analysis (çok hızlı)
from modules.url_analyzer import quick_url_check
score, level = quick_url_check(url)  # ~0.3 saniye

# URL ile early filtering
detector = PhishIntentionWrapper(enable_url_analysis=True)
# Yüksek riskli URL'ler için visual analysis atlanır
```

### 2. Batch Processing
```python
# Paralel işlem için
from concurrent.futures import ThreadPoolExecutor

urls = [url1, url2, url3, ...]

with ThreadPoolExecutor(max_workers=4) as executor:
    results = list(executor.map(quick_url_check, urls))
```

### 3. Caching
```python
# URL features'ları cache'le
url_cache = {}

def analyze_with_cache(url):
    if url in url_cache:
        return url_cache[url]
    
    features = analyzer.analyze(url)
    url_cache[url] = features
    return features
```

---

## Hata Ayıklama

### Yaygın Hatalar

**1. ModuleNotFoundError: No module named 'torch'**
```bash
# Çözüm: pixi run kullanın
pixi run python phishintention.py --folder datasets/test_sites
```

**2. SSL Timeout**
```yaml
# configs/configs.yaml
URL_ANALYZER:
  TIMEOUT: 10  # Artırın
```

**3. Chromedriver Hatası**
```bash
# Webdriver otomatik yönetiliyor, güncelleme için:
pixi run pip install --upgrade webdriver-manager
```

---

## Katkıda Bulunma

Yeni özellikler eklemek veya hata bildirmek için:
1. Repository'yi fork edin
2. Değişikliklerinizi yapın
3. Pull request gönderin

---

## Destek

Sorular için:
- GitHub Issues: https://github.com/ensaryesir/PhishFusion-Net/issues
- Dokümantasyon: Bu dosya ve README.md
