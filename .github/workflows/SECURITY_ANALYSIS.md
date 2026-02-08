# Security Analysis Workflow

Bu workflow, OWASP Juice Shop projesi için kapsamlı güvenlik analizi sağlar.

## 🔧 Araçlar

### 1. **Semgrep** - Statik Kod Analizi
Semgrep, kod güvenlik açıklarını ve anti-patternleri tespit eden açık kaynaklı bir statik analiz aracıdır.

**Kullanılan Kural Setleri:**
- `auto` - Otomatik dil tespiti ve temel kurallar
- `p/owasp-top-ten` - OWASP Top 10 güvenlik açıkları
- `p/security-audit` - Genel güvenlik denetimi
- `p/nodejs` - Node.js özel kuralları
- `p/typescript` - TypeScript özel kuralları
- `p/expressjs` - Express.js framework kuralları
- `p/sql-injection` - SQL injection tespiti
- `p/xss` - XSS (Cross-Site Scripting) tespiti

**Çıktılar:**
- SARIF formatı (GitHub Security tab'a yüklenir)
- JSON formatı (detaylı analiz için)

### 2. **Syft** - Software Bill of Materials (SBOM)
Syft, projedeki tüm bağımlılıkları ve paketleri tespit edip SBOM oluşturur.

**Oluşturulan SBOM'lar:**
- Backend bağımlılıkları (root package.json)
- Frontend bağımlılıkları (frontend/package.json)
- Docker image (eğer build edilirse)

**Format Çıktıları:**
- Syft JSON (native format)
- SPDX JSON (industry standard)
- CycloneDX JSON (industry standard)

### 3. **Grype** - Vulnerability Scanner
Grype, Syft tarafından oluşturulan SBOM'ları kullanarak bilinen güvenlik açıklarını tarar.

**Özellikler:**
- CVE veritabanı ile otomatik eşleştirme
- Kritik seviyedeki açıklarda build'i fail edebilir
- SARIF ve JSON çıktı formatları

## 🚀 Workflow Tetikleyicileri

Workflow aşağıdaki durumlarda çalışır:

1. **Push Events:**
   - `develop` branch'e push
   - `master` branch'e push
   - Markdown ve screenshot dosyaları hariç

2. **Pull Request Events:**
   - `develop` veya `master`'a açılan PR'lar
   - Markdown dosyaları hariç

3. **Scheduled (Zamanlanmış):**
   - Her Pazartesi saat 02:00'de otomatik çalışır

4. **Manual (Manuel):**
   - GitHub Actions UI'dan "Run workflow" butonu ile

## 📊 Jobs ve Workflow

### Job 1: `semgrep` - SARIF Çıktısı
- Container: `semgrep/semgrep`
- SARIF formatında rapor üretir
- GitHub Security tab'a yüklenir
- Artifact olarak saklanır (30 gün)

### Job 2: `semgrep-json` - JSON Çıktısı
- Container: `semgrep/semgrep`
- JSON formatında detaylı rapor
- Artifact olarak saklanır (30 gün)

### Job 3: `syft-sbom` - SBOM Oluşturma
- Backend, frontend ve Docker için ayrı SBOM'lar
- Multiple format desteği (JSON, SPDX, CycloneDX)
- Artifact olarak saklanır (90 gün)

### Job 4: `grype-vulnerability-scan` - Zafiyet Tarama
- Syft SBOM'larını kullanır
- Backend ve frontend için ayrı taramalar
- Kritik zafiyetlerde uyarı verir
- SARIF ve JSON çıktıları
- Artifact olarak saklanır (30 gün)

### Job 5: `security-report` - Özet Rapor
- Tüm sonuçları birleştirir
- GitHub Step Summary'de özet gösterir
- Tüm raporları tek artifact'ta toplar (90 gün)

## 📁 Artifact'lar

Workflow sonunda oluşan artifact'lar:

1. **semgrep-results** (30 gün)
   - `semgrep-results.sarif`

2. **semgrep-results-json** (30 gün)
   - `semgrep-results.json`

3. **sbom-reports** (90 gün)
   - `sbom-backend.json`
   - `sbom-backend-spdx.json`
   - `sbom-backend-cyclonedx.json`
   - `sbom-frontend.json`
   - `sbom-frontend-spdx.json`
   - `sbom-frontend-cyclonedx.json`
   - `sbom-docker.json` (opsiyonel)
   - `sbom-docker-spdx.json` (opsiyonel)
   - `sbom-docker-cyclonedx.json` (opsiyonel)

4. **grype-vulnerability-reports** (30 gün)
   - `grype-backend-results.sarif`
   - `grype-backend-results.json`
   - `grype-frontend-results.sarif`
   - `grype-frontend-results.json`

5. **security-analysis-complete** (90 gün)
   - Tüm yukarıdaki artifact'ların birleşimi

## 🔍 Sonuçları Görüntüleme

### GitHub Security Tab
1. Repository → Security → Code scanning alerts
2. Semgrep ve Grype sonuçları burada görünür
3. Her finding için detaylı açıklama ve çözüm önerileri

### GitHub Actions Summary
1. Workflow run'a tıklayın
2. En altta "Summary" sekmesinde özet rapor görünür
3. Findings sayıları ve severity breakdown

### Artifact Download
1. Workflow run → Artifacts bölümü
2. İstediğiniz artifact'ı indirin
3. JSON dosyalarını analiz edin

## ⚙️ Özelleştirme

### Semgrep Kurallarını Değiştirme

`.github/workflows/security-analysis.yml` dosyasında `semgrep scan` komutunu düzenleyin:

```yaml
semgrep scan \
  --config=p/owasp-top-ten \      # Bu satırı ekleyin/çıkarın
  --config=p/cwe-top-25 \         # Yeni kural seti ekleyin
```

**Popüler Kural Setleri:**
- `p/cwe-top-25` - CWE Top 25
- `p/jwt` - JWT güvenlik kontrolleri
- `p/secrets` - Hardcoded secrets tespiti
- `p/docker` - Dockerfile güvenlik kontrolleri

Tüm kural setleri: https://semgrep.dev/r

### Grype Fail Threshold'u Değiştirme

```yaml
grype sbom:./sbom-backend.json \
  --fail-on high    # critical yerine high severity'de fail
```

Seçenekler: `negligible`, `low`, `medium`, `high`, `critical`

### Schedule Zamanını Değiştirme

```yaml
schedule:
  - cron: '0 2 * * 1'  # Her Pazartesi 02:00
  # '0 0 * * *'        # Her gün gece yarısı
  # '0 */6 * * *'      # Her 6 saatte bir
```

## 🛠️ Lokal Çalıştırma

### Semgrep
```bash
# Kurulum
pip install semgrep

# Çalıştırma
semgrep scan \
  --config=auto \
  --config=p/owasp-top-ten \
  --json \
  --output=semgrep-results.json
```

### Syft
```bash
# Kurulum
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# SBOM oluşturma
syft dir:. -o json=sbom.json
```

### Grype
```bash
# Kurulum
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Zafiyet tarama
grype sbom:./sbom.json -o json=vulnerabilities.json
```

## 📌 Notlar

- Bu proje (OWASP Juice Shop) **kasıtlı olarak güvenlik açıkları içerir** (eğitim amaçlı)
- Semgrep ve Grype çok sayıda bulgu rapor edecektir - bu **beklenen bir durumdur**
- Raporları inceleyerek hangi açıkların kasıtlı olduğunu öğrenebilirsiniz
- Yeni özellik eklerken bu workflow'un pass etmesini beklemeyin
- Workflow'u öğrenme amaçlı kullanın

## 🔗 Kaynaklar

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Syft GitHub](https://github.com/anchore/syft)
- [Grype GitHub](https://github.com/anchore/grype)
- [SARIF Format](https://sarifweb.azurewebsites.net/)
- [SPDX Spec](https://spdx.dev/)
- [CycloneDX](https://cyclonedx.org/)
