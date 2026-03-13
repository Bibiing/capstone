# Dynamic Cyber Risk Scoring Engine

### Berbasis Telemetri Wazuh | Studi Kasus Simulasi Perbankan Daerah

> Capstone Project Kolaborasi Industri – ITS 2026

---

## Daftar Isi

1. [Gambaran Umum](#1-gambaran-umum)
2. [Arsitektur Sistem](#2-arsitektur-sistem)
3. [Formula Risk Scoring](#3-formula-risk-scoring)
4. [Struktur Proyek](#4-struktur-proyek)
5. [Tech Stack](#5-tech-stack)
6. [Setup & Instalasi](#6-setup--instalasi)
7. [Konfigurasi](#7-konfigurasi)
8. [Menjalankan Sistem](#8-menjalankan-sistem)
9. [API Reference](#9-api-reference)
10. [Sprint Plan & Roadmap](#10-sprint-plan--roadmap)
11. [Penjelasan Komponen Detail](#11-penjelasan-komponen-detail)
12. [Simulasi & Testing](#12-simulasi--testing)
13. [Koneksi ke Wazuh](#13-koneksi-ke-wazuh)

---

## 1. Gambaran Umum

Proyek ini membangun **Proof of Concept (PoC)** sebuah _Risk Scoring Engine_ yang mengubah telemetri teknis dari Wazuh (alert, log, data kerentanan) menjadi **skor risiko 0–100** per aset yang dapat dipahami oleh manajemen eksekutif perbankan.

### Inti Permasalahan

| Tantangan SOC                                           | Kebutuhan Manajemen                       |
| ------------------------------------------------------- | ----------------------------------------- |
| Volume alert sangat tinggi, sulit diprioritaskan manual | Prioritas mitigasi berbasis risiko nyata  |
| Bahasa teknis sulit dipahami non-teknis                 | Pemantauan tren risiko secara periodik    |
| Tidak ada scoring risiko terpadu per aset               | Ringkasan eksekutif untuk keputusan cepat |

### Output Utama

- ✅ **Skor Risiko Dinamis** per aset (0–100), diperbarui periodik
- ✅ **Dashboard Eksekutif** dengan ranking aset, tren, dan drill-down penyebab skor
- ✅ **Simulasi Spike & Remediation** — skor naik saat serangan, turun saat aman
- ✅ **Model Transparan** — setiap skor bisa dijelaskan faktor pembentuknya

---

## 2. Arsitektur Sistem

```
┌─────────────────────────────────────────────────────────────┐
│                    WAZUH INFRASTRUCTURE                       │
│  Wazuh Manager ──► Wazuh Indexer (OpenSearch)               │
│  https://20.194.14.146  │  https://20.194.14.146:9200        │
└──────────────────────────────┬──────────────────────────────┘
                               │ REST API / Polling (per jam)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                  DATA INGESTION LAYER (Python)                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ Alert Fetcher│  │ SCA Fetcher  │  │ Asset Criticality│  │
│  │ (Threat/T)   │  │ (Vuln/V)     │  │ (Impact/I)       │  │
│  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘  │
└─────────┼─────────────────┼───────────────────┼─────────────┘
          │                 │                   │
          ▼                 ▼                   ▼
┌─────────────────────────────────────────────────────────────┐
│                  RISK SCORING ENGINE (Python)                 │
│  T = Σ(alert × weight) + (T_prev × 0.5)  [Time Decay]       │
│  V = 100 – SCA_Pass%                                          │
│  I = Likert_Score / 5.0                                       │
│  R = I × (0.3×V + 0.7×T)   [cap: 0–100]                     │
└──────────────────────────────┬──────────────────────────────┘
                               │ Write time-series
                               ▼
┌─────────────────────────────────────────────────────────────┐
│               DATABASE (PostgreSQL / TimescaleDB)             │
│  Table: assets | risk_scores | alert_snapshots | sca_scores  │
└──────────────────────────────┬──────────────────────────────┘
                               │ Query
                               ▼
┌─────────────────────────────────────────────────────────────┐
│              DASHBOARD (Streamlit / Next.js)                  │
│  - Top Risk Assets Ranking                                    │
│  - Risk Trend Chart (time-series)                            │
│  - Drill-down: Breakdown T / V / I per aset                  │
│  - Simulasi Spike & Remediation                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Formula Risk Scoring

### Formula Utama

```
R = I × (w1 × V + w2 × T)
```

Di mana:

- **R** = Risk Score Final (0–100)
- **I** = Asset Impact/Criticality (0.0 – 1.0)
- **V** = Vulnerability Score (0–100)
- **T** = Dynamic Threat Score (0–100)
- **w1** = 0.3 (bobot kerentanan/SCA)
- **w2** = 0.7 (bobot ancaman aktif/alert)

---

### 3.1 Impact / Asset Criticality (I)

Sumber: **Kuesioner Likert (1–5)** yang diisi manajemen berdasarkan Balanced Scorecard.

```
I = Likert_Score / 5.0
```

| Likert | Keterangan                                   | I   |
| ------ | -------------------------------------------- | --- |
| 1      | Sangat tidak penting (misal: PC resepsionis) | 0.2 |
| 2      | Tidak penting                                | 0.4 |
| 3      | Sedang                                       | 0.6 |
| 4      | Penting                                      | 0.8 |
| 5      | Sangat kritis (misal: Server DB Nasabah)     | 1.0 |

**8 Pertanyaan Kuesioner** (skala Likert 1–5, rata-rata = skor final):

- **Perspektif Keuangan**: Q1 (downtime → kerugian langsung), Q2 (memproses transaksi besar)
- **Perspektif Pelanggan**: Q3 (kebocoran data → reputasi), Q4 (titik kontak utama layanan)
- **Perspektif Proses Internal**: Q5 (esensial operasional harian), Q6 (tidak ada backup manual)
- **Perspektif Kepatuhan**: Q7 (data pribadi nasabah / regulasi OJK), Q8 (risiko sanksi hukum)

```python
# Implementasi
def calculate_impact(questionnaire_answers: list[int]) -> float:
    """
    questionnaire_answers: list of 8 integers, each 1–5
    returns: float between 0.2 and 1.0
    """
    avg_likert = sum(questionnaire_answers) / len(questionnaire_answers)
    return avg_likert / 5.0
```

---

### 3.2 Vulnerability Score (V)

Sumber: **Wazuh SCA (Security Configuration Assessment)** — Modul audit CIS Benchmark.

```
V = 100 - SCA_Pass_Percentage
```

**Logika**: SCA Score Wazuh = 100% → sistem sangat aman → V = 0 (tidak rentan).

```python
# Implementasi
def calculate_vulnerability(sca_pass_percentage: float) -> float:
    """
    sca_pass_percentage: float 0–100 (dari Wazuh SCA)
    returns: float 0–100 (semakin tinggi = semakin rentan)
    """
    return 100.0 - sca_pass_percentage

# Contoh: 191 checks, 56 passed, 87 failed
# SCA Score = (56 / (56+87)) * 100 = 39.16%
# V = 100 - 39.16 = 60.84
```

---

### 3.3 Dynamic Threat Score (T)

Sumber: **Wazuh Alerts** via API/Indexer. Dihitung per periode (misal: setiap 1 jam atau 4 jam).

**Bobot Level Alert:**
| Level Wazuh | Kategori | Bobot |
|---|---|---|
| 0 – 4 | Rendah (noise, login sukses, error kecil) | 1 |
| 5 – 7 | Menengah (error user, bad word match) | 5 |
| 8 – 11 | Tinggi (brute force, first time seen, integrity warning) | 10 |
| 12 – 15 | Kritikal (serangan nyata, malware, rootkit) | 25 |

**Formula T dengan Time Decay:**

```
T_new   = (count_L1-4 × 1) + (count_L5-7 × 5) + (count_L8-11 × 10) + (count_L12-15 × 25)
T_now   = min(T_new + (T_prev × 0.5), 100)
```

- **decay factor (α) = 0.5**: dampak serangan 1 periode lalu tersisa 50%, terus menyusut jika tidak ada serangan baru
- **Cap 100**: T tidak melebihi 100

```python
# Implementasi
ALERT_WEIGHTS = {
    "low":      {"range": (0, 4),   "weight": 1},
    "medium":   {"range": (5, 7),   "weight": 5},
    "high":     {"range": (8, 11),  "weight": 10},
    "critical": {"range": (12, 15), "weight": 25},
}
DECAY_FACTOR = 0.5

def calculate_threat_score(alert_counts: dict, t_previous: float) -> float:
    """
    alert_counts: {"low": int, "medium": int, "high": int, "critical": int}
    t_previous: float — T score dari periode sebelumnya
    returns: float 0–100
    """
    t_new = (
        alert_counts.get("low", 0) * 1 +
        alert_counts.get("medium", 0) * 5 +
        alert_counts.get("high", 0) * 10 +
        alert_counts.get("critical", 0) * 25
    )
    t_now = t_new + (t_previous * DECAY_FACTOR)
    return min(t_now, 100.0)
```

---

### 3.4 Final Risk Score (R)

```python
def calculate_risk_score(I: float, V: float, T: float,
                          w1: float = 0.3, w2: float = 0.7) -> float:
    """
    I: 0.0–1.0, V: 0–100, T: 0–100
    returns: R in 0–100
    """
    R = I * (w1 * V + w2 * T)
    return round(min(max(R, 0), 100), 2)
```

---

### 3.5 Severity Thresholds (Adaptasi CVSS v3.1)

| Level    | Skor     | CVSS Equivalen | Warna Dashboard |
| -------- | -------- | -------------- | --------------- |
| Low      | 0 – 39   | 0.0 – 3.9      | 🟢 Hijau        |
| Medium   | 40 – 69  | 4.0 – 6.9      | 🟡 Kuning       |
| High     | 70 – 89  | 7.0 – 8.9      | 🟠 Oranye       |
| Critical | 90 – 100 | 9.0 – 10.0     | 🔴 Merah        |

---

## 4. Struktur Proyek

```
capstone/
├── README.md
├── .env.example                  # Template environment variables
├── docker-compose.yml            # Orchestrasi semua service
├── docs/
│   ├── Prototype Formulasi Risk Scoring.txt
│   └── Pengembangan-Dynamic-Cyber-Risk-Scoring-Engine-Berbasis-Telemetri-Wazuh.txt
│
├── ingestion/                    # Data ingestion layer
│   ├── __init__.py
│   ├── wazuh_client.py           # HTTP client ke Wazuh API & Indexer
│   ├── alert_fetcher.py          # Tarik & klasifikasi alert per periode
│   ├── sca_fetcher.py            # Tarik SCA score per agent
│   └── asset_registry.py        # CMDB dummy — daftar aset + Likert score
│
├── engine/                       # Risk Scoring Engine (core logic)
│   ├── __init__.py
│   ├── scoring.py                # Formula R, I, V, T
│   ├── time_decay.py             # Time decay logic & state management
│   ├── normalizer.py             # Normalisasi & capping nilai
│   └── scheduler.py             # APScheduler — jalankan scoring tiap N jam
│
├── database/                     # Database layer
│   ├── models.py                 # SQLAlchemy models
│   ├── migrations/               # Alembic migrations
│   │   └── versions/
│   └── queries.py               # Query helpers (get latest score, trend, dll)
│
├── api/                          # REST API (FastAPI)
│   ├── __init__.py
│   ├── main.py                   # FastAPI app entry point
│   ├── routes/
│   │   ├── assets.py            # GET /assets, POST /assets
│   │   ├── scores.py            # GET /scores/{asset_id}, GET /scores/latest
│   │   ├── trends.py            # GET /trends/{asset_id}?period=7d
│   │   └── simulate.py         # POST /simulate/spike, POST /simulate/remediation
│   └── schemas.py               # Pydantic schemas (request/response)
│
├── dashboard/                    # Frontend Dashboard
│
└── tests/
    ├── test_scoring.py           # Unit test formula R, I, V, T
    ├── test_time_decay.py        # Test time decay logic
    ├── test_ingestion.py         # Test fetcher (mock Wazuh API)
    └── test_api.py               # Integration test REST API
```

---

## 5. Tech Stack

| Layer           | Teknologi               | Keterangan                    |
| --------------- | ----------------------- | ----------------------------- |
| **Risk Engine** | Python 3.11+            | Core kalkulasi scoring        |
| **Scheduler**   | APScheduler             | Cron job polling Wazuh        |
| **API**         | FastAPI + Uvicorn       | REST API untuk dashboard      |
| **Database**    | PostgreSQL + SQLAlchemy | Penyimpanan time-series score |
| **Migrations**  | Alembic                 | Schema versioning             |
| **Dashboard**   |                         |                               |
| **Charts**      | Plotly / Altair         | Grafik interaktif             |
| **Container**   | Docker + Docker Compose | Environment consistency       |
| **Wazuh**       | Wazuh 4.x + OpenSearch  | Sumber telemetri utama        |
| **HTTP Client** | httpx (async)           | Koneksi ke Wazuh API          |
| **Testing**     | pytest + pytest-asyncio | Unit & integration tests      |
| **Env Config**  | python-dotenv           | Manajemen secrets             |

---

## 6. Setup & Instalasi

### Prasyarat

- Python 3.11+
- Docker & Docker Compose
- Akses ke Wazuh Lab (Manager API + Indexer)
- Git

### Langkah 1: Clone & masuk ke direktori proyek

```bash
git clone <repo-url>
cd capstone
```

### Langkah 2: Setup Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate          # Linux/Mac
# .venv\Scripts\activate            # Windows

pip install --upgrade pip
pip install -r requirements.txt
```

### Langkah 3: Konfigurasi Environment Variables

```bash
cp .env.example .env
# Edit .env dengan nilai yang sesuai (lihat bagian Konfigurasi)
nano .env
```

### Langkah 4: Jalankan via Docker Compose (Rekomendasi)

```bash
docker-compose up -d
# Service yang akan berjalan:
# - postgres:5432
# - risk-engine (scheduler)
# - api:8000
# - dashboard:8501
```

### Langkah 5: Jalankan Migrasi Database

```bash
# Pastikan PostgreSQL sudah running
alembic upgrade head
```

### Langkah 6: Verifikasi Instalasi

```bash
# Cek API
curl http://localhost:8000/health

# Buka dashboard
open http://localhost:8501
```

---

## 7. Konfigurasi

Salin `.env.example` ke `.env` dan isi nilai berikut:

```env
# === WAZUH CONNECTION ===
WAZUH_API_URL=https://20.194.14.146
WAZUH_INDEXER_URL=https://20.194.14.146:9200
WAZUH_API_USER=wazuh
WAZUH_API_PASSWORD=<your_password>
WAZUH_VERIFY_SSL=false          # Set true jika sertifikat valid

# === DATABASE ===
DATABASE_URL=postgresql://capstone:capstone@localhost:5432/risk_scoring

# === SCORING ENGINE ===
SCORING_INTERVAL_HOURS=1        # Seberapa sering scoring dihitung (default: 1 jam)
ALERT_LOOKBACK_HOURS=1          # Window waktu pengambilan alert Wazuh
DECAY_FACTOR=0.5                # Alpha untuk time decay (0.0–1.0)
WEIGHT_VULNERABILITY=0.3        # w1: bobot SCA/CIS
WEIGHT_THREAT=0.7               # w2: bobot alert aktif

# === API ===
API_HOST=0.0.0.0
API_PORT=8000
API_SECRET_KEY=<random-secret>  # Untuk JWT jika diperlukan

# === DASHBOARD ===
DASHBOARD_API_URL=http://localhost:8000
```

---

## 8. Menjalankan Sistem

### Mode Development (Tanpa Docker)

```bash
# Terminal 1: Jalankan PostgreSQL
docker-compose up postgres -d

# Terminal 2: Jalankan Risk Engine Scheduler
cd engine
python scheduler.py

# Terminal 3: Jalankan API
cd api
uvicorn main:app --reload --port 8000

# Terminal 4: Jalankan Dashboard
cd dashboard
streamlit run app.py --server.port 8501
```

### Menjalankan Test

```bash
pytest tests/ -v
pytest tests/test_scoring.py -v          # Hanya unit test formula
pytest tests/ --cov=engine --cov-report=html  # Dengan coverage report
```

---

## 9. API Reference

### Base URL: `http://localhost:8000`

| Method | Endpoint                | Deskripsi                                          |
| ------ | ----------------------- | -------------------------------------------------- |
| GET    | `/health`               | Health check                                       |
| GET    | `/assets`               | Daftar semua aset terdaftar                        |
| POST   | `/assets`               | Daftarkan aset baru + submit Likert score          |
| GET    | `/scores/latest`        | Skor risiko terkini semua aset (ranking)           |
| GET    | `/scores/{asset_id}`    | Skor terkini + breakdown (T, V, I) satu aset       |
| GET    | `/trends/{asset_id}`    | Time-series skor aset (query param: `?period=7d`)  |
| POST   | `/simulate/spike`       | Inject lonjakan alert simulasi ke engine           |
| POST   | `/simulate/remediation` | Reset T_prev ke 0 (simulasi perbaikan)             |
| GET    | `/scores/top`           | Top N aset risiko tertinggi (query param: `?n=10`) |

### Contoh Response GET `/scores/{asset_id}`

```json
{
  "asset_id": "agent-001",
  "hostname": "db-server-01",
  "timestamp": "2026-03-13T08:00:00Z",
  "risk_score": 72.5,
  "severity": "High",
  "breakdown": {
    "impact": 1.0,
    "vulnerability": 61.0,
    "threat": 78.0,
    "w1": 0.3,
    "w2": 0.7
  },
  "formula": "R = 1.0 × (0.3×61.0 + 0.7×78.0) = 72.9"
}
```

---

## 10. Sprint Plan & Roadmap

### Sprint 1–2 (Minggu 1–4): Foundation

**Goal**: Data contract terkunci, infrastruktur berjalan, aset terdaftar.

- [ ] Setup repo, Docker Compose, struktur folder
- [ ] Buat schema database (assets, risk_scores, alert_snapshots, sca_scores)
- [ ] Jalankan migrasi Alembic awal
- [ ] Buat `wazuh_client.py` — koneksi ke Wazuh API & Indexer (dengan SSL skip)
- [ ] Buat `asset_registry.py` — CMDB dummy 5–10 aset dengan Likert score
- [ ] Buat `alert_fetcher.py` — query alerts per agent per time window
- [ ] Buat `sca_fetcher.py` — query SCA score per agent
- [ ] Verifikasi data telemetry live dari Wazuh (Indexer + API)
- [ ] Tulis unit test dasar untuk fetcher (dengan mock)
- [ ] **DoD**: Docker `docker-compose up` berjalan, data dummy bisa masuk ke DB

---

### Sprint 3–4 (Minggu 5–8): Core Engine

**Goal**: Scoring engine berjalan end-to-end, time-series tersimpan di DB.

- [ ] Implementasi `scoring.py` — formula R, I, V, T
- [ ] Implementasi `time_decay.py` — state T_prev per aset, di DB
- [ ] Implementasi `normalizer.py` — capping, normalisasi output 0–100
- [ ] Implementasi `scheduler.py` — APScheduler polling tiap 1 jam
- [ ] Buat FastAPI app + semua routes (assets, scores, trends, simulate)
- [ ] Buat Pydantic schemas untuk validasi input/output API
- [ ] Tulis unit test lengkap: `test_scoring.py`, `test_time_decay.py`
- [ ] Tulis integration test: `test_api.py`
- [ ] **DoD**: `GET /scores/latest` mengembalikan skor real dengan breakdown T/V/I

---

### Sprint 5 (Minggu 9–10): Dashboard

**Goal**: Dashboard aktif, dapat dibaca manajemen.

- [ ] Setup Streamlit app + multi-page structure
- [ ] Halaman Executive View: global risk index, top 10 aset risiko
- [ ] Halaman Asset Detail: breakdown T/V/I per aset, formula transparan
- [ ] Halaman Risk Trend: line chart time-series per aset
- [ ] Halaman Simulation: tombol inject spike, lihat skor naik secara live
- [ ] Buat komponen gauge chart (pewarnaan sesuai severity CVSS)
- [ ] Pastikan bahasa di dashboard non-teknis / eksekutif-friendly
- [ ] **DoD**: Demo end-to-end: dari data masuk → skor → grafik terlihat di dashboard

---

### Sprint 6 (Minggu 11–12): Final Demo & Dokumentasi

**Goal**: PoC selesai, simulasi berjalan mulus, dokumentasi lengkap.

- [ ] Jalankan skenario simulasi lengkap (normal → spike → decay → remediation)
- [ ] Rekam/screenshot semua skenario untuk presentasi
- [ ] Tulis README final (dokumen ini)
- [ ] Buat diagram arsitektur sistem
- [ ] Buat slide presentasi (ringkasan eksekutif)
- [ ] Pastikan semua test hijau (`pytest tests/`)
- [ ] Final code review & cleanup
- [ ] **DoD**: Presentasi akhir kepada mitra industri

---

## 11. Penjelasan Komponen Detail

### 11.1 Wazuh Client (`ingestion/wazuh_client.py`)

Bertanggung jawab untuk semua komunikasi dengan Wazuh.

**Fungsi utama:**

- `authenticate()` → dapatkan JWT token dari Wazuh API
- `get_alerts(agent_id, from_time, to_time)` → query Wazuh Indexer (OpenSearch) untuk alert dalam rentang waktu
- `get_sca_summary(agent_id)` → dapatkan SCA pass/fail/not-applicable per agent
- `get_agents()` → daftar semua agent aktif

**Endpoint Wazuh yang digunakan:**

```
POST https://20.194.14.146/security/user/authenticate  → Token
GET  https://20.194.14.146/agents                       → Agent list
GET  https://20.194.14.146/sca/{agent_id}               → SCA summary
POST https://20.194.14.146:9200/wazuh-alerts-*/_search → Alert query
```

**Contoh Query OpenSearch untuk alert per agent:**

```json
{
  "query": {
    "bool": {
      "must": [
        { "term": { "agent.id": "001" } },
        { "range": { "timestamp": { "gte": "now-1h", "lte": "now" } } }
      ]
    }
  },
  "aggs": {
    "by_level": {
      "range": {
        "field": "rule.level",
        "ranges": [
          { "key": "low", "from": 0, "to": 5 },
          { "key": "medium", "from": 5, "to": 8 },
          { "key": "high", "from": 8, "to": 12 },
          { "key": "critical", "from": 12, "to": 16 }
        ]
      }
    }
  },
  "size": 0
}
```

---

### 11.2 Time Decay State Management

State `T_prev` per aset **harus disimpan di database** agar persist antar restart.

```sql
-- Tabel untuk menyimpan state T terakhir
CREATE TABLE threat_state (
    asset_id    VARCHAR(50) PRIMARY KEY,
    t_previous  FLOAT       NOT NULL DEFAULT 0.0,
    updated_at  TIMESTAMP   NOT NULL DEFAULT NOW()
);
```

Setiap kali scoring engine berjalan:

1. Baca `T_prev` dari tabel `threat_state`
2. Hitung `T_now` dengan formula decay
3. Update `T_prev = T_now` di tabel

---

### 11.3 Database Schema

```sql
-- Aset terdaftar (CMDB dummy)
CREATE TABLE assets (
    asset_id     VARCHAR(50) PRIMARY KEY,
    hostname     VARCHAR(100) NOT NULL,
    wazuh_agent_id VARCHAR(10),
    ip_address   INET,
    likert_score FLOAT NOT NULL,           -- Rata-rata 8 jawaban kuesioner
    impact       FLOAT GENERATED ALWAYS AS (likert_score / 5.0) STORED,
    description  TEXT,
    created_at   TIMESTAMP DEFAULT NOW()
);

-- Time-series skor risiko
CREATE TABLE risk_scores (
    id           SERIAL PRIMARY KEY,
    asset_id     VARCHAR(50) REFERENCES assets(asset_id),
    timestamp    TIMESTAMP NOT NULL,
    risk_score   FLOAT NOT NULL,
    severity     VARCHAR(10) NOT NULL,     -- Low/Medium/High/Critical
    impact       FLOAT NOT NULL,
    vulnerability FLOAT NOT NULL,
    threat       FLOAT NOT NULL,
    t_new        FLOAT NOT NULL,
    t_previous   FLOAT NOT NULL,
    sca_pass_pct FLOAT NOT NULL,
    alert_count_low      INT DEFAULT 0,
    alert_count_medium   INT DEFAULT 0,
    alert_count_high     INT DEFAULT 0,
    alert_count_critical INT DEFAULT 0
);

-- Index untuk query time-series yang cepat
CREATE INDEX idx_risk_scores_asset_time ON risk_scores(asset_id, timestamp DESC);
```

---

## 12. Simulasi & Testing

### Skenario Simulasi Wajib

#### Skenario 1: Normal Traffic

- Alert: mayoritas Level 3–4 (login sukses, aktivitas normal)
- Expected: R ≈ 10–25 (Low/Hijau)

#### Skenario 2: Brute Force Spike

- Alert Jam 1: 50× Level 10 (multiple failed login)
- Expected T_jam1: min(50×10 + 0, 100) = 100
- Expected R ≈ 70+ (High/Merah)

#### Skenario 3: Time Decay (Serangan Berhenti)

- Alert Jam 2: hanya beberapa Level 3
- T_baru_jam2 = 10
- T_sekarang = 10 + (100 × 0.5) = 60
- Expected R ≈ 40–50 (Medium/Kuning) — skor turun tapi belum aman total

#### Skenario 4: Full Remediation

- Admin klik "Remediation" → T_prev direset ke 0
- Alert kembali normal
- Expected R ≈ 10–20 (Low/Hijau) dalam 2–3 periode berikutnya

### Contoh Kalkulasi Lengkap

```
Server DB Nasabah:
- Likert Score = 5 → I = 1.0
- SCA Pass = 39% (56/143 checks) → V = 100 - 39 = 61
- Alert periode ini: 50× Level 10 (brute force), T_prev = 0
  T_new = 50 × 10 = 500 → di-cap → T = 100
- R = 1.0 × (0.3×61 + 0.7×100) = 1.0 × (18.3 + 70) = 88.3
- Severity: HIGH (mendekati Critical)
```

---

## 13. Koneksi ke Wazuh

### Konfigurasi Koneksi Lab

```
Wazuh API  : https://20.194.14.146          (port 443/55000)
Wazuh Indexer (OpenSearch): https://20.194.14.146:9200
```

> **Catatan Keamanan**: SSL self-signed cert → set `WAZUH_VERIFY_SSL=false` di `.env`  
> Jangan hardcode credentials. Selalu gunakan environment variables.

### Test Koneksi Manual

```bash
# Test authentikasi ke Wazuh API
curl -k -X POST "https://20.194.14.146/security/user/authenticate" \
     -H "Content-Type: application/json" \
     -d '{"user": "wazuh", "password": "<password>"}'

# Test query ke Indexer
curl -k -u admin:<password> \
     "https://20.194.14.146:9200/wazuh-alerts-4.x-*/_count"
```

---

## Referensi

- [Wazuh SCA Documentation](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/use-cases.html)
- [Wazuh Rules Classification](https://documentation.wazuh.com/current/user-manual/ruleset/rules-classification.html)
- [CVSS v3.1 Specification](https://www.first.org/cvss/specification-document)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [Wazuh API Reference](https://documentation.wazuh.com/current/user-manual/api/reference.html)
