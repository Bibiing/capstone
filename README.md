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
│  Table: assets | risk_scores | threat_state | sca_snapshots  │
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
│   ├── threat_hunting.py         # Snapshot Threat Hunting (events, histogram, top rule)
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

### Backend Stack

| Layer                  | Teknologi                    | Keterangan                            |
| ---------------------- | ---------------------------- | ------------------------------------- |
| **Web Framework**      | FastAPI 0.111.0              | Async REST API with automatic docs    |
| **Application Server** | Uvicorn 0.29.0               | ASGI server untuk FastAPI             |
| **Authentication**     | JWT + OTP (bcrypt + passlib) | Register, Login, Email verification   |
| **Risk Engine**        | Python 3.11+                 | Core kalkulasi scoring (R, I, V, T)   |
| **Scheduler**          | APScheduler 3.10.4           | Cron job polling Wazuh setiap periode |
| **Database**           | PostgreSQL + SQLAlchemy 2.x  | Time-series storage + Session mgmt    |
| **Migrations**         | Alembic 1.13.1               | Schema versioning (001 + 002 auth)    |
| **HTTP Client**        | httpx 0.27.0                 | Async koneksi ke Wazuh API            |
| **Data Validation**    | Pydantic 2.7.1               | Request/Response schema validation    |
| **Password Hashing**   | bcrypt 4.0.1 (12 rounds)     | Secure password storage               |
| **Token Management**   | python-jose 3.3.0            | JWT generation & validation           |

---

## 6. Setup & Instalasi

### Prasyarat

- Python 3.11+
- Docker & Docker Compose (recommended) atau PostgreSQL lokal
- Akses ke Wazuh Lab (Manager API + Indexer)
- Git

### Langkah 1: Clone & Setup Direktori

```bash
git clone <repo-url>
cd capstone
```

### Langkah 2: Setup Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate        # Linux/Mac
# .venv\Scripts\activate          # Windows

pip install --upgrade pip
pip install -r requirements.txt
```

### Langkah 3: Konfigurasi Environment Variables

```bash
cp .env.example .env
```

Edit `.env` dengan nilai berikut:

```env
# === WAZUH CONNECTION ===
WAZUH_API_URL=https://20.194.14.146:55000
WAZUH_INDEXER_URL=https://20.194.14.146:9200
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=<your_password>
WAZUH_VERIFY_SSL=false

# === DATABASE ===
DATABASE_URL=postgresql://capstone:capstone_dev@localhost:5432/risk_scoring

# === API & AUTH ===
API_HOST=0.0.0.0
API_PORT=8000
API_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
API_ENVIRONMENT=development

# === JWT CONFIGURATION ===
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=24

# === OTP CONFIGURATION ===
OTP_EXPIRATION_MINUTES=15
OTP_MAX_ATTEMPTS=5

# === SCORING ENGINE ===
SCORING_INTERVAL_HOURS=1
ALERT_LOOKBACK_HOURS=1
DECAY_FACTOR=0.5
WEIGHT_VULNERABILITY=0.3
WEIGHT_THREAT=0.7

# === DASHBOARD ===
DASHBOARD_API_URL=http://localhost:8000
```

### Langkah 4A: Jalankan via Docker Compose (RECOMMENDED)

```bash
# Start semua service (PostgreSQL + FastAPI + Risk Engine + Dashboard)
docker-compose up -d

# Verifikasi service berjalan
docker-compose ps

# Check logs
docker-compose logs -f api      # API logs
docker-compose logs -f postgres # Database logs
```

### Langkah 4B: Jalankan Lokal (Development)

```bash
# Terminal 1: Start PostgreSQL
docker-compose up postgres -d

# Terminal 2: Jalankan API (FastAPI)
uvicorn api.main:app --reload --port 8000

# Terminal 3: Jalankan Risk Engine (optional)
cd engine
python scheduler.py

# Terminal 4: Jalankan Dashboard (Sprint 5)
cd dashboard
streamlit run app.py --server.port 8501
```

### Langkah 5: Migrate Database

```bash
# Jalankan migrasi (001_initial_schema.py dan 002_add_auth_tables.py)
alembic upgrade head

# Verify database
psql postgresql://capstone:capstone_dev@localhost:5432/risk_scoring -c "\dt"
```

### Langkah 6: Verifikasi Instalasi

```bash
# ✅ Test health endpoint
curl http://localhost:8000/health

# ✅ Buka Swagger UI (API documentation)
open http://localhost:8000/docs

# ✅ Test registration
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "TestPass123!"
  }'

# ✅ Buka dashboard (Sprint 5)
open http://localhost:8501
```

---

## 7. Konfigurasi

### Security Best Practices

#### API Secret Key Generation

Untuk `API_SECRET_KEY`, generate random secret yang kuat:

```bash
# Linux/Mac
python -c "import secrets; print(secrets.token_hex(32))"

# Atau
openssl rand -hex 32
```

#### OTP Email Settings (Resend API)

Kami menggunakan **Resend** untuk mengirim OTP codes via email.

**Setup Resend**:

1. **Sign up** di [https://resend.com](https://resend.com)
2. **Get API Key** dari dashboard (format: `re_xxxxx`)
3. **Set di .env**:
   ```env
   RESEND_API_KEY=re_xxxxxxxxx    # Ganti dengan API key Anda
   OTP_FROM_EMAIL=noreply@resend.dev  # Atau custom domain
   OTP_EXPIRATION_MINUTES=15
   OTP_MAX_ATTEMPTS=5
   ```

**Detailed Setup Guide**: Lihat [docs/RESEND_SETUP.md](docs/RESEND_SETUP.md)

### OTP Email Flow (dengan Resend)

```
User Registration
    ↓
Generate 6-digit OTP code
    ↓
Call send_otp_email()
    ↓
Resend API: POST /emails
    ↓
Email delivered dalam 1-2 detik
    ↓
User dapat email dengan OTP code
    ↓
User verifikasi code
    ↓
Account aktif ✅
```

**Email Template Example**:

```
From: noreply@resend.dev
To: user@example.com
Subject: Email Verification - OTP Code

┌─────────────────────────────┐
│ Your OTP Code              │
│                             │
│     482619                  │
│                             │
│ This code expires in 15     │
│ minutes                     │
└─────────────────────────────┘

Do not share this code with anyone.
```

---

## 8. Menjalankan Sistem

### Mode Development

```bash
# Start semua service
docker-compose up -d

# Verifikasi service
docker-compose ps

# Check API
curl http://localhost:8000/health

# Buka Swagger UI untuk testing endpoints
open http://localhost:8000/docs
```

### Menjalankan Tanpa Docker (Local Development)

```bash
# Terminal 1: Start PostgreSQL container
docker-compose up postgres -d

# Terminal 2: Activate venv dan jalankan API
source .venv/bin/activate
uvicorn api.main:app --reload --port 8000

# Terminal 3: Jalankan Risk Engine Scheduler (optional)
source .venv/bin/activate
cd engine
python scheduler.py

# Terminal 4: Jalankan Dashboard (Sprint 5)
source .venv/bin/activate
cd dashboard
streamlit run app.py --server.port 8501
```

### Menjalankan Test Suite

```bash
# ✅ Activate venv
source .venv/bin/activate

# ✅ Run all tests
pytest tests/ -v

# ✅ Run API tests only (43/46 passing, 93.5%)
pytest tests/test_api.py -v

# ✅ Run specific test class
pytest tests/test_api.py::TestJWTToken -v

# ✅ Run with coverage report
pytest tests/ --cov=api --cov-report=html

# ✅ Run unit tests (formula, ingestion, etc)
pytest tests/test_scoring.py -v

# ✅ Run quick tests only
pytest tests/ -q
```

### Current Test Status

```
Test Suite Summary (March 2026):
✅ Total: 46 test cases
✅ Passing: 43 tests (93.5%)
⚠️  Expected Failures: 3 tests (awaiting DB integration)

Category Breakdown:
  ✅ Password Hashing (4/4) — bcrypt security
  ✅ JWT Tokens (4/4) — token generation & validation
  ✅ OTP Management (5/5) — email verification
  ⚠️  Authentication API (6/6, 3 expected fails) — mock returns
  ✅ Asset CRUD (8/8) — in-memory store
  ✅ Score Queries (6/6) — mock time-series
  ✅ Simulation (6/6) — spike & remediation
  ✅ Health & Metadata (2/2) — API info
  ✅ Error Handling (5/5) — validation, 404s
```

Note: 3 auth endpoint tests fail dengan expected mock responses (401/404) sampai database integration selesai di Sprint 4.

---

## 9. API Reference

### Base URL: `http://localhost:8000`

**Documentation**: Swagger UI tersedia di `http://localhost:8000/docs` dan ReDoc di `http://localhost:8000/redoc`

### Health & Info Endpoints

| Method | Endpoint  | Deskripsi                       | Auth  |
| ------ | --------- | ------------------------------- | ----- |
| GET    | `/health` | Health check + system status    | ✅ No |
| GET    | `/`       | API info & available endpoints  | ✅ No |
| GET    | `/docs`   | Interactive Swagger UI          | ✅ No |
| GET    | `/redoc`  | Alternative ReDoc documentation | ✅ No |

### Authentication Endpoints

| Method | Endpoint           | Deskripsi                                 | Auth  |
| ------ | ------------------ | ----------------------------------------- | ----- |
| POST   | `/auth/register`   | Register akun baru + kirim OTP ke email   | ✅ No |
| POST   | `/auth/login`      | Login dengan email/password, dapatkan JWT | ✅ No |
| POST   | `/auth/verify-otp` | Verifikasi email via OTP code             | ✅ No |
| POST   | `/auth/resend-otp` | Resend OTP jika expired                   | ✅ No |

### Asset Management Endpoints

| Method | Endpoint             | Deskripsi                     | Auth        |
| ------ | -------------------- | ----------------------------- | ----------- |
| GET    | `/assets`            | Daftar semua aset (paginated) | Sprint 4 📋 |
| POST   | `/assets`            | Registrasi aset baru          | Sprint 4 📋 |
| GET    | `/assets/{asset_id}` | Detail satu aset              | Sprint 4 📋 |
| PUT    | `/assets/{asset_id}` | Update aset                   | Sprint 4 📋 |
| DELETE | `/assets/{asset_id}` | Hapus aset                    | Sprint 4 📋 |

### Risk Scoring Endpoints

| Method | Endpoint             | Deskripsi                               | Auth        |
| ------ | -------------------- | --------------------------------------- | ----------- |
| GET    | `/scores/latest`     | Skor risiko terkini semua aset          | Sprint 4 📋 |
| GET    | `/scores/{asset_id}` | Skor + breakdown (I, V, T) per aset     | Sprint 4 📋 |
| GET    | `/trends/{asset_id}` | Time-series skor (period=1d/7d/30d/90d) | Sprint 4 📋 |

### Simulation Endpoints

| Method | Endpoint                | Deskripsi                    | Auth        |
| ------ | ----------------------- | ---------------------------- | ----------- |
| POST   | `/simulate/spike`       | Inject threat spike scenario | Sprint 4 📋 |
| POST   | `/simulate/remediation` | Simulasi remediation (T→0)   | Sprint 4 📋 |

### API Examples

#### 1. Register New User

**Request**:

```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "manager_john",
    "email": "john@bank.local",
    "password": "SecurePass123!",
    "role": "Manajemen"
  }'
```

**Response** (201 Created):

```json
{
  "user_id": 1,
  "username": "manager_john",
  "email": "john@bank.local",
  "role": "Manajemen",
  "message": "Registration successful. Please verify your email using the OTP sent.",
  "verification_required": true
}
```

#### 2. Login & Get JWT Token

**Request**:

```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@bank.local",
    "password": "SecurePass123!"
  }'
```

**Response** (200 OK):

```json
{
  "user_id": 1,
  "username": "manager_john",
  "email": "john@bank.local",
  "role": "Manajemen",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 86400
}
```

#### 3. Get Latest Risk Scores

**Request**:

```bash
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
curl -X GET http://localhost:8000/scores/latest \
  -H "Authorization: Bearer $TOKEN"
```

**Response** (200 OK):

```json
{
  "timestamp": "2026-03-25T10:00:00Z",
  "asset_count": 3,
  "average_risk": 54.3,
  "highest_risk": 88.5,
  "severity_distribution": {
    "low": 0,
    "medium": 1,
    "high": 1,
    "critical": 1
  },
  "assets": [
    {
      "asset_id": "asset-001",
      "hostname": "db-prod-01",
      "risk_score": 88.5,
      "severity": "High",
      "timestamp": "2026-03-25T10:00:00Z"
    }
  ]
}
```

#### 4. Get Detailed Score with Breakdown

**Request**:

```bash
curl -X GET http://localhost:8000/scores/asset-001 \
  -H "Authorization: Bearer $TOKEN"
```

**Response** (200 OK):

```json
{
  "asset_id": "asset-001",
  "hostname": "db-prod-01",
  "timestamp": "2026-03-25T10:00:00Z",
  "risk_score": 88.5,
  "severity": "High",
  "breakdown": {
    "impact": 1.0,
    "vulnerability": 61.0,
    "threat": 78.0,
    "w1": 0.3,
    "w2": 0.7,
    "formula": "R = 1.0 × (0.3 × 61.0 + 0.7 × 78.0) = 88.5"
  }
}
```

#### 5. Simulate Threat Spike

**Request**:

```bash
curl -X POST http://localhost:8000/simulate/spike \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_ids": ["asset-001"],
    "threat_value": 95.0,
    "reason": "Simulated brute force attack detected"
  }'
```

**Response** (200 OK):

```json
{
  "message": "Threat spike simulated successfully",
  "affected_assets": 1,
  "new_scores": [
    {
      "asset_id": "asset-001",
      "risk_score": 95.8,
      "severity": "Critical"
    }
  ]
}
```

---

## 10. Sprint Plan & Roadmap

### ✅ Sprint 1–2: Foundation

**Goal**: Data contract terkunci, infrastruktur berjalan, aset terdaftar.

- ✅ Setup repo, Docker Compose, struktur folder
- ✅ Database schema (assets, risk_scores, threat_state, sca_snapshots)
- ✅ Alembic migrations (001 + 002 auth tables)
- ✅ Wazuh client (`wazuh_client.py`) — API & Indexer integration
- ✅ Asset registry & management
- ✅ Alert & SCA fetcher
- ✅ Unit tests dengan mock Wazuh
- ✅ **DoD**: Docker compose berjalan, live telemetry dari Wazuh tervalidasi

---

### ✅ Sprint 3–4 (IN PROGRESS): REST API & Authentication

**Goal**: FastAPI backend berjalan, authentication system live, 20 endpoints functional.

#### Completed ✅

- ✅ FastAPI app structure dengan middleware & error handling
- ✅ Complete authentication system:
  - User registration dengan password strength validation
  - Email-based OTP verification (mock email sending)
  - JWT token generation & validation (24-hour expiry)
  - Password hashing dengan bcrypt (12 rounds)
- ✅ 14 Pydantic schemas untuk request/response validation
- ✅ 20 REST endpoints:
  - 4 Authentication endpoints (register, login, verify-otp, resend-otp)
  - 5 Asset CRUD endpoints (list, create, read, update, delete)
  - 3 Risk Scoring endpoints (latest, single asset, trends)
  - 2 Simulation endpoints (spike, remediation)
  - 6 Infrastructure endpoints (health, docs, redoc, etc)
- ✅ 46 comprehensive test cases (43 passing, 3 expected failures = 93.5%)
- ✅ Docker Compose integration dengan FastAPI service
- ✅ Interactive API documentation (Swagger UI + ReDoc)

#### In Progress 🔄

- 🔄 Database integration (Sprint 4 Phase 2):
  - [ ] Async SQLAlchemy session factory
  - [ ] Wire `/assets` → PostgreSQL queries
  - [ ] Wire `/scores` → risk_scores table
  - [ ] Integrate auth endpoints dengan User/OTPCode DB
  - [ ] JWT middleware untuk protected routes
  - [ ] 3 failing tests akan pass setelah DB integration

---

### 📋 Sprint 5 (Upcoming): Dashboard & Authorization

**Goal**: Interactive dashboard live, role-based access control, real-time updates.

#### Planned Tasks

- [ ] Streamlit dashboard multi-page structure
- [ ] Executive summary: risk index, top aset, trends
- [ ] Asset detail pages: breakdown T/V/I, formula transparency
- [ ] Risk trend visualization: time-series charts
- [ ] Simulation interface: live spike/remediation testing
- [ ] Role-based access control (CISO, Manajemen)
- [ ] Email service integration (SendGrid/AWS SES)
- [ ] Rate limiting on auth endpoints
- [ ] **DoD**: Dashboard fully functional, RBAC enforced, 100% test passing

---

### 📋 Sprint 6 (Final): Production Readiness

**Goal**: PoC selesai, simulasi berjalan, dokumentasi lengkap, siap deployment.

#### Planned Tasks

- [ ] End-to-end Test: normal → spike → decay → remediation
- [ ] Performance optimization & load testing
- [ ] Security audit & hardening
- [ ] Production deployment configurations
- [ ] Logging & monitoring setup
- [ ] Final documentation & runbook
- [ ] Presentation slides & demo recording
- [ ] **DoD**: Go-live ready, final demo to stakeholders

---

## 9A. FastAPI Backend Implementation Details

### Overview

FastAPI backend PoC selesai dengan implementasi lengkap:

```
✅ 20 REST endpoints (4 auth + 5 assets + 3 scores + 2 simulation + 6 infrastructure)
✅ Authentication system (JWT + OTP email verification)
✅ Password security (bcrypt 12-round hashing)
✅ 46 test cases (43 passing, 93.5%)
✅ Docker-ready dengan docker-compose.yml
✅ Interactive API docs (Swagger UI at /docs)
```

### Key Components

#### API Application (`api/main.py`)

- FastAPI app dengan CORS middleware
- Global exception handlers (HTTPException, ValidationError, generic errors)
- Request ID tracking untuk distributed tracing
- Process time middleware untuk performance monitoring
- Health check dan root info endpoints

#### Security Module (`api/security.py`)

```python
# Password management
hash_password(password: str) -> str          # bcrypt hashing
verify_password(plain: str, hash: str) -> bool  # constant-time comparison

# JWT token management
create_access_token(...) -> Tuple[str, int]  # (token, expires_in_seconds)
verify_token(token: str) -> Optional[TokenPayload]

# OTP management
generate_otp(length: int = 6) -> str        # cryptographically secure
is_otp_expired(expires_at: datetime) -> bool
```

#### Request/Response Schemas (`api/schemas.py`)

```python
# Authentication schemas
RegisterRequest, LoginResponse, VerifyOTPRequest, etc

# Asset schemas
AssetCreate, AssetResponse, AssetListResponse

# Score schemas
RiskScoreResponse, LatestScoresResponse, TrendResponse

# Simulation schemas
SimulateSpikeRequest, SimulateRemediationRequest
```

#### Route Modules

**`api/routes/auth.py`** (4 endpoints)

- POST /auth/register — User registration with validation
- POST /auth/login — Email/password authentication
- POST /auth/verify-otp — OTP verification untuk email confirmation
- POST /auth/resend-otp — Resend OTP if expired

**`api/routes/assets.py`** (5 endpoints)

- GET /assets — List dengan pagination
- POST /assets — Create asset baru
- GET /assets/{asset_id} — Detail satu asset
- PUT /assets/{asset_id} — Update asset
- DELETE /assets/{asset_id} — Delete asset

**`api/routes/scores.py`** (3 endpoints)

- GET /scores/latest — Latest scores all assets + summary
- GET /scores/{asset_id} — Latest score one asset with breakdown
- GET /trends/{asset_id} — Historical trends (period filter)

**`api/routes/simulate.py`** (2 endpoints)

- POST /simulate/spike — Inject threat scenario
- POST /simulate/remediation — Reset threat (T→0)

### Authentication Flow

#### Registration

```
1. User submit username, email, password
2. Validate input (email format, password strength)
3. Check uniqueness (username, email)
4. Hash password dengan bcrypt (12 rounds)
5. Create User record dengan is_active=false, is_verified=false
6. Generate 6-digit OTP code
7. (TODO) Send OTP via email (SendGrid/SMTP)
8. Return user_id + confirmation
```

#### Login & Token

```
1. User submit email + password
2. Find user by email
3. Verify password (bcrypt constant-time)
4. Check is_active && is_verified
5. Generate JWT token (HS256, 24-hour expiry)
6. Return token + user info
```

#### OTP Verification

```
1. User submit email + OTP code
2. Find latest OTP for user
3. Check: not expired, not used, attempts < max
4. Compare code
5. Mark OTP as used
6. Set user.is_verified=true, is_active=true
7. Return success
```

### Database Schema Extensions (Sprint 3)

#### users table (New)

```sql
CREATE TABLE users (
  user_id        SERIAL PRIMARY KEY,
  username       VARCHAR(50) NOT NULL UNIQUE,
  email          VARCHAR(100) NOT NULL UNIQUE,
  password_hash  VARCHAR(255) NOT NULL,
  role           VARCHAR(20) DEFAULT 'Manajemen',  -- CISO|Manajemen
  is_active      BOOLEAN DEFAULT false,
  is_verified    BOOLEAN DEFAULT false,
  created_at     TIMESTAMPTZ DEFAULT NOW(),
  updated_at     TIMESTAMPTZ DEFAULT NOW()
);
```

#### otp_codes table (New)

```sql
CREATE TABLE otp_codes (
  otp_id         SERIAL PRIMARY KEY,
  user_id        INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
  code           VARCHAR(10) NOT NULL,
  expires_at     TIMESTAMPTZ NOT NULL,
  is_used        BOOLEAN DEFAULT false,
  attempts       INTEGER DEFAULT 0,
  created_at     TIMESTAMPTZ DEFAULT NOW()
);
```

### Test Coverage (Sprint 3)

```
TestPasswordHashing (4 tests) ✅
  ✅ test_hash_password
  ✅ test_verify_password_correct
  ✅ test_verify_password_incorrect
  ✅ test_password_strength_validation

TestJWTToken (4 tests) ✅
  ✅ test_create_access_token
  ✅ test_verify_token_valid
  ✅ test_verify_token_expired
  ✅ test_verify_token_invalid

TestOTP (5 tests) ✅
  ✅ test_generate_otp
  ✅ test_otp_randomness
  ✅ test_otp_expiration
  ✅ test_otp_attempt_counting
  ✅ test_otp_used_marking

TestAuthAPI (6 tests) — 3 Passing ✅, 3 Expected Failures ⚠️
  ✅ test_register_success
  ⚠️  test_login_success (mock returns 401)
  ⚠️  test_verify_otp_success (mock returns 404)
  ✅ test_verify_otp_invalid_code
  ✅ test_resend_otp_invalid_user
  ⚠️  test_resend_otp_success (mock returns 404)

TestAssetsAPI (8 tests) ✅
  ✅ test_list_assets
  ✅ test_create_asset
  ✅ test_get_single_asset
  ✅ test_update_asset
  ✅ test_delete_asset
  ✅ test_asset_pagination
  ✅ test_asset_not_found
  ✅ test_duplicate_hostname

TestScoresAPI (6 tests) ✅
  ✅ test_get_latest_scores
  ✅ test_get_single_asset_score
  ✅ test_get_asset_trend
  ✅ test_trend_period_filtering
  ✅ test_trend_invalid_period
  ✅ test_trend_asset_not_found

TestSimulationAPI (6 tests) ✅
  ✅ test_simulate_spike
  ✅ test_simulate_spike_multiple_assets
  ✅ test_simulate_remediation
  ✅ test_simulation_invalid_assets
  ✅ test_simulate_partial_failure
  ✅ test_spike_with_severity_change

TestHealthAndMetadata (2 tests) ✅
  ✅ test_health_check
  ✅ test_root_endpoint

TestErrorHandling (5 tests) ✅
  ✅ test_validation_error_response
  ✅ test_404_not_found
  ✅ test_request_id_tracking
  ✅ test_process_time_header
  ✅ test_unhandled_exception
```

### Next Steps (Sprint 4 Phase 2)

#### ✅ COMPLETED: Email OTP Integration (Resend API)

- ✅ Added `resend` library to requirements.txt
- ✅ Created `api/email.py` service for OTP delivery
- ✅ Integrated OTP email sending in register endpoint
- ✅ Integrated OTP resend email in resend-otp endpoint
- ✅ Beautiful HTML email templates with branding
- ✅ Error handling and logging for email failures
- ✅ Configuration via environment variables (RESEND_API_KEY, OTP_FROM_EMAIL)
- ✅ Documentation: [docs/RESEND_SETUP.md](docs/RESEND_SETUP.md)

**How to Setup**:

```bash
# 1. Sign up at https://resend.com
# 2. Get API key (format: re_xxxxx)
# 3. Update .env
RESEND_API_KEY=re_xxxxxxxxx
OTP_FROM_EMAIL=noreply@resend.dev

# 4. Test registration (OTP will be emailed)
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "your-email@example.com",
    "password": "TestPass123!"
  }'
```

#### TODO: Async SQLAlchemy Integration

1. **Async SQLAlchemy Integration**

   ```python
   from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession

   async def get_db_session() -> AsyncSession:
       async with async_session_maker() as session:
           yield session
   ```

2. **Database Query Integration**
   - Replace in-memory stores dengan SQLAlchemy queries
   - Implement async/await patterns
   - Add transaction management

3. **JWT Middleware**
   - Extract token dari Authorization header
   - Validate token + extract user context
   - Enforce authorization per endpoint

4. **Email Service Integration**
   - SendGrid atau AWS SES untuk OTP
   - Email templates
   - Retry logic

### Documentation

Detailed implementation guide tersedia di: `docs/FastAPI-Backend-Implementation.md`

---

## 11. Penjelasan Komponen Detail

### 11.1 Wazuh Client (`ingestion/wazuh_client.py`)

Bertanggung jawab untuk semua komunikasi dengan Wazuh.

**Fungsi utama:**

- `authenticate()` → dapatkan JWT token dari Wazuh API
- `get_alerts(agent_id, from_time, to_time)` → query Wazuh Indexer (OpenSearch) untuk alert dalam rentang waktu
- `get_sca_summary(agent_id)` → dapatkan SCA pass/fail/not-applicable per agent
- `get_agents()` → daftar semua agent aktif
- `get_threat_hunting_snapshot(...)` → ambil snapshot setara layar Threat Hunting (events, histogram, top rules)

**Endpoint Wazuh yang digunakan:**

```
POST https://20.194.14.146:55000/security/user/authenticate?raw=true  → Token
GET  https://20.194.14.146:55000/agents                                  → Agent list
GET  https://20.194.14.146:55000/sca/{agent_id}                          → SCA summary
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

### 11.2 Threat Hunting Integration (`ingestion/threat_hunting.py`)

Backend sudah menyediakan service khusus Threat Hunting yang selaras dengan tampilan Wazuh UI.

Output utama per snapshot:

- Event stream terbaru per agent
- Histogram event per interval (default `30m`)
- Distribusi `rule.level` (exact + group low/medium/high/critical)
- Top rule (`rule.id`) berdasarkan frekuensi

Contoh command demo:

```bash
python -m ingestion.threat_hunting
```

Contoh penggunaan di Python:

```python
from ingestion.wazuh_client import WazuhClient
from ingestion.threat_hunting import ThreatHuntingFetcher

with WazuhClient.from_settings() as client:
  fetcher = ThreatHuntingFetcher(client=client)
  snapshot = fetcher.fetch(agent_id="001", manager_name="manager")
  print(snapshot.total_hits)
  print(snapshot.by_level_group)
```

---

### 11.3 Time Decay State Management

State `T_prev` per aset **harus disimpan di database** agar persist antar restart.

```sql
-- Tabel untuk menyimpan state T terakhir
CREATE TABLE threat_state (
  asset_id    VARCHAR(50) PRIMARY KEY,
  t_previous  FLOAT       NOT NULL DEFAULT 0.0,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

Setiap kali scoring engine berjalan:

1. Baca `T_prev` dari tabel `threat_state`
2. Hitung `T_now` dengan formula decay
3. Update `T_prev = T_now` di tabel

---

### 11.4 Database Schema

Schema final saat ini mengikuti migrasi Alembic `001_initial_schema`.

Relasi utama:

- `assets` (master aset) 1:N `risk_scores`
- `assets` 1:1 `threat_state`
- `assets` 1:N `sca_snapshots`

```sql
-- ============================================================================
-- TABLE: assets
-- ============================================================================
CREATE TABLE assets (
  asset_id         VARCHAR(50) PRIMARY KEY,
  hostname         VARCHAR(100) NOT NULL,
  wazuh_agent_id   VARCHAR(10) UNIQUE,
  ip_address       VARCHAR(45),
  likert_score     FLOAT NOT NULL,
  description      TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT ck_assets_likert_range
    CHECK (likert_score >= 1.0 AND likert_score <= 5.0)
);

-- ============================================================================
-- TABLE: risk_scores (append-only time-series)
-- ============================================================================
CREATE TABLE risk_scores (
  id                 SERIAL PRIMARY KEY,
  asset_id           VARCHAR(50) NOT NULL
               REFERENCES assets(asset_id) ON DELETE CASCADE,
  timestamp          TIMESTAMPTZ NOT NULL,
  risk_score         FLOAT NOT NULL,
  severity           VARCHAR(10) NOT NULL,
  impact             FLOAT NOT NULL,
  vulnerability      FLOAT NOT NULL,
  threat             FLOAT NOT NULL,
  t_new              FLOAT NOT NULL,
  t_previous         FLOAT NOT NULL,
  sca_pass_pct       FLOAT NOT NULL,
  alert_count_low      INTEGER NOT NULL DEFAULT 0,
  alert_count_medium   INTEGER NOT NULL DEFAULT 0,
  alert_count_high     INTEGER NOT NULL DEFAULT 0,
  alert_count_critical INTEGER NOT NULL DEFAULT 0,
  CONSTRAINT ck_risk_score_range
    CHECK (risk_score >= 0.0 AND risk_score <= 100.0),
  CONSTRAINT ck_risk_severity_values
    CHECK (severity IN ('Low', 'Medium', 'High', 'Critical'))
);

CREATE INDEX idx_risk_scores_asset_time
  ON risk_scores(asset_id, timestamp);

-- ============================================================================
-- TABLE: threat_state (persist T_prev per asset)
-- ============================================================================
CREATE TABLE threat_state (
  asset_id      VARCHAR(50) PRIMARY KEY
          REFERENCES assets(asset_id) ON DELETE CASCADE,
  t_previous    FLOAT NOT NULL DEFAULT 0.0,
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- TABLE: sca_snapshots (historical SCA posture)
-- ============================================================================
CREATE TABLE sca_snapshots (
  id              SERIAL PRIMARY KEY,
  asset_id        VARCHAR(50) NOT NULL
            REFERENCES assets(asset_id) ON DELETE CASCADE,
  policy_id       VARCHAR(100) NOT NULL,
  policy_name     VARCHAR(200) NOT NULL,
  pass_count      INTEGER NOT NULL,
  fail_count      INTEGER NOT NULL,
  not_applicable  INTEGER NOT NULL DEFAULT 0,
  total_checks    INTEGER NOT NULL,
  pass_percentage FLOAT NOT NULL,
  scanned_at      TIMESTAMPTZ NOT NULL,
  CONSTRAINT ck_sca_pass_range
    CHECK (pass_percentage >= 0.0 AND pass_percentage <= 100.0)
);

CREATE INDEX idx_sca_asset_time
  ON sca_snapshots(asset_id, scanned_at);
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
Wazuh API (Manager)  : https://20.194.14.146:55000
Wazuh Indexer (OpenSearch): https://20.194.14.146:9200
```

> **Catatan Keamanan**: SSL self-signed cert → set `WAZUH_VERIFY_SSL=false` di `.env`  
> Jangan hardcode credentials. Selalu gunakan environment variables.

### Test Koneksi Manual

```bash
# Test autentikasi ke Wazuh Manager API (raw token)
curl -k -u wazuh-wui:<password> -X POST \
  "https://20.194.14.146:55000/security/user/authenticate?raw=true"

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
