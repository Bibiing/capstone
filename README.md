# Cyber Risk Scoring Engine — Proof of Concept

## Daftar Isi

1. [Gambaran Umum](#1-gambaran-umum)
2. [Arsitektur Sistem](#2-arsitektur-sistem)
3. [Struktur Direktori](#3-struktur-direktori)
4. [Prasyarat](#4-prasyarat)
5. [Konfigurasi Awal](#5-konfigurasi-awal)
6. [Cara Menjalankan](#6-cara-menjalankan)
7. [Data Contract (Skema Event)](#7-data-contract-skema-event)
8. [Katalog Skenario Data Dummy](#8-katalog-skenario-data-dummy)
9. [Referensi Modul Python](#9-referensi-modul-python)
10. [Skema Database](#10-skema-database)
11. [Menjalankan Unit Test](#11-menjalankan-unit-test)
12. [Panduan Kontribusi Kode](#12-panduan-kontribusi-kode)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. Gambaran Umum

Proyek ini adalah simulasi **Dynamic Cyber Risk Scoring Engine** berbasis telemetri Wazuh untuk lingkungan perbankan. Tujuannya adalah membangun Proof of Concept (PoC) yang dapat mendemonstrasikan kepada manajemen bahwa:

- Risk score sebuah aset dapat dihitung secara dinamis berdasarkan telemetri keamanan nyata.
- Sistem dapat mendeteksi lonjakan insiden (_spike_), klaster kerentanan (_vuln cluster_), dan penurunan risiko pasca-remediasi (_decay_).
- Seluruh pipeline — dari generasi data dummy hingga penyimpanan ke database — dapat dijalankan dan divalidasi secara otomatis.

**Batasan PoC:** Semua data adalah simulasi. Tidak ada koneksi ke sistem Wazuh produksi maupun data nasabah nyata.

---

## 2. Arsitektur Sistem

```
┌──────────────────────────────────────────────────────────────────┐
│                          Developer Machine                        │
│                                                                    │
│  ┌─────────────────────┐        ┌──────────────────────────────┐  │
│  │   dummy_generator/  │        │        ingestor/              │  │
│  │                     │        │                              │  │
│  │  generate_all.py    │──JSON──▶  main.py                    │  │
│  │  (4 worker proses)  │  files │  (validasi + bulk insert)   │  │
│  │                     │        │                              │  │
│  │  scenarios/         │        │  db.py                      │  │
│  │  ├── normal.py      │        │  (DAL + Data Contract)      │  │
│  │  ├── spike.py       │        └──────────────┬───────────────┘  │
│  │  ├── vuln.py        │                       │                  │
│  │  └── decay.py       │                       │ psycopg2         │
│  └─────────────────────┘                       │ execute_values   │
│                                                 ▼                  │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │              Docker Compose                                  │  │
│  │                                                              │  │
│  │  ┌──────────────────────────┐  ┌──────────────────────────┐ │  │
│  │  │  postgres:17-alpine      │  │  pgAdmin 4               │ │  │
│  │  │  container: risk_scoring_db│  │  http://localhost:5050   │ │  │
│  │  │  port: 5432              │  │  port: 5050              │ │  │
│  │  │                          │  │                          │ │  │
│  │  │  • assets                │  │  admin@risk.com          │ │  │
│  │  │  • wazuh_events          │  │  password: admin123      │ │  │
│  │  │  • risk_scores           │  │                          │ │  │
│  │  └──────────────────────────┘  └──────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

**Alur data:**

```
generate_all.py
    │  (spawn workers paralel)
    ├── NormalScenario   ──▶  output/events_normal.json
    ├── SpikeScenario    ──▶  output/events_spike.json
    ├── VulnClusterScen  ──▶  output/events_vuln_cluster.json
    └── DecayScenario    ──▶  output/events_remediation_decay.json
                                          │
                                    seed.sh / main.py
                                          │
                                 validate (Data Contract)
                                          │
                              bulk insert → PostgreSQL
```

---

## 3. Struktur Direktori

```
Capstone/
├── docker-compose.yml          # Infrastruktur: PostgreSQL + pgAdmin
├── .env.example                # Template variabel environment
├── README.md                   # Dokumentasi ini
│
├── db/
│   └── init.sql                # DDL: CREATE TABLE assets, wazuh_events, risk_scores
│
├── dummy_generator/            # Modul generasi data simulasi
│   ├── assets.json             # Katalog 15 aset bank (CMDB dummy)
│   ├── constants.py            # Rule catalog Wazuh + Data Contract constants
│   ├── base_generator.py       # Abstract base class semua generator
│   ├── generate_all.py         # Entry point (parallel ProcessPoolExecutor)
│   ├── scenarios/
│   │   ├── normal.py           # Skenario 1: Aktivitas harian normal
│   │   ├── spike.py            # Skenario 2: Lonjakan insiden mendadak
│   │   ├── vuln.py             # Skenario 3: Klaster CVE pada beberapa aset
│   │   └── decay.py            # Skenario 4: Penurunan risiko pasca-remediasi
│   ├── output/                 # File JSON hasil generate (di-gitignore produksi)
│   │   ├── events_normal.json
│   │   ├── events_spike.json
│   │   ├── events_vuln_cluster.json
│   │   └── events_remediation_decay.json
│   └── tests/
│       └── test_base_generator.py  # 61 unit test (pytest)
│
├── ingestor/
│   ├── db.py                   # Data Access Layer: validasi + bulk insert
│   ├── main.py                 # Service ingesti: baca JSON → insert PostgreSQL
│   ├── requirements.txt        # Dependensi Python
│   └── Dockerfile              # Container image ingestor
│
└── script/
    └── seed.sh                 # Otomatisasi end-to-end: generate → validate → insert
```

---

## 4. Prasyarat

| Kebutuhan       | Versi Minimum | Keterangan                      |
| --------------- | ------------- | ------------------------------- |
| Python          | 3.10+         | Direkomendasikan 3.12           |
| Docker          | 20.10+        | Untuk menjalankan PostgreSQL    |
| Docker Compose  | 2.x           | Tersedia bersama Docker Desktop |
| psycopg2-binary | 2.9+          | Tersedia via `requirements.txt` |

Pastikan Docker daemon berjalan sebelum melanjutkan.

---

## 5. Konfigurasi Awal

### 5.1 Salin dan isi file `.env`

```bash
cp .env.example .env
```

Isi default sudah cukup untuk environment lokal:

```ini
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=risk_scoring
POSTGRES_USER=admin
POSTGRES_PASSWORD=admin
```

> **Keamanan:** Jangan pernah commit file `.env` ke repositori. File ini sudah terdaftar di `.gitignore`.

### 5.2 Buat virtual environment Python

```bash
python3 -m venv .venv
source .venv/bin/activate          # Linux / macOS
# .venv\Scripts\activate           # Windows
pip install -r ingestor/requirements.txt
pip install pytest                 # Untuk menjalankan unit test
```

### 5.3 Jalankan infrastruktur database

```bash
docker compose up -d
```

Container `risk_scoring_db` akan otomatis menjalankan `db/init.sql` saat pertama kali dinyalakan, membuat semua tabel yang dibutuhkan.

---

## 6. Cara Menjalankan

### Cara Cepat — Satu Perintah (Direkomendasikan)

```bash
bash script/seed.sh
```

Skrip ini menangani seluruh pipeline:

1. Verifikasi prasyarat (Docker, `.env`, Python)
2. Menunggu PostgreSQL healthy
3. Generate semua data dummy (4 skenario)
4. Validasi Data Contract pada setiap file JSON
5. Bulk insert ke PostgreSQL
6. Laporan akhir di terminal

**Opsi tambahan `seed.sh`:**

```bash
bash script/seed.sh --skip-generate   # Gunakan file JSON yang sudah ada
bash script/seed.sh --dry-run         # Generate + validasi, tapi jangan insert ke DB
```

---

### Menjalankan Generator Secara Manual

```bash
cd dummy_generator

# Generate semua skenario secara paralel (default)
python3 generate_all.py

# Generate satu skenario tertentu
python3 generate_all.py --scenario spike

# Kontrol jumlah worker proses
python3 generate_all.py --workers 2

# Hanya tampilkan statistik tanpa menyimpan file
python3 generate_all.py --dry-run

# Generate + langsung insert ke DB
python3 generate_all.py --seed-db
```

### Menjalankan Ingestor Secara Manual

```bash
cd ingestor

# Insert semua file dari folder output default
python3 main.py

# Tentukan folder input secara eksplisit
python3 main.py --input-dir ../dummy_generator/output

# Jalankan query validasi setelah insert
python3 main.py --validate
```

---

## 7. Data Contract (Skema Event)

Setiap objek JSON yang masuk ke sistem **wajib** memenuhi kontrak berikut. Pelanggaran akan ditolak oleh `ingestor/db.py` sebelum menyentuh database.

| Field        | Tipe      | Nilai yang Diizinkan                            | Keterangan                                 |
| ------------ | --------- | ----------------------------------------------- | ------------------------------------------ |
| `timestamp`  | `string`  | Format ISO-8601                                 | Contoh: `2026-03-12T08:30:00+07:00`        |
| `asset_id`   | `string`  | Non-kosong                                      | Merujuk ke `assets.asset_id`               |
| `severity`   | `integer` | `1` – `15`                                      | Skala standar Wazuh (lihat tabel di bawah) |
| `category`   | `string`  | `auth` \| `malware` \| `integrity` \| `network` | Kategori rule Wazuh                        |
| `event_type` | `string`  | `alert` \| `vuln` \| `control`                  | Jenis event                                |

**Field tambahan (opsional, tidak diwajibkan oleh contract):**

| Field              | Keterangan                                           |
| ------------------ | ---------------------------------------------------- |
| `hostname`         | Nama host aset                                       |
| `rule_id`          | ID rule Wazuh atau VULN-xxx                          |
| `rule_description` | Deskripsi rule                                       |
| `cve_id`           | Diisi jika `event_type = vuln`                       |
| `cvss_score`       | Skor CVSS (0.0–10.0), diisi jika `event_type = vuln` |
| `scenario`         | Label skenario generator                             |

**Skala Severity Wazuh:**

| Rentang | Level         | Contoh                                   |
| ------- | ------------- | ---------------------------------------- |
| 1–3     | Informational | Login sukses                             |
| 4–6     | Low           | Login gagal, file ditambah               |
| 7–10    | Medium        | Port scan, checksum berubah              |
| 11–13   | High          | Brute force, suspicious traffic          |
| 14–15   | Critical      | Malware, ransomware, rootkit, CVE kritis |

---

## 8. Katalog Skenario Data Dummy

### Skenario 1 — Normal (`events_normal.json`)

Mensimulasikan **aktivitas harian bank tanpa anomali** selama 7 hari.

| Parameter        | Nilai                                         |
| ---------------- | --------------------------------------------- |
| Volume           | 60–120 events/hari                            |
| Severity dominan | 1–6 (informational/low)                       |
| Category dominan | `auth` (login success/fail rutin)             |
| Event type       | Hanya `alert`                                 |
| Tujuan           | Membangun baseline risk score rendah (~10–30) |

**Distribusi jam:** Puncak di 08:00–17:00 WIB sesuai jam kerja bank. Sangat sepi di dini hari.

---

### Skenario 2 — Spike (`events_spike.json`)

Mensimulasikan **insiden keamanan mendadak** selama 3 hari.

| Parameter        | Nilai                                         |
| ---------------- | --------------------------------------------- |
| Duration         | 3 hari (1 normal + 1 spike + 1 aftermath)     |
| Volume spike     | 200–400 events dalam 2–3 jam (8–15× baseline) |
| Severity dominan | 10–14 (brute force, port scan, malware)       |
| Target aset      | 1–2 aset kritis (pilihan acak)                |
| Tujuan           | Membuktikan risk score melonjak terdeteksi    |

**Timeline:**

- **Hari 1:** Normal baseline (~80 events)
- **Hari 2:** Spike di jam 10:00–14:00 pada target aset; 85% traffic fokus ke target, 15% simulating lateral movement
- **Hari 3:** Aftermath — residual anomali, severity mulai turun

---

### Skenario 3 — Vulnerability Cluster (`events_vuln_cluster.json`)

Mensimulasikan **hasil vulnerability scan** yang menemukan CVE pada 3–5 aset selama 5 hari.

| Parameter       | Nilai                                                       |
| --------------- | ----------------------------------------------------------- |
| Aset vulnerable | 3–5 aset (pilih acak dari semua tipe)                       |
| CVE per aset    | 1–3 CVE (prioritas CVSS ≥ 7.0 untuk aset kritis)            |
| Jam scan        | Dini hari 01:00–03:00 atau malam 19:00–21:00                |
| Event type      | Campuran `vuln` (scan results) + `alert` (integrity events) |
| Tujuan          | Menguji kenaikan `vuln_score` pada aset yang belum di-patch |

**Ab hari ke-2:** Ditambahkan integrity alerts (file berubah) sebagai penanda potensi eksploitasi.

---

### Skenario 4 — Remediation Decay (`events_remediation_decay.json`)

Mensimulasikan **penurunan bertahap risk score** setelah tim SOC melakukan remediasi, selama 5 hari.

| Hari | Fase                                    | Volume            | Max Severity |
| ---- | --------------------------------------- | ----------------- | ------------ |
| 0    | Post-spike: kondisi darurat             | 200 events (100%) | 15           |
| 1    | SOC Response: investigasi & containment | 120 events (60%)  | 12           |
| 2    | Patch deployed: CVE diselesaikan        | 60 events (30%)   | 9            |
| 3    | Enhanced monitoring: residual rendah    | 30 events (15%)   | 7            |
| 4    | Normalized: kembali ke baseline         | 10 events (5%)    | 5            |

> Skenario ini adalah yang **paling penting untuk demo ke manajemen** karena memperlihatkan bahwa investasi remediasi secara kasat mata menurunkan risk score pada dashboard.

---

## 9. Referensi Modul Python

### `dummy_generator/constants.py`

Sumber kebenaran tunggal untuk semua nilai konstanta. **Jangan hardcode nilai ini di tempat lain.**

```python
from constants import (
    RULES,               # Dict[rule_id, {description, severity, category, event_type}]
    CVE_CATALOG,         # List[{cve_id, cvss_score, product}]
    VALID_CATEGORIES,    # frozenset — {'auth', 'malware', 'integrity', 'network'}
    VALID_EVENT_TYPES,   # frozenset — {'alert', 'vuln', 'control'}
    SCENARIO_NORMAL,     # "normal"
    SCENARIO_SPIKE,      # "spike"
    SCENARIO_VULN,       # "vuln_cluster"
    SCENARIO_DECAY,      # "remediation_decay"
)
```

---

### `dummy_generator/base_generator.py` — Kelas `BaseGenerator`

Abstract base class yang diwarisi semua skenario. Menyediakan utility bersama.

| Method                                                             | Keterangan                                                 |
| ------------------------------------------------------------------ | ---------------------------------------------------------- |
| `_load_assets()`                                                   | Membaca `assets.json` dan mengembalikan list asset         |
| `_get_asset(asset_id)`                                             | Mengembalikan satu asset. Jika `asset_id=None`, pilih acak |
| `_get_assets_by_type(type)`                                        | Filter asset berdasarkan `asset_type`                      |
| `_get_assets_by_criticality(level)`                                | Filter asset berdasarkan level kritisitas                  |
| `_build_alert_event(asset, rule_id, timestamp, override_severity)` | Bangun satu event alert dari rule catalog                  |
| `_build_vuln_event(asset, cve, timestamp)`                         | Bangun satu event vulnerability dari CVE catalog           |
| `_random_cve(min_cvss)`                                            | Pilih CVE acak dengan skor CVSS minimal                    |
| `save(events)`                                                     | Simpan list events ke file JSON di `output/`               |
| `run()`                                                            | Shortcut: `generate_events()` → `save()`                   |

**Wajib diimplementasi subclass:**

```python
@property
@abstractmethod
def scenario_name(self) -> str: ...   # label skenario, e.g. "spike"

@abstractmethod
def generate_events(self) -> list[dict]: ...  # logic generasi event
```

---

### `ingestor/db.py` — Data Access Layer

Modul ini adalah satu-satunya titik akses ke database. Jangan menulis SQL secara langsung di modul lain.

**Fungsi publik:**

| Fungsi                                                            | Keterangan                                                                          |
| ----------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `build_engine()`                                                  | Buat SQLAlchemy Engine dari variabel `.env`                                         |
| `ping(engine)`                                                    | Uji koneksi, kembalikan versi PostgreSQL                                            |
| `validate_events(events)`                                         | Validasi list event terhadap Data Contract. Kembalikan `(valid_list, error_list)`   |
| `bulk_insert_events(engine, events, batch_size, skip_validation)` | Bulk insert menggunakan `psycopg2.extras.execute_values`. Kembalikan dict statistik |
| `bulk_insert_assets(engine, assets)`                              | Insert asset CMDB, skip jika duplikat                                               |

**Exception kustom:**

```python
class SchemaValidationError(ValueError):
    event_index: int   # posisi event di input list (0-based)
    field: str         # nama field yang melanggar
    reason: str        # penjelasan pelanggaran
    raw_value: Any     # nilai aktual yang diterima
```

**Contoh penggunaan:**

```python
from ingestor.db import build_engine, validate_events, bulk_insert_events

engine = build_engine()
valid, errors = validate_events(raw_events)

if errors:
    for err in errors:
        logger.warning("Skema rusak: %s", err)

result = bulk_insert_events(engine, valid)
print(result)
# {'total': 707, 'inserted': 707, 'skipped_invalid': 0, 'errors': []}
```

---

### `dummy_generator/generate_all.py` — Parallel Entry Point

Menjalankan semua skenario secara paralel menggunakan `ProcessPoolExecutor`.

```
Proses Utama
├── Worker PID-A  →  NormalScenario.generate_events()  →  save JSON
├── Worker PID-B  →  SpikeScenario.generate_events()   →  save JSON
├── Worker PID-C  →  VulnClusterScenario.generate_events() → save JSON
└── Worker PID-D  →  DecayScenario.generate_events()   →  save JSON
```

**Catatan penting:** Karena menggunakan `multiprocessing`, guard `if __name__ == "__main__"` di baris terakhir file sangat penting untuk kompatibilitas Windows. Jangan dihapus.

---

## 10. Skema Database

### Tabel `assets` (CMDB)

| Kolom               | Tipe              | Keterangan                                 |
| ------------------- | ----------------- | ------------------------------------------ |
| `asset_id`          | `VARCHAR(100) PK` | Identifikasi unik aset                     |
| `hostname`          | `VARCHAR(100)`    | Nama host                                  |
| `asset_type`        | `VARCHAR(50)`     | `server` \| `workstation` \| `application` |
| `criticality`       | `VARCHAR(20)`     | `low` \| `medium` \| `high` \| `critical`  |
| `criticality_score` | `INTEGER`         | Skor 1–10                                  |
| `department`        | `VARCHAR(100)`    | Departemen pemilik aset                    |
| `ip_address`        | `VARCHAR(50)`     | Alamat IP                                  |

**Katalog 15 aset dummy yang tersedia:**

| Asset ID                 | Tipe        | Kritisitas      | Departemen        |
| ------------------------ | ----------- | --------------- | ----------------- |
| `srv-core-banking-01/02` | server      | critical        | Core Banking      |
| `srv-database-01/02`     | server      | critical / high | IT Infrastructure |
| `srv-web-banking-01`     | server      | high            | Digital Banking   |
| `app-mobile-banking`     | application | critical        | Digital Banking   |
| `app-internet-banking`   | application | critical        | Digital Banking   |
| `ws-teller-01/02/03`     | workstation | high            | Teller            |
| `ws-ops-01/02`           | workstation | medium          | Operations        |
| `srv-backup-01`          | server      | high            | IT Infrastructure |
| `srv-siem-01`            | server      | high            | Security          |
| `ws-cso-01`              | workstation | medium          | Security          |

---

### Tabel `wazuh_events` (Telemetri Input)

| Kolom        | Tipe           | Constraint                | Keterangan                     |
| ------------ | -------------- | ------------------------- | ------------------------------ |
| `id`         | `SERIAL PK`    | —                         | Auto-increment                 |
| `event_id`   | `UUID`         | default gen_random_uuid() | ID unik event                  |
| `timestamp`  | `TIMESTAMP`    | NOT NULL                  | Waktu kejadian                 |
| `asset_id`   | `VARCHAR(100)` | FK → assets               | Aset yang terdampak            |
| `severity`   | `INTEGER`      | CHECK 1–15                | Level bahaya Wazuh             |
| `category`   | `VARCHAR(50)`  | —                         | auth/malware/integrity/network |
| `event_type` | `VARCHAR(50)`  | —                         | alert/vuln/control             |
| `rule_id`    | `VARCHAR(50)`  | —                         | ID rule Wazuh                  |
| `cve_id`     | `VARCHAR(50)`  | —                         | Diisi jika event_type=vuln     |
| `cvss_score` | `NUMERIC(4,1)` | —                         | Diisi jika event_type=vuln     |
| `scenario`   | `VARCHAR(50)`  | —                         | Label skenario generator       |

**Index yang tersedia:** `asset_id`, `timestamp`, `severity`, `scenario`

---

### Tabel `risk_scores` (Output Scoring Engine)

Tabel ini diisi oleh **scoring engine** (komponen berikutnya dalam roadmap). Saat ini didefinisikan sebagai kontrak ke depan.

| Kolom               | Keterangan                               |
| ------------------- | ---------------------------------------- |
| `asset_id`          | Aset yang dikalkulasi                    |
| `risk_score`        | Skor risiko gabungan (0–100)             |
| `threat_score`      | Sub-skor ancaman aktif                   |
| `vuln_score`        | Sub-skor dari kerentanan CVE             |
| `criticality_score` | Sub-skor bobot kritis aset               |
| `calculated_at`     | Timestamp kalkulasi                      |
| `window_hours`      | Jendela waktu kalkulasi (default 24 jam) |

---

## 11. Menjalankan Unit Test

Suite test terdiri dari **61 test case** yang memvalidasi seluruh layer logic generator.

```bash
# Dari root proyek
.venv/bin/python3 -m pytest dummy_generator/tests/ -v
```

**Output yang diharapkan:**

```
61 passed in 0.06s
```

**Kelompok test dan cakupannya:**

| Kelas Test                 | Jumlah | Apa yang Divalidasi                                                      |
| -------------------------- | ------ | ------------------------------------------------------------------------ |
| `TestDataContract`         | 20     | 5 invariant Data Contract × 4 skenario (parameterized)                   |
| `TestBaseGeneratorUtility` | 11     | Method internal `BaseGenerator` (build_event, override_severity, dll)    |
| `TestNormalScenario`       | 6      | Auth dominan, tidak ada vuln events, severity rendah                     |
| `TestSpikeScenario`        | 4      | Severity ≥10 minimal 30%, rasio spike/baseline ≥2×                       |
| `TestVulnClusterScenario`  | 5      | Vuln terkonsentrasi <50% aset, cve_id terisi                             |
| `TestDecayScenario`        | 5      | Volume dan avg severity menurun harian                                   |
| `TestSchemaConsistency`    | 6      | Validasi `constants.py` — mencegah bug category 'vulnerability' terulang |

**Menjalankan satu kelompok test tertentu:**

```bash
# Hanya test Data Contract
.venv/bin/python3 -m pytest dummy_generator/tests/ -v -k "TestDataContract"

# Hanya test terkait severity
.venv/bin/python3 -m pytest dummy_generator/tests/ -v -k "severity"
```

---

## 12. Panduan Kontribusi Kode

### Menambah Skenario Baru

1. Buat file baru di `dummy_generator/scenarios/nama_skenario.py`
2. Buat kelas yang mewarisi `BaseGenerator`
3. Implementasi `scenario_name` (property) dan `generate_events()` (method)
4. Daftarkan kelas ke `SCENARIO_REGISTRY` di `generate_all.py`
5. Tambahkan label ke `constants.py` (e.g. `SCENARIO_NAMA = "nama_skenario"`)
6. Tulis minimal 4 test case di `test_base_generator.py`

```python
# Contoh skeleton skenario baru
from base_generator import BaseGenerator
from constants import SCENARIO_NAMA   # tambahkan konstanta dulu

class NamaScenario(BaseGenerator):
    scenario_name = SCENARIO_NAMA

    def generate_events(self) -> list[dict]:
        events = []
        # ... logic generasi event
        events.sort(key=lambda e: e["timestamp"])
        return events
```

### Menambah Rule Wazuh Baru

Tambahkan entri ke dict `RULES` di `constants.py`. Pastikan:

- `category` adalah salah satu dari `VALID_CATEGORIES`
- `event_type` adalah salah satu dari `VALID_EVENT_TYPES`
- `severity` adalah integer antara 1 dan 15

```python
RULES["new-rule-id"] = {
    "description": "Deskripsi rule",
    "severity": 8,
    "category": "network",    # HARUS salah satu dari VALID_CATEGORIES
    "event_type": "alert",    # HARUS salah satu dari VALID_EVENT_TYPES
}
```

### Aturan Commit

- Jalankan `pytest` sebelum membuat commit. Tidak boleh ada test yang gagal.
- Jangan hapus atau ubah konstanta `VALID_CATEGORIES` / `VALID_EVENT_TYPES` tanpa mendiskusikan dengan tim terlebih dahulu — perubahan ini berdampak ke seluruh pipeline termasuk constraint database.

---

## 13. Troubleshooting

### `Connection refused` saat menjalankan ingestor

**Penyebab:** Container PostgreSQL belum sepenuhnya siap.

```bash
# Cek status container
docker compose ps

# Cek apakah PostgreSQL menerima koneksi
docker exec risk_scoring_db pg_isready -U admin -d risk_scoring

# Jika container baru dijalankan, tunggu beberapa detik lalu coba lagi
```

---

### `FATAL: password authentication failed`

**Penyebab:** Variabel di `.env` tidak cocok dengan konfigurasi container yang sudah ada.

```bash
# Hapus volume database lama (DATA AKAN HILANG — aman karena ini data dummy)
docker compose down -v
docker compose up -d
```

---

### Generator berjalan tapi tidak menghasilkan file output

**Penyebab paling umum:** Menjalankan `generate_all.py` dari direktori yang salah.

```bash
# Pastikan working directory adalah dummy_generator/
cd dummy_generator
python3 generate_all.py

# Atau dari root proyek menggunakan path lengkap
python3 dummy_generator/generate_all.py
```

---

### Test gagal dengan `ImportError`

**Penyebab:** Modul `pytest` belum terinstall di virtual environment.

```bash
source .venv/bin/activate
.venv/bin/python3 -m pip install pytest
```

---

### `SchemaValidationError: category='vulnerability'`

**Penyebab:** Entri di `constants.py` menggunakan `category: 'vulnerability'` yang bukan bagian dari Data Contract.

**Solusi:** Periksa `RULES` di `constants.py`. Semua entry harus menggunakan salah satu dari `{'auth', 'malware', 'integrity', 'network'}`. Jalankan test `TestSchemaConsistency` untuk mendeteksi pelanggaran secara otomatis:

```bash
.venv/bin/python3 -m pytest dummy_generator/tests/ -v -k "TestSchemaConsistency"
```

---

_Dokumen ini dikelola bersama kode sumber. Perbarui bagian yang relevan setiap kali ada perubahan arsitektur atau antarmuka publik._
