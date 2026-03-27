# Dynamic Cyber Risk Scoring Engine

Backend platform untuk mengubah telemetri Wazuh menjadi skor risiko siber yang terukur, dapat dijelaskan, dan dapat ditracking secara time-series.

Dokumen ini ditulis untuk kebutuhan tim engineering, DevOps, dan frontend agar onboarding, operasi, serta integrasi API berjalan konsisten di skala industri.

---

## 1. Ringkasan Eksekutif

Sistem menghitung skor risiko per aset dengan formula:

R = I x (w1 x V + w2 x T)

Keterangan:

- I: Impact bisnis aset (0.0 - 1.0)
- V: Vulnerability score dari SCA Wazuh (0 - 100)
- T: Threat score dinamis dari alert Wazuh + time decay (0 - 100)
- R: Final risk score (0 - 100)

Default bobot:

- w1 = 0.30 (vulnerability)
- w2 = 0.70 (threat)

Tujuan:

- SOC dapat prioritas mitigasi berbasis risiko nyata.
- CISO/Manajemen mendapat ringkasan eksekutif yang explainable.
- Tim dapat melakukan analisis tren dan audit trail berbasis data historis.

---

## 2. Prinsip Arsitektur

- Tidak menggunakan seed/mock untuk asset-agent.
- Asset-agent hanya berasal dari sinkronisasi Wazuh.
- Sumber integrasi Wazuh terpusat di service khusus.
- Snapshot skor disimpan sebagai time-series.
- API dipisah dari storage (PostgreSQL) dan orkestrasi job periodik.

---

## 3. Arsitektur Sistem

```text
Wazuh Manager API (55000) -----> wazuh_service.py -----> sinkronisasi agents + SCA
Wazuh Indexer API (9200)  -----> wazuh_service.py -----> query alert telemetry
                                                 |
                                                 v
                                       scoring_engine.py
                                                 |
                                                 v
                                         scheduler.py
                                                 |
                                                 v
                            PostgreSQL (assets, risk_scores, alert_snapshots)
                                                 |
                                                 v
                              FastAPI routes (auth, assets, scores, simulate)
```

---

## 4. Struktur Repository

```text
Capstone/
├── api/
│   ├── main.py
│   ├── schemas.py
│   ├── security.py
│   ├── email.py
│   ├── dependencies/
│   ├── routes/
│   └── services/
├── config/
│   └── settings.py
├── database/
│   ├── connection.py
│   ├── models.py
│   ├── queries.py
│   ├── repositories/
│   └── migrations/
├── docs/
├── tests/
├── docker-compose.yml
├── Dockerfile
├── alembic.ini
└── requirements.txt
```

---

## 5. Data Model Inti

### assets

Inventaris aset hasil sinkronisasi Wazuh.

- id (UUID)
- agent_id (unik dari Wazuh)
- name, ip_address, os_type, status
- impact_score (0.0 - 1.0)

### risk_scores

Snapshot skor risiko per aset per periode.

- score_i, score_v, score_t, score_r
- period_start, period_end, calculated_at
- index: asset_id + calculated_at DESC

### alert_snapshots

Cache alert per aset untuk audit dan explainability.

- rule_level, rule_id, description
- event_time, ingested_at

---

## 6. Service Utama

### wazuh_service.py

Satu-satunya gateway ke Wazuh API:

- auth token Wazuh Manager
- list/detail agent
- SCA score
- alert search dari indexer

### scoring_engine.py

Pure function kalkulasi:

- calculate_v
- calculate_t
- calculate_r
- classify_severity

### scheduler.py

Job periodik:

- sync_assets_from_wazuh: setiap 6 jam
- run_threat_scoring: setiap 4 jam
- run_vulnerability_scoring: setiap 24 jam

---

## 7. Konfigurasi Environment

Konfigurasi dibaca dari .env melalui config/settings.py.

Contoh variabel minimum:

```env
# Database
DATABASE_URL=postgresql://admin:secret@postgres:5432/risk_scoring

# Wazuh Manager
WAZUH_API_URL=https://<wazuh-host>:55000
WAZUH_API_USER=<username>
WAZUH_API_PASSWORD=<password>

# Wazuh Indexer
WAZUH_INDEXER_URL=https://<wazuh-host>:9200
WAZUH_INDEXER_USER=<username>
WAZUH_INDEXER_PASSWORD=<password>

# Security
API_SECRET_KEY=<strong-secret>
RESEND_API_KEY=<resend-api-key>
OTP_FROM_EMAIL=<verified-sender>

# Scoring
WEIGHT_VULNERABILITY=0.3
WEIGHT_THREAT=0.7
DECAY_FACTOR=0.5
SCORING_SCHEDULER_ENABLED=true
```

Catatan:

- Gunakan WAZUH_VERIFY_SSL=true di production dengan CA valid.
- Jangan commit file .env ke repository.

---

## 8. Cara Running (Detail)

### 8.1 Prasyarat

- Docker dan Docker Compose aktif
- Port 5432 dan 8000 tersedia
- Kredensial Wazuh valid di .env

### 8.2 Jalankan layanan

```bash
docker compose up -d --build postgres api
```

### 8.3 Jalankan migrasi database

```bash
docker compose exec -T api alembic upgrade head
```

### 8.4 Validasi container

```bash
docker compose ps
```

Expected:

- risk_scoring_db status healthy
- risk_scoring_api status healthy

### 8.5 Validasi API base

```bash
curl -i http://localhost:8000/health
curl -i http://localhost:8000/docs
```

### 8.6 Sinkronisasi aset dari Wazuh (wajib)

```bash
curl -i -X POST http://localhost:8000/assets/sync/agents
curl -i http://localhost:8000/assets
```

Jika sinkronisasi berhasil, endpoint assets menampilkan data agent Wazuh.

### 8.7 Menghasilkan snapshot skor pertama

Ada dua cara:

1) Otomatis oleh scheduler

- Pastikan SCORING_SCHEDULER_ENABLED=true
- Tunggu jadwal job berjalan

2) Manual cepat (untuk smoke test)

- Ambil satu asset_id UUID dari GET /assets
- Panggil simulasi spike:

```bash
curl -i -X POST http://localhost:8000/simulate/spike \
  -H 'Content-Type: application/json' \
  -d '{"asset_ids":["<asset_uuid>"],"threat_value":80,"reason":"smoke-test"}'
```

Setelah itu endpoint skor akan punya data.

---

## 9. Kenapa Muncul 503 No risk scores available yet

Respons berikut:

- status_code 503
- message No risk scores available yet. Run scoring engine first.

artinya normal pada kondisi ini:

- Tabel risk_scores masih kosong.
- Aset sudah ada, tetapi belum pernah dihitung skor.

Langkah perbaikan:

1. Pastikan assets sudah tersinkron dari Wazuh: POST /assets/sync/agents.
2. Jalankan jalur pembentukan skor pertama:
   - tunggu scheduler, atau
   - panggil POST /simulate/spike dengan UUID asset.
3. Ulangi GET /scores/latest.

Jika tetap 503:

- Cek Wazuh connectivity dan kredensial .env.
- Cek log container API:

```bash
docker compose logs --tail=200 api
```

---

## 10. API yang Diekspos

### Health & metadata

- GET /health
- GET /
- GET /docs

### Auth

- POST /auth/register
- POST /auth/login
- POST /auth/verify-otp
- POST /auth/resend-otp

### Assets

- POST /assets/sync/agents
- GET /assets
- GET /assets/{asset_id}

### Scores

- GET /scores/latest
- GET /scores/{asset_id}
- GET /trends/{asset_id}?period=1d|7d|30d|90d

### Simulation

- POST /simulate/spike
- POST /simulate/remediation

---

## 11. Catatan Khusus Tim Frontend

Bagian ini penting sebagai kontrak integrasi FE-BE.

### 11.1 Endpoint yang direkomendasikan untuk layar utama

1. Dashboard summary

- GET /scores/latest
- Tujuan: menampilkan ranking aset berdasarkan score_r terbaru.

2. Asset inventory

- GET /assets
- Tujuan: menampilkan daftar agent/aset hasil sinkronisasi Wazuh.

3. Asset detail

- GET /assets/{asset_id}
- GET /scores/{asset_id}
- GET /trends/{asset_id}?period=7d

4. Simulasi

- POST /simulate/spike
- POST /simulate/remediation

### 11.2 Alur data FE yang disarankan

1. Saat halaman dashboard load:

- panggil GET /scores/latest
- jika 503, tampilkan status kosong dengan CTA:
  - Sinkronkan aset
  - Jalankan simulasi awal

2. Saat halaman aset load:

- panggil GET /assets
- simpan asset_id UUID dari response untuk semua request berikutnya

3. Saat halaman detail aset load:

- panggil GET /scores/{asset_id}
- panggil GET /trends/{asset_id}?period=7d

### 11.3 Kontrak penting untuk frontend

- asset_id selalu UUID, bukan asset-001 style lama.
- Endpoint scores dan trends akan mengembalikan 400 jika asset_id bukan UUID valid.
- Endpoint latest bisa mengembalikan 503 jika belum ada snapshot skor.
- Semua error mengikuti schema standar: status_code, message, detail, request_id.

### 11.4 Daftar status code yang wajib ditangani FE

- 200: sukses
- 201: resource dibuat (contoh register)
- 400: invalid input atau invalid UUID
- 401/403: auth/permission
- 404: asset/data tidak ditemukan
- 422: validation error
- 503: data scoring belum tersedia atau integrasi eksternal gagal

---

## 12. Testing

Targeted integration tests:

```bash
python -m pytest -q tests/test_wazuh_service.py tests/test_scheduler.py
```

Catatan:

- Setelah migrasi ke Wazuh-only asset flow, beberapa legacy test yang mengasumsikan mock id non-UUID perlu disesuaikan.

---

## 13. Keamanan dan Operasional

Sudah diimplementasikan:

- bcrypt password hashing
- JWT bearer auth
- OTP verification + retry policy email
- rate limiting endpoint auth sensitif
- request id dan structured error response

Rekomendasi production:

- aktifkan SSL verify ke Wazuh dengan CA valid
- batasi CORS origin
- rotasi secret berkala
- aktifkan observability (metrics, tracing, alerting)

---

## 14. Troubleshooting Cepat

1. API unhealthy di docker compose ps

- cek logs api
- pastikan migrasi sudah jalan

2. POST /assets/sync/agents gagal

- cek WAZUH_API_URL, kredensial, dan network dari container API

3. GET /scores/latest 503

- belum ada snapshot pertama di risk_scores
- jalankan simulasi spike atau tunggu scheduler

4. Simulasi 400 none of provided asset IDs found

- pastikan pakai UUID dari GET /assets

---

## 15. Arah Pengembangan Lanjutan

- pecah schemas per domain
- tambah RBAC endpoint sensitif (CISO vs Manajemen)
- tambah integration test end-to-end Wazuh -> scoring -> trend
- tambah endpoint dashboard khusus summary agar payload lebih ringan

