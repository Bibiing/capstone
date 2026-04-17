# Dynamic Cyber Risk Scoring Engine

Backend platform untuk mengubah telemetri Wazuh menjadi skor risiko siber yang terukur, explainable, dan dapat ditrack secara time-series.

Dokumen ini ditujukan untuk engineering, DevOps, QA, dan frontend agar onboarding, operasi, dan integrasi API berjalan konsisten dengan arsitektur terbaru.

---

## 1. Ringkasan

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

- SOC dapat menentukan prioritas mitigasi berbasis risiko nyata.
- CISO/Manajemen mendapat ringkasan eksekutif yang explainable.
- Tim dapat melakukan analisis tren dan audit trail berbasis data historis.

---

## 2. Perubahan Arsitektur Terbaru

### 2.1 Auth sekarang Firebase-first

Sebelumnya sistem menggunakan auth lokal + OTP email. Sekarang identitas pengguna dikelola oleh Firebase Authentication.

Provider yang didukung:

- Email/password
- Google Sign-In

Backend tetap menerbitkan JWT aplikasi sendiri setelah Firebase token tervalidasi, untuk otorisasi endpoint internal dan role-based access.

### 2.2 Mandatory login untuk endpoint backend

Semua endpoint bisnis dilindungi auth. Tanpa login, request akan ditolak (401/403).

Pengecualian endpoint publik:

- GET /health
- Endpoint auth Firebase di bawah /auth/firebase/\*
- /docs dan /openapi.json (default FastAPI, sebaiknya dibatasi di production lewat gateway)

### 2.3 Aktivasi otomatis setelah verifikasi email

Role wajib dipilih saat register. Setelah email Firebase terverifikasi, backend akan mengaktifkan akun otomatis pada sign-in pertama.

Respons sign-in pertama setelah verifikasi akan menandai bahwa akun baru diaktivasi, sehingga frontend dapat mengarahkan user kembali ke halaman login untuk mendapatkan sesi backend pada login berikutnya.

### 2.4 Legacy flow dihapus

Flow legacy berikut tidak dipakai lagi:

- register/login lokal
- verify-otp/resend-otp
- integrasi email OTP (Resend)

---

## 3. Prinsip Arsitektur

- Tidak menggunakan seed/mock asset-agent.
- Asset-agent hanya berasal dari sinkronisasi Wazuh.
- Integrasi Wazuh terpusat di service khusus.
- Snapshot skor disimpan sebagai time-series.
- API terpisah dari storage (PostgreSQL) dan orkestrasi job periodik.
- Identity provider externalized ke Firebase, authorization tetap dikontrol backend.

---

## 4. Arsitektur Sistem

```text
Firebase Auth (email/password, Google)
          |
          v
Frontend obtains Firebase ID Token
          |
          v
/auth/firebase/sign-in (FastAPI)
  - verify Firebase token
  - sync local user
  - enforce email verification
  - auto-activate account on first verified sign-in
          |
          v
Backend JWT (Bearer)
          |
          +------------------------------+
          |                              |
          v                              v
Wazuh Manager API (55000)         Wazuh Indexer API (9200)
          \                              /
           \                            /
            -------> wazuh_service.py <-
                         |
                         v
                   scoring_engine.py
                         |
                         v
                     scheduler.py
                         |
                         v
PostgreSQL (users, assets, risk_scores, alert_snapshots)
                         |
                         v
FastAPI routes (auth, assets, scores, simulate, dashboard, observability)
```

---

## 5. Struktur Repository

```text
Capstone/
├── api/
│   ├── main.py
│   ├── schemas.py
│   ├── security.py
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

## 6. Model Data Inti

### 6.1 users

Tabel user lokal untuk authorization dan profil aplikasi.

Field penting:

- user_id
- username
- email
- role
- is_active
- is_verified
- firebase_uid
- auth_provider
- display_name
- avatar_url

### 6.2 assets

Inventaris aset hasil sinkronisasi Wazuh.

- id (UUID)
- agent_id (unik dari Wazuh)
- name, ip_address, os_type, status
- impact_score (0.0 - 1.0)

### 6.3 risk_scores

Snapshot skor risiko per aset per periode.

- score_i, score_v, score_t, score_r
- period_start, period_end, calculated_at
- index: asset_id + calculated_at DESC

### 6.4 alert_snapshots

Cache alert per aset untuk audit dan explainability.

- rule_level, rule_id, description
- event_time, ingested_at

---

## 7. Service Utama

### 7.1 firebase_auth_service.py

Tanggung jawab:

- inisialisasi Firebase Admin SDK
- verifikasi Firebase ID token
- trigger email verification
- trigger password reset

### 7.2 auth_service.py

Tanggung jawab:

- sinkronisasi user Firebase ke PostgreSQL
- enforcement verified email
- aktivasi otomatis akun saat sign-in pertama setelah email terverifikasi
- penerbitan backend JWT

### 7.3 wazuh_service.py

Gateway tunggal ke Wazuh:

- auth token Wazuh Manager
- list/detail agent
- SCA score
- alert search dari indexer

### 7.4 scoring_engine.py

Pure function kalkulasi:

- calculate_v
- calculate_t
- calculate_r
- classify_severity

### 7.5 scheduler.py

Job periodik:

- sync_assets_from_wazuh: setiap 6 jam
- run_threat_scoring: setiap 4 jam
- run_vulnerability_scoring: setiap 24 jam

---

## 8. Matriks Akses Endpoint

### 8.1 Public

- GET /health
- POST /auth/firebase/sign-in
- POST /auth/firebase/send-email-verification
- POST /auth/firebase/password-reset

### 8.2 Authenticated (Bearer JWT backend)

- GET /assets
- GET /assets/{asset_id}
- GET /scores/latest
- GET /scores/{asset_id}
- GET /trends/{asset_id}
- GET /dashboard/summary
- GET /dashboard/risk-trend

### 8.3 Authenticated + Role CISO

- POST /assets/sync/agents
- POST /simulate/spike
- POST /simulate/remediation
- GET /dashboard/latest-alerts
- GET /dashboard/assets-table
- GET /dashboard/assets/{asset_id}/detail
- GET /dashboard/assets/{asset_id}/security-report
- GET /metrics

Catatan:

- Semua endpoint bisnis akan menolak request tanpa bearer token.
- Token yang dipakai untuk endpoint bisnis adalah token backend, bukan langsung Firebase ID token.

---

## 9. Konfigurasi Environment

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
WAZUH_VERIFY_SSL=false

# App security
API_SECRET_KEY=<strong-secret>

# Firebase
FIREBASE_PROJECT_ID=<firebase-project-id>
FIREBASE_WEB_API_KEY=<firebase-web-api-key>
FIREBASE_SERVICE_ACCOUNT_PATH=./<service-account-file>.json
FIREBASE_REQUIRE_VERIFIED_EMAIL=true

# Auth rate limits
AUTH_LOGIN_LIMIT_PER_15M=10
AUTH_PASSWORD_RESET_LIMIT_PER_HOUR=10

# Dashboard hardening
DASHBOARD_RATE_LIMIT_PER_MINUTE=120
DASHBOARD_RATE_LIMIT_WINDOW_SECONDS=60
METRICS_ENABLED=true

# Scoring
WEIGHT_VULNERABILITY=0.3
WEIGHT_THREAT=0.7
DECAY_FACTOR=0.5
SCORING_SCHEDULER_ENABLED=true
```

Catatan keamanan:

- Jangan commit file .env dan service account JSON ke repository.
- Gunakan WAZUH_VERIFY_SSL=true di production dengan CA valid.
- Rotasi API_SECRET_KEY dan kredensial Wazuh secara berkala.

---

## 10. Cara Menjalankan (Lokal Docker)

### 10.1 Prasyarat

- Docker dan Docker Compose aktif
- Port 5432 dan 8000 tersedia
- Kredensial Wazuh valid di .env
- Service account Firebase Admin tersedia sesuai FIREBASE_SERVICE_ACCOUNT_PATH

### 10.2 Build dan jalankan layanan

```bash
docker compose up -d --build postgres api
```

### 10.3 Jalankan migrasi database

```bash
docker compose exec -T api alembic upgrade head
```

### 10.4 Validasi container

```bash
docker compose ps
```

Expected:

- risk_scoring_db: healthy
- risk_scoring_api: healthy

### 10.5 Validasi endpoint publik

```bash
curl -i http://localhost:8000/health
```

### 10.6 Login flow (wajib sebelum akses endpoint bisnis)

Langkah login backend:

0. Setelah `POST /auth/firebase/register`, backend otomatis mencoba mengirim email verifikasi.
   Frontend sebaiknya arahkan user ke halaman "Check your email" dan sediakan tombol resend.

1. Frontend sign-in ke Firebase dan dapatkan id_token.
2. Exchange ke backend:

```bash
curl -i -X POST http://localhost:8000/auth/firebase/sign-in \
  -H 'Content-Type: application/json' \
  -d '{"id_token":"<firebase_id_token>"}'
```

3. Jika response sign-in pertama berisi `session: null` dan message aktivasi, arahkan user ke halaman login lalu lakukan sign-in ulang.

4. Gunakan access_token backend dari sign-in kedua untuk endpoint lain:

```bash
curl -i http://localhost:8000/assets \
  -H 'Authorization: Bearer <backend_access_token>'
```

### 10.7 Sinkronisasi aset dari Wazuh

```bash
curl -i -X POST http://localhost:8000/assets/sync/agents \
  -H 'Authorization: Bearer <backend_access_token_ciso>'
```

### 10.8 Generate snapshot skor pertama

Opsional untuk smoke test jika belum ada data skor:

```bash
curl -i -X POST http://localhost:8000/simulate/spike \
  -H 'Authorization: Bearer <backend_access_token_ciso>' \
  -H 'Content-Type: application/json' \
  -d '{"asset_ids":["<asset_uuid>"],"threat_value":80,"reason":"smoke-test"}'
```

---

## 11. Error yang Sering Muncul

### 11.1 401 Unauthorized

Penyebab:

- tidak mengirim Authorization header
- token backend invalid/expired

Perbaikan:

- login ulang melalui flow Firebase -> backend
- pastikan format header: Authorization: Bearer <token>

### 11.2 403 Forbidden

Penyebab:

- user belum verified email (jika enforcement aktif)
- role tidak memenuhi (contoh endpoint CISO diakses role Manajemen)

Perbaikan:

- selesaikan verifikasi email Firebase
- gunakan akun dengan role yang sesuai

### 11.3 503 No risk scores available yet

Penyebab:

- tabel risk_scores masih kosong

Perbaikan:

- sinkronisasi aset dari Wazuh
- tunggu scheduler atau jalankan simulasi spike untuk bootstrap data

---

## 12. Integrasi Frontend (Ringkas)

Frontend harus:

1. Sign-in ke Firebase (email/password atau Google).
2. Ambil Firebase ID token.
3. Exchange ke backend via /auth/firebase/sign-in.
4. Simpan backend access token.
5. Gunakan backend token untuk seluruh endpoint bisnis.

---

## 13. Testing

Jalankan test API utama:

```bash
python -m pytest -q tests/test_api.py
```

Targeted tests:

```bash
python -m pytest -q tests/test_wazuh_service.py tests/test_scheduler.py
```

---

## 14. Checklist Production Readiness

- Batasi CORS origin (jangan wildcard)
- Lindungi /docs dan /openapi.json via gateway auth/IP allowlist
- Gunakan HTTPS end-to-end
- Aktifkan SSL verify untuk Wazuh
- Simpan secret pada secret manager
- Tambahkan observability: logs terstruktur, metrics, tracing, alerting

---

## 15. Kontak dan Ownership

- Domain Auth: Backend Platform
- Domain Wazuh Integration: Security Engineering
- Domain Scoring Model: Risk Analytics

Perubahan kontrak API harus diikuti pembaruan README ini dan changelog internal tim.
