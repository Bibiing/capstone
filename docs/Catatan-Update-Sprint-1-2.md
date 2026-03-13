# Catatan Update Sprint 1-2

## Tujuan Dokumen

Dokumen ini menjelaskan pembaruan teknis terbaru pada fase Sprint 1-2, khususnya untuk dua area utama:

1. Docker dan Database setup.
2. Wazuh client, fetcher, dan integrasi asset registry berbasis Wazuh.

Dokumen ini dibuat terpisah dari README agar pembaca dapat memahami konteks perubahan tanpa harus menelusuri seluruh dokumentasi proyek.

## Ruang Lingkup Update

Update yang dibahas pada catatan ini mencakup:

1. [docker-compose.yml](../docker-compose.yml)
2. [config/assets_registry.json](../config/assets_registry.json)
3. [ingestion/wazuh_client.py](../ingestion/wazuh_client.py)
4. [ingestion/alert_fetcher.py](../ingestion/alert_fetcher.py)
5. [ingestion/sca_fetcher.py](../ingestion/sca_fetcher.py)

## Ringkasan Eksekutif

Konfigurasi infrastruktur sudah berada pada kondisi yang siap untuk pengembangan backend bertahap:

1. PostgreSQL dijalankan sebagai service inti dengan healthcheck.
2. pgAdmin disiapkan sebagai tool observabilitas data khusus mode development.
3. Baseline asset registry disimpan di konfigurasi terpusat agar mapping asset-agent konsisten.
4. Pipeline ingestion berjalan berbasis telemetry live Wazuh (bukan replay dataset).

## Detail Perubahan

### 1. Docker dan Database Setup

File: [docker-compose.yml](../docker-compose.yml)

1. Service `postgres` menjadi fondasi environment dengan image `postgres:16-alpine`.
2. Persistensi data database sudah diaktifkan melalui volume `postgres_data`.
3. Healthcheck menggunakan `pg_isready` untuk memastikan service benar-benar siap sebelum dependensi lain dijalankan.
4. Service `pgadmin` tersedia lewat profile `dev`, sehingga tidak membebani mode run standar.
5. Service `risk-engine`, `api`, dan `dashboard` sudah dipersiapkan dalam template komentar sebagai jalur aktivasi Sprint berikutnya.

Nilai dari desain ini:
1. Maintainability: struktur compose jelas dan mudah diaktifkan bertahap.
2. Scalability: service extension sudah disiapkan tanpa perlu refactor file besar.
3. Reliability: healthcheck mencegah race condition saat startup stack.

### 2. Baseline Asset Registry

File: [config/assets_registry.json](../config/assets_registry.json)

Perubahan penting:

1. Terdapat 7 aset representatif domain perbankan.
2. Setiap aset memiliki `asset_id`, `hostname`, `wazuh_agent_id`, `ip_address`, `likert_score`, dan `description`.
3. Nilai `likert_score` membentuk variasi tingkat kritikalitas bisnis dari rendah sampai sangat kritis.

Nilai profesional dari desain ini:

1. Business alignment: aset kritis bank (database nasabah, core banking, channel layanan) terwakili.
2. Explainability: deskripsi aset memudahkan pembaca non-teknis memahami dampak bisnis.
3. Integrasi `wazuh_agent_id` memudahkan korelasi langsung antara asset bisnis dan telemetry live.

### 3. Integrasi Telemetry Live Wazuh

File:

1. [ingestion/wazuh_client.py](../ingestion/wazuh_client.py)
2. [ingestion/alert_fetcher.py](../ingestion/alert_fetcher.py)
3. [ingestion/sca_fetcher.py](../ingestion/sca_fetcher.py)

Perubahan penting:

1. Discovery agent demo menggunakan telemetry indexer 24 jam terakhir.
2. Query alert severity (low/medium/high/critical) berjalan langsung ke indexer Wazuh.
3. Endpoint SCA tetap dijaga melalui API Manager, dengan fallback terkontrol jika belum reachable.
4. Semua demo CLI difokuskan untuk pembuktian integrasi live, bukan replay dataset.

## Dampak ke Implementasi Backend Sprint 3-4

Update ini sudah memberi fondasi kuat untuk pekerjaan berikutnya:

1. Scoring engine dapat memakai alert live dan SCA live sebagai input utama.
2. Repository layer dapat memelihara mapping asset-agent dari registry terpusat.
3. Endpoint API nantinya dapat menampilkan skor berbasis telemetry aktual.

## Panduan Running Detail

Bagian ini adalah panduan operasional untuk menjalankan komponen Sprint 1-2 secara urut dan aman.

### A. Prasyarat Lingkungan

Pastikan komponen berikut tersedia sebelum memulai:

1. Python 3.11+.
2. Docker Engine + Docker Compose.
3. Akses jaringan ke endpoint Wazuh lab (jika mode Live Wazuh).
4. Shell Linux dengan hak akses menjalankan Docker.

Verifikasi cepat:

1. Jalankan `python3 --version`.
2. Jalankan `docker --version`.
3. Jalankan `docker compose version`.

### B. Setup Lokal Project

Urutan rekomendasi:

1. Masuk ke root project.
2. Buat virtual environment.
3. Install dependency.

Perintah:

1. `cd /home/julian/Documents/Capstone`
2. `python3 -m venv .venv`
3. `source .venv/bin/activate`
4. `pip install -r requirements.txt`

Alternatif cepat via Makefile:

1. `make setup`

### C. Konfigurasi Environment

File acuan konfigurasi ada di [.env.example](../.env.example).

Langkah:

1. Salin file contoh menjadi file aktif.
2. Isi kredensial yang valid.

Perintah:

1. `cp .env.example .env`

Parameter minimum yang wajib benar:

1. `DATABASE_URL`.
2. `WAZUH_API_URL`, `WAZUH_API_USER`, `WAZUH_API_PASSWORD`.
3. `WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASSWORD`.
4. `WAZUH_VERIFY_SSL` (umumnya `false` untuk lab self-signed).

Catatan penting endpoint Wazuh:

1. Alert telemetry dibaca dari `WAZUH_INDEXER_URL` (contoh: `https://HOST:9200`).
2. Endpoint agent list dan SCA dibaca dari `WAZUH_API_URL` dan **wajib** mengarah ke API Manager (disarankan `https://HOST:55000`).
3. Endpoint autentikasi default backend: `/security/user/authenticate?raw=true` (Basic Auth → JWT token).
4. Jika `WAZUH_API_URL` salah host/port/path, Anda bisa tetap melihat alert live dari indexer, tetapi endpoint agent/SCA akan gagal.

Catatan keamanan:

1. Jangan commit file `.env` ke repository.
2. Jangan menaruh password langsung di source code.
3. Gunakan akun Wazuh dengan hak minimum yang diperlukan.

### D. Docker dan Database Setup

Sumber konfigurasi service: [docker-compose.yml](../docker-compose.yml).

#### D1. Menjalankan PostgreSQL saja (mode standar)

Perintah:

1. `docker compose up -d postgres`

Alternatif:

1. `make up`

#### D2. Menjalankan PostgreSQL + pgAdmin (mode development)

Perintah:

1. `docker compose --profile dev up -d`

Alternatif:

1. `make dev-up`

Endpoint default:

1. PostgreSQL di `localhost:5432`.
2. pgAdmin di `http://localhost:5050`.

#### D3. Verifikasi container dan health

Perintah:

1. `docker compose ps`
2. `docker logs risk_scoring_db --tail 50`

Indikator sukses:

1. Container `risk_scoring_db` status `Up`.
2. Healthcheck PostgreSQL status `healthy`.

#### D4. Inisialisasi schema database

Perintah:

1. `python -m alembic upgrade head`

Alternatif:

1. `make migrate`

Validasi schema terbentuk:

1. `python -m alembic current`
2. Pastikan tabel inti tersedia: `assets`, `risk_scores`, `threat_state`, `sca_snapshots`.

#### D5. Bootstrap baseline asset registry ke database

Sumber baseline: [config/assets_registry.json](../config/assets_registry.json).

Perintah:

1. `python -m ingestion.asset_registry seed`
2. `python -m ingestion.asset_registry list`

Alternatif:

1. `make seed`

Catatan:

1. Perintah `seed` di sini adalah **bootstrap CMDB aset** (asset registry), bukan simulasi telemetry Wazuh.
2. Telemetry alert/SCA tetap diambil live dari Wazuh API + Indexer.

### E. Menjalankan dan Memvalidasi Wazuh Client

Komponen utama ada di [ingestion/wazuh_client.py](../ingestion/wazuh_client.py).

Fungsi penting yang perlu dipahami:

1. `get_agents()` untuk mengambil daftar agent.
2. `get_sca_summary(agent_id)` untuk ringkasan SCA.
3. `count_alerts_by_level(agent_id, from_dt, to_dt)` untuk agregasi alert berdasarkan level.

> **Perhatian — penulisan perintah yang benar:**
> Python tidak menerima ekstensi `.py` di flag `-m`.
> `python -m ingestion.wazuh_client.py` → **ERROR**
> `python -m ingestion.wazuh_client` → **BENAR**

Cara menjalankan langsung dari terminal (satu baris, tidak perlu REPL):

```bash
python -m ingestion.wazuh_client
```

Perintah ini menjalankan blok demo bawaan: list agents → alert counts → SCA summary.

Perilaku pada environment hybrid (sesuai kondisi saat ini):

1. Jika API Manager tidak reachable, demo akan fallback ke discovery agent dari indexer (live telemetry) dan tetap menampilkan alert counts.
2. Bagian SCA akan ditandai `unavailable` dengan alasan dependency API Manager.

Smoke test cepat (Live Wazuh):  
Alternatif via Python REPL atau skrip singkat:

```python
from datetime import datetime, timedelta, timezone
from ingestion.wazuh_client import WazuhClient

with WazuhClient.from_settings() as client:
	agents = client.get_agents(status="active")
	print("agents:", len(agents))

	if agents:
		agent_id = agents[0].agent_id
		now = datetime.now(timezone.utc)
		counts = client.count_alerts_by_level(agent_id, now - timedelta(hours=1), now)
		print("sample agent:", agent_id, counts)

		sca = client.get_sca_summary(agent_id)
		print("sca policies:", len(sca))
```

Indikator sukses:

1. Alert count live dari indexer tampil.
2. Jika API Manager reachable, daftar agent dan SCA tampil.
3. Jika API Manager belum reachable, fallback message muncul jelas tanpa crash.

### F. Menjalankan Alert Fetcher dan SCA Fetcher

Komponen:

1. [ingestion/alert_fetcher.py](../ingestion/alert_fetcher.py)
2. [ingestion/sca_fetcher.py](../ingestion/sca_fetcher.py)
3. [ingestion/threat_hunting.py](../ingestion/threat_hunting.py)

Tujuan eksekusi:

1. Alert Fetcher menghasilkan ringkasan count per level.
2. SCA Fetcher menghasilkan pass percentage dan vulnerability score.
3. Threat Hunting Fetcher menghasilkan snapshot investigasi (event stream, histogram, top rules).

Cara menjalankan langsung dari terminal:

```bash
# Fetcher alert (auto-discovery agent dari telemetry 24 jam terakhir)
python -m ingestion.alert_fetcher

# Fetcher SCA (auto-discovery agent dari telemetry 24 jam terakhir)
python -m ingestion.sca_fetcher

# Fetcher Threat Hunting (snapshot gaya UI Threat Hunting)
python -m ingestion.threat_hunting
```

Contoh eksekusi manual via REPL:

```python
from ingestion.wazuh_client import WazuhClient
from ingestion.alert_fetcher import AlertFetcher
from ingestion.sca_fetcher import SCAFetcher

asset_id = "asset-001"
agent_id = "001"

with WazuhClient.from_settings() as client:
	alert_fetcher = AlertFetcher.from_settings(client=client)
	sca_fetcher = SCAFetcher.from_settings(client=client, persist=True)

	alerts = alert_fetcher.fetch(agent_id)
	print("alerts:", alerts)

	sca = sca_fetcher.fetch(agent_id=agent_id, asset_id=asset_id)
	print("sca pass:", sca.pass_percentage, "vuln:", sca.vulnerability_score)
```

Perilaku fallback yang perlu dipahami:

1. Alert Fetcher akan mengembalikan nilai nol jika query gagal.
2. SCA Fetcher akan fallback ke pass 50% bila data SCA tidak tersedia.
3. Mekanisme ini mencegah pipeline berhenti total saat ada gangguan parsial.

### H. Checklist Verifikasi End-to-End Sprint 1-2

Sebelum lanjut ke Sprint 3-4, pastikan kondisi berikut terpenuhi:

1. Docker PostgreSQL berjalan stabil.
2. Alembic migration sudah `head`.
3. Baseline asset registry berhasil di-bootstrap.
4. Unit test ingestion lolos.
5. Alert live dari indexer dapat di-query (proof telemetry live).
6. API Manager reachable: agent list + SCA tampil.
7. Threat Hunting snapshot dapat ditarik per agent (event stream + histogram + top rules).

Perintah validasi cepat:

1. `make test`
2. `make check-db`
3. `python -m ingestion.asset_registry list`

### I. Troubleshooting Singkat

Masalah umum dan solusi:

1. `ModuleNotFoundError: __path__ attribute not found on 'ingestion.wazuh_client'`.
   Penyebab: menggunakan ekstensi `.py` pada flag `-m`, misalnya `python -m ingestion.wazuh_client.py`.
   Solusi: hilangkan `.py` — gunakan `python -m ingestion.wazuh_client`.
2. `Connection refused` ke PostgreSQL.
   Solusi: pastikan container aktif dengan `docker compose ps`, lalu cek log.
3. `WazuhAuthenticationError`.
   Solusi: verifikasi username/password di `.env` dan hak akses user Wazuh.
4. `Wazuh API authentication endpoint not found (404)`.
   Solusi: cek `WAZUH_API_URL` (harus API Manager), gunakan port `55000`, dan pastikan auth path `/security/user/authenticate?raw=true`.
5. SSL error saat hit endpoint Wazuh lab.
   Solusi: gunakan `WAZUH_VERIFY_SSL=false` untuk environment lab self-signed.
6. Bootstrap asset registry gagal karena format JSON.
   Solusi: cek validitas JSON pada [config/assets_registry.json](../config/assets_registry.json) dan pastikan field wajib ada.

### J. Demo Urutan Lengkap untuk Stakeholder

Urutan perintah berikut menghasilkan output nyata yang dapat ditampilkan langsung pada demo.
Semua perintah dijalankan dari root project dengan virtual environment aktif.

#### Langkah 1 — Buktikan test suite hijau

```bash
source .venv/bin/activate
make test
```

Output yang diharapkan: `21 passed` tanpa error.

#### Langkah 2 — Buktikan infrastruktur database berjalan

```bash
make up
make check-db
```

Output yang diharapkan: status `healthy` pada PostgreSQL dan konfirmasi koneksi berhasil.

#### Langkah 3 — Buktikan schema dan baseline asset registry tersedia

```bash
python -m alembic current
python -m ingestion.asset_registry list
```

Output yang diharapkan: revision `001` tercantum dan 7 aset terdaftar.

#### Langkah 4 (Live Wazuh) — Buktikan koneksi ke Wazuh

```bash
python -m ingestion.wazuh_client
```

Output yang diharapkan:

```
============================================================
  WazuhClient — Demo / Smoke Test
============================================================

[1] Active agents (API): N
   • 001 ...
[2] Alert counts (last 24 h) for agent 000:
    low       : N
    medium    : N
    high      : N
    critical  : N
    T_new_raw = N
[3] SCA policies for agent 000: N
   • ...

[OK] WazuhClient smoke test passed.
```

#### Langkah 5 (Live Wazuh) — Buktikan Alert Fetcher berfungsi

```bash
python -m ingestion.alert_fetcher
```

Output yang diharapkan:

```
============================================================
  AlertFetcher — Demo / Smoke Test
============================================================

Live agents from telemetry: 000, 001

agent=001  total=N  [low=N medium=N high=N critical=N]
  → T_new_raw = N
...
[OK] AlertFetcher demo complete.
```

#### Langkah 6 (Live Wazuh) — Buktikan SCA Fetcher berfungsi

```bash
python -m ingestion.sca_fetcher
```

Output yang diharapkan:

```
============================================================
  SCAFetcher — Demo / Smoke Test
============================================================

Live agents from telemetry: 000, 001

agent=001  asset=None
   policy : fallback — No SCA data available
   pass   : 0/0 (50.0%)
   V score: 50.0

...
[OK] SCAFetcher demo complete.
```

#### Langkah 7 (Live Wazuh) — Buktikan Threat Hunting Fetcher berfungsi

```bash
python -m ingestion.threat_hunting
```

Output yang diharapkan:

```
============================================================
   ThreatHuntingFetcher - Demo / Smoke Test
============================================================

agent_id      : 001
total_hits    : N
level_groups  : {'low': N, 'medium': N, 'high': N, 'critical': N}
top_rules     :
   - 5710 (lvl=5) xN | sshd: Attempt to login using a non-existent user
...
[OK] ThreatHuntingFetcher demo complete.
```

#### Catatan operasional

Dokumen ini tidak lagi menggunakan mode dataset-only. Semua pembuktian difokuskan pada telemetry live Wazuh.

## Cara Pembaca Memakai Dokumen Ini

Gunakan dokumen ini sebagai panduan cepat saat:

1. Onboarding anggota tim backend baru.
2. Menjelaskan status kesiapan teknis ke pembimbing atau stakeholder.
3. Menyusun checklist validasi sebelum lanjut ke implementasi engine dan API.

## Penutup

Secara keseluruhan, update Sprint 1-2 telah berada di jalur yang benar untuk praktik industri: infrastruktur modular, integrasi telemetry live Wazuh, dan basis validasi scoring yang jelas. Fokus berikutnya adalah memastikan implementasi engine tetap konsisten dengan data operasional aktual.
