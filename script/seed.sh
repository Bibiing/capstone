#!/usr/bin/env bash
# =============================================================================
#   1. Memverifikasi prasyarat (Docker, .env, Python venv)
#   2. Menunggu PostgreSQL siap menerima koneksi
#   3. Menjalankan dummy generator jika file output belum ada
#   4. Menjalankan ingestor untuk bulk insert ke PostgreSQL
#
# Penggunaan:
#   bash script/seed.sh                        # jalankan semua langkah
#   bash script/seed.sh --skip-generate        # lewati generator (pakai JSON yg ada)
#   bash script/seed.sh --dry-run              # hanya generate, tidak insert ke DB
#
# Prasyarat:
#   - Docker Compose sudah dijalankan: docker compose up -d
#   - File .env sudah ada di root proyek (salin dari .env.example)
# =============================================================================

set -euo pipefail   # exit on error, undefined vars, pipe failure

# ---------------------------------------------------------------------------
# Warna output terminal
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "${BLUE}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
die()     { error "$*"; exit 1; }

# ---------------------------------------------------------------------------
# Konstanta dan path
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${PROJECT_ROOT}/.env"
VENV_DIR="${PROJECT_ROOT}/.venv"
GENERATOR_DIR="${PROJECT_ROOT}/dummy_generator"
OUTPUT_DIR="${GENERATOR_DIR}/output"
INGESTOR_DIR="${PROJECT_ROOT}/ingestor"

SKIP_GENERATE=false
DRY_RUN=false

# ---------------------------------------------------------------------------
# Parse argumen
# ---------------------------------------------------------------------------
for arg in "$@"; do
  case "$arg" in
    --skip-generate) SKIP_GENERATE=true ;;
    --dry-run)       DRY_RUN=true ;;
    --help|-h)
      echo "Penggunaan: $0 [--skip-generate] [--dry-run]"
      echo "  --skip-generate  Lewati langkah generate data dummy"
      echo "  --dry-run        Hanya generate JSON, tidak insert ke DB"
      exit 0
      ;;
    *) warn "Argumen tidak dikenal '$arg' — diabaikan" ;;
  esac
done

# ---------------------------------------------------------------------------
# 1. Verifikasi prasyarat
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}====================================================${RESET}"
echo -e "${BOLD}  Cyber Risk Scoring — Database Seed Script${RESET}"
echo -e "${BOLD}====================================================${RESET}"
echo ""

info "Langkah 1/5: Verifikasi prasyarat..."

# File .env harus ada
if [[ ! -f "${ENV_FILE}" ]]; then
  die ".env tidak ditemukan di ${PROJECT_ROOT}. Salin dari .env.example:\n  cp .env.example .env"
fi
success ".env ditemukan"

# Load variabel env
# Export setiap variabel yang tidak kosong dari .env ke environment shell ini.
# Baris komentar (diawali #) dan baris kosong diabaikan.
set -o allexport
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +o allexport
success "Variabel environment dimuat dari .env"

# Docker harus tersedia
if ! command -v docker &>/dev/null; then
  die "Docker tidak ditemukan. Install Docker terlebih dahulu."
fi
success "Docker tersedia: $(docker --version | head -1)"

# Python / venv harus ada
PYTHON_BIN=""
if [[ -x "${VENV_DIR}/bin/python3" ]]; then
  PYTHON_BIN="${VENV_DIR}/bin/python3"
  success "Python venv ditemukan: ${PYTHON_BIN}"
elif command -v python3 &>/dev/null; then
  PYTHON_BIN="$(command -v python3)"
  warn "Venv tidak ditemukan, menggunakan system python3: ${PYTHON_BIN}"
else
  die "python3 tidak ditemukan. Install Python 3.10+ atau buat venv di .venv/"
fi

# ---------------------------------------------------------------------------
# 2. Verifikasi container PostgreSQL
# ---------------------------------------------------------------------------
info "Langkah 2/5: Verifikasi container PostgreSQL..."

CONTAINER_NAME="${COMPOSE_PROJECT_NAME:-risk_scoring}_db"
# Gunakan nama hard-coded dari docker-compose.yml jika variabel tidak ada
CONTAINER_NAME="risk_scoring_db"

if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
  warn "Container '${CONTAINER_NAME}' tidak berjalan."
  info "Mencoba menjalankan docker compose..."
  cd "${PROJECT_ROOT}" && docker compose up -d postgres
fi

# ---------------------------------------------------------------------------
# 3. Tunggu PostgreSQL sampai healthy (max 60 detik)
# ---------------------------------------------------------------------------
info "Langkah 3/5: Menunggu PostgreSQL siap..."

PG_HOST="${POSTGRES_HOST:-localhost}"
PG_PORT="${POSTGRES_PORT:-5432}"
PG_USER="${POSTGRES_USER:-admin}"
PG_DB="${POSTGRES_DB:-risk_scoring}"

MAX_WAIT=60
WAIT_INTERVAL=3
elapsed=0

until docker exec "${CONTAINER_NAME}" pg_isready \
        -h "${PG_HOST}" -U "${PG_USER}" -d "${PG_DB}" &>/dev/null; do
  if (( elapsed >= MAX_WAIT )); then
    die "PostgreSQL tidak siap setelah ${MAX_WAIT} detik. Periksa container."
  fi
  info "  Menunggu PostgreSQL... (${elapsed}s / ${MAX_WAIT}s)"
  sleep "${WAIT_INTERVAL}"
  (( elapsed += WAIT_INTERVAL ))
done

success "PostgreSQL siap menerima koneksi"

# ---------------------------------------------------------------------------
# 4. Generate data dummy (opsional)
# ---------------------------------------------------------------------------
info "Langkah 4/5: Generate data dummy..."

if [[ "${SKIP_GENERATE}" == "true" ]]; then
  warn "--skip-generate aktif: melewati langkah generate"
else
  # Cek apakah semua 4 file output sudah ada
  EXPECTED_FILES=(
    "${OUTPUT_DIR}/events_normal.json"
    "${OUTPUT_DIR}/events_spike.json"
    "${OUTPUT_DIR}/events_vuln_cluster.json"
    "${OUTPUT_DIR}/events_remediation_decay.json"
  )
  MISSING=0
  for f in "${EXPECTED_FILES[@]}"; do
    [[ ! -f "$f" ]] && (( MISSING++ )) && warn "File tidak ada: $f"
  done

  if (( MISSING > 0 )); then
    info "Menjalankan dummy generator (${MISSING} file belum ada)..."
  else
    info "Semua file output sudah ada. Menjalankan ulang untuk data terbaru..."
  fi

  cd "${GENERATOR_DIR}"
  "${PYTHON_BIN}" generate_all.py
  cd "${PROJECT_ROOT}"

  success "Data dummy berhasil digenerate"
fi

# Validasi cepat file output
info "Memvalidasi skema file JSON output..."
"${PYTHON_BIN}" - <<'PYEOF'
import json, sys
from pathlib import Path

output_dir = Path(__file__).parent if '__file__' in dir() else Path('dummy_generator/output')
import os; output_dir = Path(os.environ.get('OUTPUT_DIR', 'dummy_generator/output'))

REQUIRED   = {'timestamp', 'asset_id', 'severity', 'category', 'event_type'}
VALID_CAT  = {'auth', 'malware', 'integrity', 'network'}
VALID_ET   = {'alert', 'vuln', 'control'}

files = sorted(output_dir.glob('events_*.json'))
if not files:
    print(f"[ERROR] Tidak ada file JSON di {output_dir}", file=sys.stderr)
    sys.exit(1)

total_violations = 0
for fpath in files:
    with open(fpath) as f:
        events = json.load(f)
    violations = []
    for i, ev in enumerate(events):
        miss = REQUIRED - ev.keys()
        if miss:
            violations.append(f"obj[{i}] MISSING: {miss}")
        sev = ev.get('severity')
        if not isinstance(sev, int) or isinstance(sev, bool) or not (1 <= sev <= 15):
            violations.append(f"obj[{i}] severity={sev!r} (harus int 1-15)")
        if ev.get('category') not in VALID_CAT:
            violations.append(f"obj[{i}] category={ev.get('category')!r}")
        if ev.get('event_type') not in VALID_ET:
            violations.append(f"obj[{i}] event_type={ev.get('event_type')!r}")
    if violations:
        print(f"[FAIL] {fpath.name}: {len(violations)} pelanggaran", file=sys.stderr)
        for v in violations[:5]:
            print(f"       {v}", file=sys.stderr)
        total_violations += len(violations)
    else:
        print(f"[PASS] {fpath.name}: {len(events)} events — skema valid")

if total_violations > 0:
    print(f"\n[ERROR] Total pelanggaran: {total_violations}", file=sys.stderr)
    sys.exit(1)
else:
    print(f"\nSemua file lolos validasi Data Contract.")
PYEOF

if [[ $? -ne 0 ]]; then
  die "Validasi skema gagal. Perbaiki file generator sebelum melanjutkan."
fi
success "Validasi skema: LULUS"

# ---------------------------------------------------------------------------
# 5. Ingest ke PostgreSQL
# ---------------------------------------------------------------------------
info "Langkah 5/5: Ingest data ke PostgreSQL..."

if [[ "${DRY_RUN}" == "true" ]]; then
  warn "--dry-run aktif: melewati ingest ke database"
  echo ""
  success "Dry run selesai. File JSON siap di: ${OUTPUT_DIR}"
  exit 0
fi

cd "${PROJECT_ROOT}"
"${PYTHON_BIN}" "${INGESTOR_DIR}/main.py" \
  --input-dir "${OUTPUT_DIR}" \
  --validate

INGESTOR_EXIT=$?
if [[ ${INGESTOR_EXIT} -ne 0 ]]; then
  die "Ingestor keluar dengan kode error ${INGESTOR_EXIT}."
fi

# ---------------------------------------------------------------------------
# Selesai
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}====================================================${RESET}"
success "Seeding selesai! Semua data berhasil dimasukkan ke database."
echo -e "${BOLD}====================================================${RESET}"
echo ""
info "Akses pgAdmin di   : http://localhost:5050"
info "  Email            : admin@risk.com"
info "  Password         : admin123"
echo ""
