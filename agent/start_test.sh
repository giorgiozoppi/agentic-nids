#!/usr/bin/env bash
# E2E test: NFStream → NATS → ClickHouse
#
# Lifecycle:
#   1. docker compose up -d        (start NATS + ClickHouse)
#   2. wait for both services
#   3. run NFStream → NATS tests
#   4. run NATS → ClickHouse test
#   5. docker compose down -v      (teardown)
#
# Idempotent: runs compose down at start to evict any stale containers.
#
# Usage:
#   ./start_test.sh
#   COMPOSE_FILE=/path/to/docker-compose.yml ./start_test.sh
#   CH_WAIT=120 ./start_test.sh    # extend ClickHouse readiness timeout

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-${SCRIPT_DIR}/docker-compose.yml}"
COMPOSE_CMD="docker compose -f ${COMPOSE_FILE}"

# ── Tunables ──────────────────────────────────────────────────────────────────
NATS_PORT="${NATS_PORT:-4222}"              # as exposed by docker compose
NATS_URL="nats://localhost:${NATS_PORT}"
NATS_SUBJECT="${NATS_SUBJECT:-test.flows}"
CH_HOST="${CH_HOST:-localhost}"
CH_PORT="${CH_PORT:-8123}"
CH_URL="http://${CH_HOST}:${CH_PORT}"
CH_DB="${CH_DB:-nids_test}"
CH_TABLE="${CH_TABLE:-flows}"
CH_WAIT="${CH_WAIT:-90}"        # max seconds to wait for ClickHouse readiness
# ClickHouse connects to NATS via the Docker network (service name)
NATS_DOCKER_URL="nats://nats:${NATS_PORT}"

PCAP_DIR="${SCRIPT_DIR}/../nfstream/tests/pcaps"
DATA_DIR="${SCRIPT_DIR}/../data"
TMP_DIR=$(mktemp -d)

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

PASS=0; FAIL=0

cleanup() {
    rm -rf "$TMP_DIR"
    echo -e "\n${YELLOW}[info]${NC} Tearing down infrastructure..."
    ${COMPOSE_CMD} down -v --remove-orphans 2>/dev/null || true
    echo -e "${YELLOW}[info]${NC} Done."
}
trap cleanup EXIT

section() { echo -e "\n${BOLD}${BLUE}━━ $* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }
log()  { echo -e "${BLUE}[....] $*${NC}"; }
ok()   { echo -e "${GREEN}[PASS]${NC} $*"; PASS=$((PASS + 1)); }
fail() { echo -e "${RED}[FAIL]${NC} $*"; FAIL=$((FAIL + 1)); }
info() { echo -e "${YELLOW}[info]${NC} $*"; }

ch_reachable() { curl -sf --max-time 2 "${CH_URL}/ping" >/dev/null; }
ch_query()     { curl -sf --max-time 15 "${CH_URL}" --data-binary "$1"; }

# ── Subscriber ────────────────────────────────────────────────────────────────
SUBSCRIBER="${TMP_DIR}/subscriber.py"
cat > "$SUBSCRIBER" << 'PYEOF'
import asyncio, signal, sys
async def main(url, subject, out):
    import nats
    nc = await nats.connect(url)
    count = 0
    stop = asyncio.Event()
    asyncio.get_event_loop().add_signal_handler(signal.SIGUSR1, stop.set)
    async def h(msg):
        nonlocal count; count += 1
    sub = await nc.subscribe(subject, cb=h)
    await stop.wait(); await asyncio.sleep(0.2)
    await sub.unsubscribe(); await nc.drain()
    open(out, "w").write(str(count))
asyncio.run(main(sys.argv[1], sys.argv[2], sys.argv[3]))
PYEOF

# ── 1. Prerequisites ──────────────────────────────────────────────────────────
check_prereqs() {
    section "Prerequisites"
    command -v docker &>/dev/null || { fail "docker not found"; exit 1; }
    info "docker      : $(docker --version)"
    command -v uv &>/dev/null || { fail "uv not found — see https://docs.astral.sh/uv/"; exit 1; }
    info "uv          : $(uv --version)"
    [ -f "$COMPOSE_FILE" ] || { fail "compose file missing: $COMPOSE_FILE"; exit 1; }
    info "compose     : $COMPOSE_FILE"
    [ -d "$PCAP_DIR" ] || { fail "PCAP dir missing: $PCAP_DIR"; exit 1; }
    info "pcap dir    : $PCAP_DIR"
    ok "Prerequisites OK"
}

# ── 2. Infrastructure ─────────────────────────────────────────────────────────
start_infra() {
    section "Infrastructure (docker compose)"

    # Idempotent: tear down any stale containers first
    info "Removing stale containers (if any)..."
    ${COMPOSE_CMD} down -v --remove-orphans 2>/dev/null || true

    info "Starting NATS + ClickHouse..."
    ${COMPOSE_CMD} up -d

    # Wait for NATS
    log "Waiting for NATS on port ${NATS_PORT}..."
    local waited=0
    until cd "$SCRIPT_DIR" && uv run python3 - "$NATS_URL" 2>/dev/null << 'PYEOF'
import asyncio, sys, nats
async def p(u):
    nc = await nats.connect(u); await nc.drain()
asyncio.run(p(sys.argv[1]))
PYEOF
    do
        [ "$waited" -ge 30 ] && { fail "NATS not ready after 30s"; exit 1; }
        sleep 1; waited=$((waited + 1))
    done
    ok "NATS ready (waited ${waited}s)"

    # Wait for ClickHouse
    log "Waiting for ClickHouse at ${CH_URL} (timeout ${CH_WAIT}s)..."
    waited=0
    until ch_reachable; do
        if [ "$waited" -ge "$CH_WAIT" ]; then
            fail "ClickHouse not ready after ${CH_WAIT}s"
            ${COMPOSE_CMD} logs clickhouse
            exit 1
        fi
        printf "."
        sleep 1; waited=$((waited + 1))
    done
    [ "$waited" -gt 0 ] && echo ""
    ok "ClickHouse ready (waited ${waited}s)"
}

# ── 3. Flow test helper ───────────────────────────────────────────────────────
run_flow_test() {
    local pcap="$1" expected="$2" label="$3"
    local count_file="${TMP_DIR}/cnt_${label//[^a-z0-9]/_}.txt"
    log "${label} — expecting ${expected} flow(s)"
    cd "$SCRIPT_DIR"
    uv run python3 "$SUBSCRIBER" "$NATS_URL" "$NATS_SUBJECT" "$count_file" &
    local sub=$!; sleep 0.3
    uv run nids-collector --pcap "$pcap" --nats-url "$NATS_URL" --subject "$NATS_SUBJECT" 2>/dev/null
    sleep 0.3; kill -USR1 "$sub" 2>/dev/null || true; wait "$sub" 2>/dev/null || true
    local actual; actual=$(cat "$count_file" 2>/dev/null || echo "0")
    [ "$actual" -eq "$expected" ] \
        && ok "${label}: ${actual}/${expected} flows" \
        || fail "${label}: got ${actual}, expected ${expected}"
}

# ── 4. Normal traffic ─────────────────────────────────────────────────────────
normal_traffic_tests() {
    section "Normal traffic  (NFStream → NATS)"
    run_flow_test "${PCAP_DIR}/443-chrome.pcap"               1  "tls/https chrome"
    run_flow_test "${PCAP_DIR}/android.pcap"                 63  "android mixed traffic"
    run_flow_test "${PCAP_DIR}/amqp.pcap"                     3  "amqp protocol"
    run_flow_test "${PCAP_DIR}/tls_certificate_too_long.pcap" 35 "tls oversized cert"
    # User-supplied datasets (data/ dir)
    if ls "${DATA_DIR}"/*.pcap 2>/dev/null | head -1 &>/dev/null; then
        for pcap in "${DATA_DIR}"/*.pcap; do
            local name; name=$(basename "$pcap" .pcap)
            # We don't know expected counts for user-supplied PCAPs:
            # just assert > 0 flows
            log "${name} (user dataset)"
            local count_file="${TMP_DIR}/cnt_user_${name}.txt"
            uv run python3 "$SUBSCRIBER" "$NATS_URL" "$NATS_SUBJECT" "$count_file" &
            local sub=$!; sleep 0.3
            uv run nids-collector --pcap "$pcap" --nats-url "$NATS_URL" --subject "$NATS_SUBJECT" 2>/dev/null
            sleep 0.3; kill -USR1 "$sub" 2>/dev/null || true; wait "$sub" 2>/dev/null || true
            local actual; actual=$(cat "$count_file" 2>/dev/null || echo "0")
            [ "$actual" -gt 0 ] && ok "${name}: ${actual} flows" || fail "${name}: 0 flows"
        done
    fi
}

# ── 5. Attack traffic ─────────────────────────────────────────────────────────
attack_traffic_tests() {
    section "Attack traffic  (NFStream → NATS)"
    run_flow_test "${PCAP_DIR}/synscan.pcap"             1994  "port scan — nmap SYN scan"
    run_flow_test "${PCAP_DIR}/malware.pcap"                5  "malware C2 traffic"
    run_flow_test "${PCAP_DIR}/WebattackSQLinj.pcap"        9  "web attack — SQL injection"
    run_flow_test "${PCAP_DIR}/WebattackXSS.pcap"         661  "web attack — XSS"
    run_flow_test "${PCAP_DIR}/dos_win98_smb_netbeui.pcap"  4  "DoS — SMB flood"
    run_flow_test "${PCAP_DIR}/ftp_failed.pcap"             1  "FTP brute-force attempt"
    run_flow_test "${PCAP_DIR}/ssh.pcap"                    2  "SSH session"
    run_flow_test "${PCAP_DIR}/smtp-starttls.pcap"          1  "SMTP STARTTLS"
}

# ── 6. NATS → ClickHouse ──────────────────────────────────────────────────────
clickhouse_test() {
    section "NATS → ClickHouse (end-to-end)"

    # Idempotent: drop test DB if it exists from a previous run
    ch_query "DROP DATABASE IF EXISTS ${CH_DB}" >/dev/null
    ch_query "CREATE DATABASE ${CH_DB}" >/dev/null

    # NATS engine table (ClickHouse connects to NATS via Docker network)
    ch_query "
CREATE TABLE ${CH_DB}.${CH_TABLE}_nats (
    collected_at             String,
    flow_id                  String,
    src_ip                   String,   dst_ip                   String,
    src_port                 UInt16,   dst_port                 UInt16,
    protocol                 UInt8,    ip_version               UInt8,
    bidirectional_first_seen_ms  UInt64, bidirectional_last_seen_ms  UInt64,
    bidirectional_duration_ms    UInt64,
    bidirectional_packets    UInt32,   bidirectional_bytes      UInt64,
    src2dst_packets          UInt32,   src2dst_bytes            UInt64,
    dst2src_packets          UInt32,   dst2src_bytes            UInt64,
    application_name         String,   application_category_name String,
    application_is_guessed   UInt8,    application_confidence   Float32,
    requested_server_name    String,
    packets_per_second       Float64,  bytes_per_second         Float64,
    bidirectional_min_ps     Float32,  bidirectional_mean_ps    Float32,
    bidirectional_stddev_ps  Float32,  bidirectional_max_ps     Float32,
    bidirectional_min_piat_ms    Float32, bidirectional_mean_piat_ms   Float32,
    bidirectional_stddev_piat_ms Float32, bidirectional_max_piat_ms    Float32,
    bidirectional_syn_packets    UInt32, bidirectional_ack_packets    UInt32,
    bidirectional_psh_packets    UInt32, bidirectional_rst_packets    UInt32,
    bidirectional_fin_packets    UInt32
) ENGINE = NATS
SETTINGS
    nats_url      = '${NATS_DOCKER_URL}',
    nats_subjects = '${NATS_SUBJECT}',
    nats_format   = 'MsgPack'
" >/dev/null

    ch_query "
CREATE TABLE ${CH_DB}.${CH_TABLE} (
    collected_at  DateTime,
    flow_id       String,
    src_ip        String,   dst_ip        String,
    src_port      UInt16,   dst_port      UInt16,
    protocol      UInt8,    ip_version    UInt8,
    bidirectional_first_seen_ms  UInt64, bidirectional_last_seen_ms  UInt64,
    bidirectional_duration_ms    UInt64,
    bidirectional_packets    UInt32,   bidirectional_bytes      UInt64,
    src2dst_packets          UInt32,   src2dst_bytes            UInt64,
    dst2src_packets          UInt32,   dst2src_bytes            UInt64,
    application_name         LowCardinality(String),
    application_category_name LowCardinality(String),
    application_is_guessed   UInt8,   application_confidence   Float32,
    requested_server_name    String,
    packets_per_second       Float64, bytes_per_second         Float64,
    bidirectional_min_ps     Float32, bidirectional_mean_ps    Float32,
    bidirectional_stddev_ps  Float32, bidirectional_max_ps     Float32,
    bidirectional_min_piat_ms    Float32, bidirectional_mean_piat_ms   Float32,
    bidirectional_stddev_piat_ms Float32, bidirectional_max_piat_ms    Float32,
    bidirectional_syn_packets    UInt32, bidirectional_ack_packets    UInt32,
    bidirectional_psh_packets    UInt32, bidirectional_rst_packets    UInt32,
    bidirectional_fin_packets    UInt32
) ENGINE = MergeTree()
ORDER BY (collected_at, src_ip, dst_ip)
" >/dev/null

    ch_query "
CREATE MATERIALIZED VIEW ${CH_DB}.${CH_TABLE}_mv TO ${CH_DB}.${CH_TABLE} AS
SELECT
    parseDateTime64BestEffort(collected_at) AS collected_at,
    flow_id, src_ip, dst_ip, src_port, dst_port, protocol, ip_version,
    bidirectional_first_seen_ms, bidirectional_last_seen_ms, bidirectional_duration_ms,
    bidirectional_packets, bidirectional_bytes,
    src2dst_packets, src2dst_bytes, dst2src_packets, dst2src_bytes,
    application_name, application_category_name, application_is_guessed,
    application_confidence, requested_server_name, packets_per_second, bytes_per_second,
    bidirectional_min_ps, bidirectional_mean_ps, bidirectional_stddev_ps, bidirectional_max_ps,
    bidirectional_min_piat_ms, bidirectional_mean_piat_ms,
    bidirectional_stddev_piat_ms, bidirectional_max_piat_ms,
    bidirectional_syn_packets, bidirectional_ack_packets,
    bidirectional_psh_packets, bidirectional_rst_packets, bidirectional_fin_packets
FROM ${CH_DB}.${CH_TABLE}_nats
" >/dev/null
    info "Schema applied (${CH_DB}.${CH_TABLE})"

    # Publish android.pcap (63) + synscan.pcap (1994) = 2057 total
    local expected=2057
    log "Publishing android.pcap + synscan.pcap (${expected} flows)..."
    cd "$SCRIPT_DIR"
    uv run nids-collector \
        --pcap "${PCAP_DIR}/android.pcap" \
        --nats-url "$NATS_URL" --subject "$NATS_SUBJECT" 2>/dev/null
    uv run nids-collector \
        --pcap "${PCAP_DIR}/synscan.pcap" \
        --nats-url "$NATS_URL" --subject "$NATS_SUBJECT" 2>/dev/null

    # Poll until rows appear (up to 30 s)
    local actual=0 poll=0
    while [ "$poll" -lt 30 ]; do
        actual=$(ch_query "SELECT count() FROM ${CH_DB}.${CH_TABLE}" 2>/dev/null \
                 | tr -d '[:space:]' || echo "0")
        [ "$actual" -ge "$expected" ] && break
        sleep 1; poll=$((poll + 1))
    done

    if [ "$actual" -ge "$expected" ]; then
        ok "ClickHouse: ${actual} rows (≥${expected} expected)"
        local syn
        syn=$(ch_query "SELECT count() FROM ${CH_DB}.${CH_TABLE} WHERE bidirectional_syn_packets > 0" \
              2>/dev/null | tr -d '[:space:]' || echo "0")
        info "  SYN-flagged flows: ${syn}"
        local apps
        apps=$(ch_query "SELECT application_name, count() AS n FROM ${CH_DB}.${CH_TABLE} GROUP BY application_name ORDER BY n DESC LIMIT 5 FORMAT TSV" \
               2>/dev/null || echo "(query failed)")
        info "  Top applications:"
        echo "$apps" | while IFS= read -r line; do info "    $line"; done
    else
        fail "ClickHouse: ${actual} rows after ${poll}s (expected ≥${expected})"
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════"
echo   "  NFStream → NATS → ClickHouse  e2e test suite"
echo -e "══════════════════════════════════════════════════${NC}"

check_prereqs
start_infra
normal_traffic_tests
attack_traffic_tests
clickhouse_test

echo ""
echo -e "${BOLD}══════════════════════════════════════════════════"
printf  "  Results: "
echo -e "${GREEN}${PASS} passed${NC}${BOLD}  ${RED}${FAIL} failed${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo ""

[ "$FAIL" -eq 0 ]
