#!/usr/bin/env bash
# Download public attack-scenario PCAP datasets into this directory.
#
# Sources:
#   - NETRESEC MACCDC 2012 (port scans, brute force, C2, DDoS)
#   - Suricata-verify test captures (varied attack protocols)
#   - Canadian Institute for Cybersecurity (CICIDS 2017 samples)
#   - ICS/SCADA attack captures (automayt/ICS-pcap)
#
# Usage:
#   cd data/
#   ./download_attack_pcaps.sh            # download all
#   ./download_attack_pcaps.sh cicids     # only CICIDS subset

set -euo pipefail

OUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[done]${NC} $*"; }
info() { echo -e "${YELLOW}[info]${NC} $*"; }
fail() { echo -e "${RED}[fail]${NC} $*"; }

fetch_zip() {
    local url="$1" label="$2" pattern="$3"
    info "Downloading ${label}..."
    local zip="${TMP_DIR}/${label}.zip"
    if curl -sL --max-time 120 -o "$zip" "$url"; then
        local found
        found=$(unzip -l "$zip" 2>/dev/null | grep -cE "$pattern" || echo "0")
        if [ "$found" -gt 0 ]; then
            unzip -qj "$zip" "*${pattern#\*}" -d "$OUT_DIR" 2>/dev/null || \
                unzip -q "$zip" -d "${TMP_DIR}/${label}_extracted" && \
                find "${TMP_DIR}/${label}_extracted" -name "*.pcap" -o -name "*.pcapng" \
                    | xargs -I{} cp {} "$OUT_DIR/" 2>/dev/null || true
            ok "${label}: extracted ${found} capture(s)"
        else
            fail "${label}: no .pcap files found in archive"
        fi
    else
        fail "${label}: download failed (check network)"
    fi
}

fetch_single() {
    local url="$1" out="$2" label="$3"
    info "Downloading ${label}..."
    if curl -sL --max-time 60 -o "${OUT_DIR}/${out}" "$url"; then
        local size; size=$(wc -c < "${OUT_DIR}/${out}")
        [ "$size" -gt 100 ] && ok "${label}: ${out} (${size} bytes)" \
            || { rm -f "${OUT_DIR}/${out}"; fail "${label}: file too small, removed"; }
    else
        fail "${label}: download failed"
    fi
}

# ── Suricata test captures (varied protocols + attacks) ───────────────────────
download_suricata() {
    fetch_zip \
        "https://github.com/jasonish/suricata-verify/archive/refs/heads/master.zip" \
        "suricata-verify" \
        "\.pcap"
}

# ── ICS/SCADA attack PCAPs ────────────────────────────────────────────────────
download_ics() {
    fetch_zip \
        "https://github.com/automayt/ICS-pcap/archive/refs/heads/master.zip" \
        "ics-pcap" \
        "\.pcap"
}

# ── CICIDS 2017 – small labelled samples (University of New Brunswick) ─────────
# Full dataset requires manual download from:
# https://www.unb.ca/cic/datasets/ids-2017.html
download_cicids() {
    info "CICIDS 2017: full dataset requires manual download from:"
    info "  https://www.unb.ca/cic/datasets/ids-2017.html"
    info "  Contains: DoS, DDoS, PortScan, Brute Force, Web attacks, Botnets"
    info "  Place the extracted .pcap files in: ${OUT_DIR}/"
}

# ── NETRESEC – MACCDC 2012 competition traffic ─────────────────────────────────
# Requires registration but first sample is free:
download_netresec() {
    info "NETRESEC MACCDC 2012: registration required — visit:"
    info "  https://www.netresec.com/?page=MACCDC"
    info "  Contains: real competition traffic with attacks and normal traffic"
}

# ── Main ──────────────────────────────────────────────────────────────────────
FILTER="${1:-all}"

echo ""
echo "Attack PCAP downloader — saving to: ${OUT_DIR}"
echo "────────────────────────────────────────────────"

case "$FILTER" in
    suricata) download_suricata ;;
    ics)      download_ics ;;
    cicids)   download_cicids ;;
    netresec) download_netresec ;;
    all)
        download_suricata
        download_ics
        download_cicids
        download_netresec
        ;;
    *)
        echo "Usage: $0 [all|suricata|ics|cicids|netresec]"
        exit 1
        ;;
esac

echo ""
echo "Files in ${OUT_DIR}:"
ls -lh "${OUT_DIR}"/*.pcap "${OUT_DIR}"/*.pcapng 2>/dev/null | awk '{print "  "$NF, $5}' || true
echo ""
