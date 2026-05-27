#!/usr/bin/env bash
#
# Bootstrap missing SIFT-OWL forensic tool dependencies on a SANS SIFT
# Workstation. Idempotent — running twice is a no-op.
#
# What this installs:
#   - YARA binary (`yara`) — for Phase 3 threat-hunt rules
#   - ssdeep — for hash_file fuzzy-hash (optional)
#   - libscca-python3 — cross-platform Windows Prefetch parser used by
#     ezt_prefetch_parse. (PECmd is NOT installed for Linux — it refuses
#     to run with "Non-Windows platforms not supported due to the need
#     to load decompression specific Windows libraries". libscca's MAM /
#     XPRESS-Huffman decompressor is portable.)
#   - libesedb-python3 — cross-platform ESE database parser used by
#     ezt_srum_parse. (SrumECmd hits the same Linux guard as PECmd:
#     "Non-Windows platforms not supported due to the need to load ESI
#     specific Windows libraries". libesedb is portable.)
#   - Vol3 community symbol pack (~800 MB, cached at
#     /opt/sift-owl/vol3-symbols/windows.zip) — pre-converted JSON
#     symbols for every Windows kernel GUID Vol3 supports. Lets Vol3
#     run fully offline; speeds cold-start from ~30 s to ~5 s.
#     (Does NOT solve the Win7-x86 PAE [GAP] — that's a Vol3
#     `KernelPDBScanner` limitation, not a symbol-availability one.)
#   - Memory Baseliner (FSecureLABS) — process diff against a clean baseline
#
# Usage:
#   bash scripts/bootstrap_sift_tools.sh
#
# Pre-req: sudo without password (or interactive sudo). Already-present
# components are skipped without complaint.

set -euo pipefail

EZ_DIR="/opt/zimmermantools"
MEMBASE_DIR="/opt/memory-baseliner"

YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RESET='\033[0m'

log()  { printf "${GREEN}[bootstrap]${RESET} %s\n" "$*"; }
warn() { printf "${YELLOW}[bootstrap]${RESET} %s\n" "$*"; }

# ---- 1. APT packages -------------------------------------------------------

apt_install() {
    local pkg="$1"
    if dpkg -l "$pkg" >/dev/null 2>&1; then
        log "$pkg already installed"
    else
        log "installing $pkg ..."
        sudo apt-get install -y "$pkg"
    fi
}

# YARA — Phase 3 (yara_scan_extract / vol3_vadyarascan). Required.
apt_install yara

# ssdeep — Phase 3 hash_file fuzzy-hash. Optional (hash_file works without it).
apt_install ssdeep

# libscca — cross-platform Windows Prefetch parser. The Python bindings are
# packaged as libscca-python3 (system-wide) and libscca-python (pip). We
# install the system package so pyscca is available even without the venv.
apt_install libscca-python3

# libesedb — cross-platform ESE database parser for SRUM. Same story as
# libscca: apt package libesedb-python3 (system-wide), pip package
# libesedb-python (venv). SrumECmd is Linux-broken; libesedb is portable.
apt_install libesedb-python3

# Volatility 3 community symbol pack — pre-converted JSON symbols for
# every Windows kernel GUID Vol3 supports. Cached locally so Vol3 runs
# **fully offline** (no Microsoft Symbol Server round-trip per case).
# Speeds up cold-start `windows.info` from ~30 s to ~5 s on x64 images.
# ~800 MB.
#
# Vol3 reads .zip files in the symbol-dirs path directly — no extraction
# needed. The MCP wrapper auto-detects /opt/sift-owl/vol3-symbols and
# passes it via `-s` to every vol invocation (override:
# $SIFT_OWL_VOL3_SYMBOL_DIRS).
#
# Known limitation: this does NOT fix the Win7-x86 PAE [GAP] on nromanoff
# (STARK-APT). The pack contains the right ntkrpamp.pdb JSON, but Vol3's
# `KernelPDBScanner` on that specific PAE dump doesn't find a kernel
# signature to match against. That is a Vol3 framework limitation; only
# disk-side analysis works for nromanoff today.
VOL3_SYM_DIR="/opt/sift-owl/vol3-symbols"
VOL3_SYM_URL="https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip"
if [[ -f "$VOL3_SYM_DIR/windows.zip" ]]; then
    log "Vol3 symbol pack already at $VOL3_SYM_DIR/windows.zip"
else
    log "downloading Vol3 community symbol pack -> $VOL3_SYM_DIR/windows.zip ..."
    sudo mkdir -p "$VOL3_SYM_DIR"
    sudo chown "$(whoami)" "$VOL3_SYM_DIR"
    if ! wget -q --tries=2 --timeout=60 -O "$VOL3_SYM_DIR/windows.zip" "$VOL3_SYM_URL"; then
        warn "Vol3 symbol pack download FAILED — Win7-x86 PAE images will hit 'No suitable kernels'"
        warn "  manual retry: wget -O $VOL3_SYM_DIR/windows.zip $VOL3_SYM_URL"
    fi
fi

# ---- 2. EZ Tools — no longer fetched on Linux -----------------------------
#
# The two Linux-broken tools (PECmd v2026.5.0, SrumECmd v2026.5.0) have
# both been replaced with libyal libraries (libscca, libesedb). Older
# EZ Tools (MFTECmd, AppCompatCacheParser, EvtxECmd, AmcacheParser,
# RBCmd, JLECmd, RECmd, bstrings) still run fine via `dotnet` and are
# preinstalled in /opt/zimmermantools on the SIFT image — no extra
# download step required.

# ---- 3. Memory Baseliner ---------------------------------------------------

if [[ -d "$MEMBASE_DIR" ]]; then
    log "Memory Baseliner already at $MEMBASE_DIR"
else
    log "cloning Memory Baseliner into $MEMBASE_DIR ..."
    sudo git clone https://github.com/FSecureLABS/Memory-Baseliner "$MEMBASE_DIR" \
        || warn "git clone failed — set $MEMBASE_DIR manually"
fi

# ---- 4. Verify --------------------------------------------------------------

log "verification:"
command -v yara                     >/dev/null && echo "  yara: $(yara --version 2>&1 | head -1)" || warn "  yara: NOT on PATH"
command -v vol                      >/dev/null && echo "  vol  (Vol3):  $(vol --help 2>&1 | head -1)"   || warn "  vol (Vol3): NOT on PATH"
python3 -c "import pyscca"  2>/dev/null && echo "  pyscca  (libscca):  present" || warn "  pyscca:  NOT importable (apt: libscca-python3,  pip: libscca-python)"
python3 -c "import pyesedb" 2>/dev/null && echo "  pyesedb (libesedb): present" || warn "  pyesedb: NOT importable (apt: libesedb-python3, pip: libesedb-python)"
[[ -f "$VOL3_SYM_DIR/windows.zip" ]] && echo "  Vol3 symbol pack: $(du -h "$VOL3_SYM_DIR/windows.zip" | cut -f1)" || warn "  Vol3 symbol pack: MISSING — Win7-x86 PAE will fail"
[[ -d "$MEMBASE_DIR" ]]             && echo "  memory-baseliner: present"     || warn "  memory-baseliner: MISSING"

log "done."
