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
#   - Volatility 2 (`vol.py`) — for Phase 2 Win7-x86 / WinXP memory support
#   - SrumECmd (Eric Zimmerman, .NET) — Win8+ System Resource Usage Monitor
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

# Volatility 2 — for Phase 2 Win7-x86 PAE + WinXP memory analysis.
# Ubuntu's `volatility` package ships v2.6 with Python 2 baked in.
apt_install volatility

# ---- 2. Eric Zimmerman EZ Tools (SrumECmd only via Get-ZimmermanTools) ----
#
# Only SrumECmd is fetched here. PECmd was previously installed but its
# 2026.5.0+ build refuses to run on Linux:
#   "Non-Windows platforms not supported due to the need to load
#    decompression specific Windows libraries! Exiting..."
# ezt_prefetch_parse uses libscca (installed above) instead.

EZT_PS="https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1"

needs_ezt_install=0
for tool in SrumECmd; do
    if [[ ! -f "$EZ_DIR/${tool}.dll" ]]; then
        needs_ezt_install=1
        log "$tool: missing → will download"
    else
        log "$tool: already at $EZ_DIR/${tool}.dll"
    fi
done

if [[ "$needs_ezt_install" -eq 1 ]]; then
    if ! command -v pwsh >/dev/null; then
        warn "pwsh not on PATH — install PowerShell, then re-run this script."
        warn "  apt install -y powershell"
        exit 1
    fi
    sudo mkdir -p "$EZ_DIR"
    tmpdir="$(mktemp -d)"
    log "downloading Get-ZimmermanTools.ps1 → $tmpdir"
    python3 -c "
import urllib.request, sys
with urllib.request.urlopen('$EZT_PS', timeout=30) as r:
    sys.stdout.buffer.write(r.read())" > "$tmpdir/Get-ZimmermanTools.ps1"
    log "running official installer (-NetVersion 9, all tools) ..."
    pwsh -File "$tmpdir/Get-ZimmermanTools.ps1" -Dest "$tmpdir/tools" -NetVersion 9
    # Copy the tools we want (with their deps + .runtimeconfig.json + subdirs)
    for tool in SrumECmd; do
        src="$tmpdir/tools/net9/${tool}"
        if [[ -d "$src" ]]; then
            log "copying $tool from $src → $EZ_DIR/"
            sudo cp -r "$src"/* "$EZ_DIR/"
        else
            warn "$tool not found at $src — Get-ZimmermanTools layout may have changed."
            warn "  layout under $tmpdir/tools:"
            find "$tmpdir/tools" -maxdepth 3 -name "${tool}*" 2>/dev/null | sed 's/^/    /' || true
        fi
    done
    rm -rf "$tmpdir"
fi

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
command -v vol.py                   >/dev/null && echo "  vol.py (Vol2): $(vol.py --info 2>&1 | head -1)" || warn "  vol.py (Vol2): NOT on PATH"
python3 -c "import pyscca" 2>/dev/null  && echo "  pyscca (libscca): present"  || warn "  pyscca: NOT importable (apt: libscca-python3, pip: libscca-python)"
[[ -f "$EZ_DIR/SrumECmd.dll" ]]     && echo "  SrumECmd.dll: present"         || warn "  SrumECmd.dll: MISSING"
[[ -d "$MEMBASE_DIR" ]]             && echo "  memory-baseliner: present"     || warn "  memory-baseliner: MISSING"

log "done."
