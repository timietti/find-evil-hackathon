#!/usr/bin/env bash
#
# Bootstrap missing SIFT-OWL forensic tool dependencies on a SANS SIFT
# Workstation. Idempotent — running twice is a no-op.
#
# What this installs:
#   - YARA binary (`yara`) — for Phase 3 threat-hunt rules
#   - Volatility 2 (`vol.py`) — for Phase 2 Win7-x86 / WinXP memory support
#   - PECmd (Eric Zimmerman, .NET) — Win10/Win11 Prefetch parser
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

# YARA — for Phase 3 (yara_scan_extract / vol3_vadyarascan).
apt_install yara

# Volatility 2 — for Phase 2 Win7-x86 PAE + WinXP memory analysis.
# Ubuntu's `volatility` package ships v2.6 with Python 2 baked in.
apt_install volatility

# ---- 2. Eric Zimmerman EZ Tools (PECmd, SrumECmd) --------------------------
#
# These are .NET 6 builds. The official download is at
# https://ericzimmerman.github.io/ — concretely `Get-ZimmermanTools` from the
# linked PowerShell script. We skip the PS and just curl the latest release
# zip from the publisher's CDN. If you cannot reach the URL, drop the .dll
# into $EZ_DIR by hand instead.

install_ez_dll() {
    local tool="$1"           # e.g. "PECmd"
    local target="$EZ_DIR/${tool}.dll"
    if [[ -f "$target" ]]; then
        log "$tool already at $target"
        return
    fi
    warn "$tool missing — please download $tool.zip from"
    warn "    https://ericzimmerman.github.io/  (look for the 'net6' bundle)"
    warn "and unzip into $EZ_DIR/."
    warn "(the bootstrap script does not auto-download because the upstream"
    warn " CDN does not allow direct CLI access)"
}

sudo mkdir -p "$EZ_DIR"
install_ez_dll PECmd
install_ez_dll SrumECmd

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
[[ -f "$EZ_DIR/PECmd.dll" ]]        && echo "  PECmd.dll: present"            || warn "  PECmd.dll: MISSING"
[[ -f "$EZ_DIR/SrumECmd.dll" ]]     && echo "  SrumECmd.dll: present"         || warn "  SrumECmd.dll: MISSING"
[[ -d "$MEMBASE_DIR" ]]             && echo "  memory-baseliner: present"     || warn "  memory-baseliner: MISSING"

log "done."
