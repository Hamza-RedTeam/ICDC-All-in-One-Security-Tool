#!/bin/bash
# ============================================================
# ICDC FULL SCAN + FEED + RUN — ALL IN ONE
# Usage: ./full_attack.sh <TARGET_IP_or_URL>
# Example: ./full_attack.sh 192.168.56.101
# ============================================================

set -e

TARGET="${1:-192.168.56.101}"
OUTDIR="/root/icdc-program/recon_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

echo "=============================================="
echo "  ICDC FULL SCAN STARTED"
echo "  Target: $TARGET"
echo "  Output: $OUTDIR"
echo "=============================================="

# ---------- 1. NMAP FULL SCAN ----------
echo ""
echo "[1/6] Nmap full port + service + OS scan..."
nmap -sV -sC -O -p- -T4 "$TARGET" -oN "$OUTDIR/nmap_full.txt" || true

# ---------- 2. NMAP VULN SCAN ----------
echo ""
echo "[2/6] Nmap vulnerability scan..."
nmap -sV --script vuln "$TARGET" -oN "$OUTDIR/nmap_vuln.txt" || true

# ---------- 3. NIKTO WEB SCAN ----------
echo ""
echo "[3/6] Nikto web scan..."
if curl -s -o /dev/null -w "%{http_code}" "http://$TARGET" | grep -qE "200|301|302|403"; then
    nikto -h "http://$TARGET" -o "$OUTDIR/nikto.txt" || true
else
    echo "  [SKIP] No web server on http://$TARGET"
fi

# ---------- 4. GOBUSTER DIRECTORY SCAN ----------
echo ""
echo "[4/6] Gobuster directory scan..."
if [ -f /usr/share/wordlists/dirb/common.txt ]; then
    gobuster dir -u "http://$TARGET" -w /usr/share/wordlists/dirb/common.txt \
        -o "$OUTDIR/gobuster.txt" -q 2>/dev/null || true
else
    echo "  [SKIP] dirb wordlist not found. Install: sudo apt install dirb"
fi

# ---------- 5. OPENVAS / GVM CHECK ----------
echo ""
echo "[5/6] OpenVAS/GVM status check..."
if command -v gvm-cli &>/dev/null; then
    echo "  [OK] GVM installed. Web UI: https://127.0.0.1:9392"
    echo "  (Manual scan karna hoga browser mein)"
elif command -v omp &>/dev/null; then
    echo "  [OK] OpenVAS (omp) installed. Web UI: https://127.0.0.1:9392"
else
    echo "  [SKIP] OpenVAS/GVM not installed."
    echo "  Install karna ho to: sudo apt install -y gvm && sudo gvm-setup && sudo gvm-start"
fi

# ---------- 6. FEED RESULTS INTO ICDC DB ----------
echo ""
echo "[6/6] Feeding results into ICDC database..."
source /root/icdc-program/venv/bin/activate

python3 << PYEOF
import re, os, glob
from core.database import init_db, log_finding
from workstreams.ws3_vuln_offensive import VulnerabilityManagement

TARGET = "$TARGET"
OUTDIR = "$OUTDIR"

init_db()

total = 0

# --- Parse nmap vuln ---
vuln_file = os.path.join(OUTDIR, "nmap_vuln.txt")
if os.path.exists(vuln_file):
    with open(vuln_file, "r", errors="ignore") as f:
        content = f.read()
    for m in re.findall(r"\|.*VULNERABLE.*", content):
        log_finding("Nmap-Vuln", TARGET, "high", m.strip()[:200])
        total += 1
    for m in re.findall(r"CVE-\d{4}-\d+", content):
        log_finding("Nmap-CVE", TARGET, "critical", m)
        total += 1

# --- Parse nmap open ports ---
full_file = os.path.join(OUTDIR, "nmap_full.txt")
if os.path.exists(full_file):
    with open(full_file, "r", errors="ignore") as f:
        for line in f:
            m = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)", line)
            if m:
                port, proto, svc = m.groups()
                log_finding("Nmap-Port", TARGET, "info", f"{port}/{proto} open ({svc})")
                total += 1

# --- Parse nikto ---
nikto_file = os.path.join(OUTDIR, "nikto.txt")
if os.path.exists(nikto_file):
    with open(nikto_file, "r", errors="ignore") as f:
        for line in f:
            if line.startswith("+ ") and "OSVDB" in line:
                log_finding("Nikto", TARGET, "medium", line.strip()[:200])
                total += 1

# --- Parse gobuster ---
gb_file = os.path.join(OUTDIR, "gobuster.txt")
if os.path.exists(gb_file):
    with open(gb_file, "r", errors="ignore") as f:
        for line in f:
            if line.startswith("/"):
                parts = line.split()
                if parts:
                    log_finding("Gobuster", TARGET, "info", parts[0])
                    total += 1

# --- Simulate vuln mgmt scan into DB ---
vm = VulnerabilityManagement()
vm.scan([TARGET])

print(f"\n[+] Total findings saved: {total}")
PYEOF

# ---------- RUN ICDC TOOL ----------
echo ""
echo "[RUN] Starting ICDC Program..."
python /root/icdc-program/main.py

# ---------- SUMMARY ----------
echo ""
echo "=============================================="
echo "  ALL DONE!"
echo "  Scan results: $OUTDIR"
echo "  Database: /root/icdc-program/icdc_program.db"
echo "  Dashboard: /root/icdc-program/dashboard.json"
echo "=============================================="

ls -lh "$OUTDIR"
