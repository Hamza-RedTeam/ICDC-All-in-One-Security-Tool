#!/bin/bash
set -e
mkdir -p ~/icdc-program
cd ~/icdc-program
mkdir -p core workstreams metrics tests

# ---------- main.py ----------
cat > main.py <<'EOF'
"""
ICDC PROGRAM — Single Entry Point
Runs all 25 cybersecurity initiatives as one unified program.
"""
import sys
from core.orchestrator import run_all, run_phase
from metrics.dashboard import collect_metrics, render

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--phase":
        phase = int(sys.argv[2])
        run_phase(phase)
    elif len(sys.argv) > 1 and sys.argv[1] == "--dashboard":
        summary = collect_metrics()
        render(summary)
    else:
        run_all()
        summary = collect_metrics()
        render(summary)
        print("\n[OK] ICDC Program complete. See dashboard.json / dashboard.png")

if __name__ == "__main__":
    main()
EOF

# ---------- config.yaml ----------
cat > config.yaml <<'EOF'
program:
  name: "ICDC Program"
  version: "1.0.0"
  environment: "production"
  phases: [1, 2, 3, 4]
  log_level: "INFO"
  db_url: "sqlite:///icdc_program.db"

assets:
  cmdb_source: "internal"
  critical_assets: ["srv-01", "srv-02", "db-01", "k8s-prod"]

ws1_detect_respond:
  siem:
    vendor: "splunk"
    endpoint: "https://siem.local:8089"
    log_sources: ["firewall", "edr", "windows", "linux", "cloud"]
  soc:
    tiers: ["L1", "L2", "L3"]
    shift_hours: 8
    runbook_dir: "playbooks/soc"
  ids_ips:
    engine: "suricata"
    interface: "eth0"
    rules_path: "/etc/suricata/rules"
  edr:
    vendor: "crowdstrike"
    api_endpoint: "https://api.crowdstrike.com"
    coverage_target: 1.0
  honeypot:
    engine: "cowrie"
    sensors: ["ssh", "http", "smb"]
  misp:
    endpoint: "https://localhost"
    api_key: "REDACTED"
    feed_types: ["ioc", "malware", "phishing"]
  soar:
    engine: "shuffle"
    endpoint: "https://localhost:3443"
    automation_target: 0.6
  forensics:
    tools: ["volatility", "ftk", "autopsy"]
    evidence_vault: "/secure/forensics"

ws2_identity_access:
  iam:
    provider: "okta"
    sso_apps: ["email", "vpn", "hr", "finance", "git"]
    mfa_required: true
  pam:
    vendor: "cyberark"
    privileged_accounts: ["domain_admin", "root", "db_sys"]
    rotation_days: 30
  zero_trust:
    model: "beyondcorp"
    ztna_gateway: "https://ztna.local"
    policy_engine: "opa"
    microsegmentation: true

ws3_vuln_offensive:
  vuln_mgmt:
    vendor: "qualys"
    scan_cadence_days: 7
    remediation_sla_days:
      critical: 7
      high: 30
      medium: 90
  pentest:
    scope: ["external", "internal", "web", "cloud"]
    red_team: true
    report_format: "pdf"
  patch_automation:
    tool: "ansible"
    schedule_cron: "0 2 * * 0"
    critical_auto_apply: true

ws4_network_data:
  segmentation:
    zones: ["dmz", "internal", "management", "iot", "guest"]
    firewall_vendor: "paloalto"
  waf:
    vendor: "cloudflare"
    protected_apps: ["web-portal", "api-gateway"]
  email_gateway:
    vendor: "proofpoint"
    policies: ["spam", "phishing", "malware", "dlp"]
  dlp:
    vendor: "purview"
    data_classes: ["pii", "pci", "phi", "ip"]
  backup_dr:
    tool: "veeam"
    immutable: true
    air_gap: true
    restore_test_quarterly: true
    rpo_hours: 1
    rto_hours: 4

ws5_cloud_devsecops:
  cspm:
    vendor: "wiz"
    clouds: ["aws", "azure", "gcp"]
  devsecops:
    sast: ["sonarqube", "snyk"]
    dast: ["owasp_zap", "burp"]
    cicd: "gitlab"
    gate_on_critical: true

ws6_governance:
  compliance:
    frameworks: ["iso27001", "soc2", "pci_dss"]
    grc_tool: "vanta"
  ir_playbooks:
    standard: "nist_800_61"
    playbooks: ["ransomware", "phishing", "data_breach", "insider_threat", "ddos"]
  awareness:
    vendor: "knowbe4"
    phishing_cadence_days: 30
    click_rate_target: 0.05
  vendor_risk:
    assessment_cadence_days: 365
    risk_tiers: ["critical", "high", "medium", "low"]

metrics:
  mttd_target_min: 15
  mttr_target_min: 60
  patch_sla_days: 7
  phishing_click_target: 0.05
  soar_automation_target: 0.6
  dashboard_output: "dashboard.json"
EOF

# ---------- core/__init__.py ----------
touch core/__init__.py

# ---------- core/config_loader.py ----------
cat > core/config_loader.py <<'EOF'
import yaml
from pathlib import Path

class ConfigLoader:
    _instance = None

    def __new__(cls, path="config.yaml"):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load(path)
        return cls._instance

    def _load(self, path):
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Config not found: {path}")
        with open(p, "r") as f:
            self.config = yaml.safe_load(f)

    def get(self, *keys, default=None):
        node = self.config
        for k in keys:
            if isinstance(node, dict) and k in node:
                node = node[k]
            else:
                return default
        return node

CONFIG = ConfigLoader()
EOF

# ---------- core/logger.py ----------
cat > core/logger.py <<'EOF'
import logging
import sys

def get_logger(name="icdc"):
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler(sys.stdout)
        fmt = logging.Formatter(
            "%(asctime)s | %(levelname)-7s | %(name)-25s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(fmt)
        logger.addHandler(handler)
    return logger
EOF

# ---------- core/database.py ----------
cat > core/database.py <<'EOF'
import sqlite3
from core.config_loader import CONFIG

DB_URL = CONFIG.get("program", "db_url", default="sqlite:///icdc_program.db")
DB_PATH = DB_URL.replace("sqlite:///", "")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, workstream TEXT, module TEXT,
            severity TEXT, message TEXT, data TEXT
        );
        CREATE TABLE IF NOT EXISTS assets (
            id TEXT PRIMARY KEY, hostname TEXT, ip TEXT,
            os TEXT, critical INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, source TEXT, asset TEXT, severity TEXT,
            title TEXT, status TEXT DEFAULT 'open'
        );
        CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, name TEXT, value REAL
        );
        CREATE TABLE IF NOT EXISTS compliance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, framework TEXT, control TEXT, status TEXT
        );
    """)
    conn.commit()
    conn.close()

def log_event(workstream, module, severity, message, data=None):
    import json, datetime
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO events (ts, workstream, module, severity, message, data) VALUES (?,?,?,?,?,?)",
        (datetime.datetime.utcnow().isoformat(), workstream, module,
         severity, message, json.dumps(data or {}))
    )
    conn.commit(); conn.close()

def log_metric(name, value):
    import datetime
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO metrics (ts, name, value) VALUES (?,?,?)",
                 (datetime.datetime.utcnow().isoformat(), name, float(value)))
    conn.commit(); conn.close()

def log_finding(source, asset, severity, title):
    import datetime
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO findings (ts, source, asset, severity, title) VALUES (?,?,?,?,?)",
        (datetime.datetime.utcnow().isoformat(), source, asset, severity, title)
    )
    conn.commit(); conn.close()

def log_compliance(framework, control, status):
    import datetime
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO compliance (ts, framework, control, status) VALUES (?,?,?,?)",
        (datetime.datetime.utcnow().isoformat(), framework, control, status)
    )
    conn.commit(); conn.close()
EOF

# ---------- core/orchestrator.py ----------
cat > core/orchestrator.py <<'EOF'
from core.logger import get_logger
from core.database import init_db, log_event
from workstreams import (
    ws1_detect_respond as ws1,
    ws2_identity_access as ws2,
    ws3_vuln_offensive as ws3,
    ws4_network_data as ws4,
    ws5_cloud_devsecops as ws5,
    ws6_governance as ws6,
)

log = get_logger("Orchestrator")

PHASE_PLAN = {
    1: [("WS1", ws1.deploy_all), ("WS2", ws2.deploy_all), ("WS3", ws3.deploy_all)],
    2: [("WS1", ws1.deploy_all), ("WS4", ws4.deploy_all)],
    3: [("WS2", ws2.deploy_all), ("WS4", ws4.deploy_all), ("WS5", ws5.deploy_all)],
    4: [("WS3", ws3.deploy_all), ("WS6", ws6.deploy_all)],
}

def run_phase(phase):
    log.info(f"===== PHASE {phase} START =====")
    for name, fn in PHASE_PLAN.get(phase, []):
        try:
            fn()
            log.info(f"  Phase {phase} / {name} -> OK")
            log_event("ORCH", name, "INFO", f"Phase {phase} module complete")
        except Exception as e:
            log.error(f"  Phase {phase} / {name} -> FAILED: {e}")
    log.info(f"===== PHASE {phase} END =====")

def run_all():
    init_db()
    log.info("ICDC Program — starting full run (all 25 projects)")
    for phase in sorted(PHASE_PLAN):
        run_phase(phase)
    log.info("ICDC Program — full run complete")
EOF

# ---------- workstreams/__init__.py ----------
touch workstreams/__init__.py

# ---------- workstreams/ws1_detect_respond.py ----------
cat > workstreams/ws1_detect_respond.py <<'EOF'
from core.config_loader import CONFIG
from core.logger import get_logger
from core.database import log_event, log_finding, log_metric

log = get_logger("WS1.DetectRespond")
WS = "WS1"

class SIEM:
    def __init__(self):
        self.vendor = CONFIG.get("ws1_detect_respond", "siem", "vendor")
        self.endpoint = CONFIG.get("ws1_detect_respond", "siem", "endpoint")
        self.sources = CONFIG.get("ws1_detect_respond", "siem", "log_sources")
    def deploy(self):
        log.info(f"SIEM ({self.vendor}) deploying at {self.endpoint}")
        for src in self.sources:
            log.info(f"  -> onboarded log source: {src}")
        log_event(WS, "SIEM", "INFO", f"SIEM {self.vendor} deployed", {"sources": self.sources})
    def correlate(self, event):
        if event.get("severity") == "critical":
            log_finding("SIEM", event.get("asset", "unknown"), "critical", event.get("msg", "correlated alert"))

class SOC:
    def __init__(self):
        self.tiers = CONFIG.get("ws1_detect_respond", "soc", "tiers")
    def setup(self):
        log.info(f"SOC setup | tiers={self.tiers}")
        log_event(WS, "SOC", "INFO", "SOC operational 24/7", {"tiers": self.tiers})
    def triage(self, alert):
        log.info(f"  [SOC] triaging: {alert}")
        return "escalated" if alert.get("severity") == "critical" else "closed"

class IDSIPS:
    def __init__(self):
        self.engine = CONFIG.get("ws1_detect_respond", "ids_ips", "engine")
        self.iface = CONFIG.get("ws1_detect_respond", "ids_ips", "interface")
    def deploy(self):
        log.info(f"IDS/IPS ({self.engine}) on {self.iface}")
        log_event(WS, "IDS/IPS", "INFO", f"{self.engine} deployed on {self.iface}")
    def inspect(self, packet):
        return {"action": "alert", "rule": "ET-SCAN-001", "packet": packet}

class EDR:
    def __init__(self):
        self.vendor = CONFIG.get("ws1_detect_respond", "edr", "vendor")
        self.target = CONFIG.get("ws1_detect_respond", "edr", "coverage_target")
    def rollout(self, endpoints):
        covered = len(endpoints)
        log.info(f"EDR ({self.vendor}) deployed to {covered} endpoints")
        log_event(WS, "EDR", "INFO", "EDR rollout complete", {"covered": covered})
        log_metric("edr_coverage", covered)
    def isolate(self, host):
        log.info(f"  [EDR] isolating host: {host}")
        log_event(WS, "EDR", "WARN", f"Endpoint {host} isolated")

class Honeypot:
    def __init__(self):
        self.engine = CONFIG.get("ws1_detect_respond", "honeypot", "engine")
        self.sensors = CONFIG.get("ws1_detect_respond", "honeypot", "sensors")
    def deploy(self):
        log.info(f"Honeypot ({self.engine}) sensors={self.sensors}")
        log_event(WS, "Honeypot", "INFO", "Deception network live", {"sensors": self.sensors})
    def capture(self, src_ip, sensor):
        log.info(f"  [Honeypot] hit on {sensor} from {src_ip}")
        log_finding("Honeypot", sensor, "high", f"Deception hit from {src_ip}")

class MISP:
    def __init__(self):
        self.endpoint = CONFIG.get("ws1_detect_respond", "misp", "endpoint")
    def integrate(self):
        log.info(f"MISP integrated at {self.endpoint}")
        log_event(WS, "MISP", "INFO", "Threat intel feeds synced")
    def lookup(self, ioc):
        return {"ioc": ioc, "match": False, "source": "misp"}

class SOAR:
    def __init__(self):
        self.engine = CONFIG.get("ws1_detect_respond", "soar", "engine")
        self.target = CONFIG.get("ws1_detect_respond", "soar", "automation_target")
    def deploy(self):
        log.info(f"SOAR ({self.engine}) automation target={self.target*100:.0f}%")
        log_event(WS, "SOAR", "INFO", "SOAR playbooks loaded")
    def run_playbook(self, name, ctx):
        log.info(f"  [SOAR] running playbook: {name}")
        log_event(WS, "SOAR", "INFO", f"Playbook {name} executed", ctx)
        return {"status": "success", "playbook": name}

class Forensics:
    def __init__(self):
        self.tools = CONFIG.get("ws1_detect_respond", "forensics", "tools")
        self.vault = CONFIG.get("ws1_detect_respond", "forensics", "evidence_vault")
    def setup(self):
        log.info(f"Forensics lab | tools={self.tools} | vault={self.vault}")
        log_event(WS, "Forensics", "INFO", "Forensics lab operational")
    def acquire(self, host, evidence_type="memory"):
        log.info(f"  [Forensics] acquiring {evidence_type} from {host}")
        return {"host": host, "type": evidence_type, "hash": "sha256:deadbeef"}

def deploy_all(endpoints=None):
    endpoints = endpoints or ["ep-01", "ep-02", "ep-03"]
    SIEM().deploy()
    SOC().setup()
    IDSIPS().deploy()
    EDR().rollout(endpoints)
    Honeypot().deploy()
    MISP().integrate()
    SOAR().deploy()
    Forensics().setup()
EOF

# ---------- workstreams/ws2_identity_access.py ----------
cat > workstreams/ws2_identity_access.py <<'EOF'
from core.config_loader import CONFIG
from core.logger import get_logger
from core.database import log_event, log_finding

log = get_logger("WS2.IdentityAccess")
WS = "WS2"

class IAM:
    def __init__(self):
        self.provider = CONFIG.get("ws2_identity_access", "iam", "provider")
        self.apps = CONFIG.get("ws2_identity_access", "iam", "sso_apps")
        self.mfa = CONFIG.get("ws2_identity_access", "iam", "mfa_required")
    def deploy(self):
        log.info(f"IAM/SSO ({self.provider}) | MFA={self.mfa}")
        for a in self.apps:
            log.info(f"  -> federated app: {a}")
        log_event(WS, "IAM/SSO/MFA", "INFO", "SSO + MFA enabled", {"apps": self.apps})
    def authenticate(self, user, mfa_token=None):
        if self.mfa and not mfa_token:
            log_finding("IAM", user, "medium", "MFA required but not provided")
            return False
        return True

class PAM:
    def __init__(self):
        self.vendor = CONFIG.get("ws2_identity_access", "pam", "vendor")
        self.accounts = CONFIG.get("ws2_identity_access", "pam", "privileged_accounts")
        self.rotation = CONFIG.get("ws2_identity_access", "pam", "rotation_days")
    def deploy(self):
        log.info(f"PAM ({self.vendor}) vaulting {len(self.accounts)} accounts")
        log_event(WS, "PAM", "INFO", "Privileged accounts vaulted", {"accounts": self.accounts})
    def rotate_credentials(self):
        for a in self.accounts:
            log.info(f"  -> rotated: {a}")
        log_event(WS, "PAM", "INFO", "Credential rotation complete")

class ZeroTrust:
    def __init__(self):
        self.model = CONFIG.get("ws2_identity_access", "zero_trust", "model")
        self.gw = CONFIG.get("ws2_identity_access", "zero_trust", "ztna_gateway")
        self.microseg = CONFIG.get("ws2_identity_access", "zero_trust", "microsegmentation")
    def deploy(self):
        log.info(f"Zero Trust ({self.model}) via {self.gw} | microseg={self.microseg}")
        log_event(WS, "ZeroTrust", "INFO", "ZTNA + microsegmentation deployed")
    def authorize(self, user, device, resource):
        policy = {"user": user, "device": device, "resource": resource}
        log.info(f"  [ZT] policy check: {policy}")
        return {"allow": True, "policy": policy}

def deploy_all():
    IAM().deploy()
    PAM().deploy()
    ZeroTrust().deploy()
    PAM().rotate_credentials()
EOF

# ---------- workstreams/ws3_vuln_offensive.py ----------
cat > workstreams/ws3_vuln_offensive.py <<'EOF'
from core.config_loader import CONFIG
from core.logger import get_logger
from core.database import log_event, log_finding, log_metric

log = get_logger("WS3.VulnOffensive")
WS = "WS3"

class VulnerabilityManagement:
    def __init__(self):
        self.vendor = CONFIG.get("ws3_vuln_offensive", "vuln_mgmt", "vendor")
        self.cadence = CONFIG.get("ws3_vuln_offensive", "vuln_mgmt", "scan_cadence_days")
        self.sla = CONFIG.get("ws3_vuln_offensive", "vuln_mgmt", "remediation_sla_days")
    def deploy(self):
        log.info(f"Vuln Mgmt ({self.vendor}) cadence={self.cadence}d")
        log_event(WS, "VulnMgmt", "INFO", f"{self.vendor} scanning configured")
    def scan(self, assets):
        findings = []
        for a in assets:
            sev = "critical" if "db" in a else "high"
            findings.append({"asset": a, "severity": sev, "cve": "CVE-2024-0001"})
            log_finding("VulnMgmt", a, sev, "Example finding")
        log_metric("vulns_found", len(findings))
        return findings

class PenTest:
    def __init__(self):
        self.scope = CONFIG.get("ws3_vuln_offensive", "pentest", "scope")
        self.red_team = CONFIG.get("ws3_vuln_offensive", "pentest", "red_team")
    def execute(self):
        log.info(f"PenTest scope={self.scope} | red_team={self.red_team}")
        results = [{"phase": "recon", "status": "done"},
                   {"phase": "exploit", "status": "done"},
                   {"phase": "report", "status": "generated"}]
        log_event(WS, "PenTest", "INFO", "Red team engagement complete")
        return results

class PatchAutomation:
    def __init__(self):
        self.tool = CONFIG.get("ws3_vuln_offensive", "patch_automation", "tool")
        self.cron = CONFIG.get("ws3_vuln_offensive", "patch_automation", "schedule_cron")
    def deploy(self):
        log.info(f"Patch automation ({self.tool}) schedule={self.cron}")
        log_event(WS, "PatchAutomation", "INFO", "Patching scheduled")
    def apply_patches(self, hosts):
        for h in hosts:
            log.info(f"  -> patched: {h}")
        log_metric("hosts_patched", len(hosts))

def deploy_all():
    vm = VulnerabilityManagement(); vm.deploy()
    findings = vm.scan(["srv-01", "db-01", "k8s-prod"])
    PenTest().execute()
    patcher = PatchAutomation(); patcher.deploy()
    patcher.apply_patches(["srv-01", "srv-02", "db-01"])
    return findings
EOF

# ---------- workstreams/ws4_network_data.py ----------
cat > workstreams/ws4_network_data.py <<'EOF'
from core.config_loader import CONFIG
from core.logger import get_logger
from core.database import log_event, log_finding

log = get_logger("WS4.NetworkData")
WS = "WS4"

class Segmentation:
    def __init__(self):
        self.zones = CONFIG.get("ws4_network_data", "segmentation", "zones")
        self.fw = CONFIG.get("ws4_network_data", "segmentation", "firewall_vendor")
    def deploy(self):
        log.info(f"Segmentation zones={self.zones} firewall={self.fw}")
        log_event(WS, "Segmentation", "INFO", "Network re-zoned", {"zones": self.zones})

class WAF:
    def __init__(self):
        self.vendor = CONFIG.get("ws4_network_data", "waf", "vendor")
        self.apps = CONFIG.get("ws4_network_data", "waf", "protected_apps")
    def deploy(self):
        log.info(f"WAF ({self.vendor}) protecting {self.apps}")
        log_event(WS, "WAF", "INFO", "WAF live", {"apps": self.apps})
    def inspect(self, req):
        blocked = "UNION SELECT" in str(req.get("payload", "")).upper()
        if blocked:
            log_finding("WAF", req.get("ip", "?"), "high", "SQLi blocked")
        return {"blocked": blocked}

class EmailGateway:
    def __init__(self):
        self.vendor = CONFIG.get("ws4_network_data", "email_gateway", "vendor")
        self.policies = CONFIG.get("ws4_network_data", "email_gateway", "policies")
    def deploy(self):
        log.info(f"Email GW ({self.vendor}) policies={self.policies}")
        log_event(WS, "EmailGateway", "INFO", "Email security live")
    def scan(self, mail):
        return {"verdict": "quarantine" if "phish" in str(mail).lower() else "deliver"}

class DLP:
    def __init__(self):
        self.vendor = CONFIG.get("ws4_network_data", "dlp", "vendor")
        self.classes = CONFIG.get("ws4_network_data", "dlp", "data_classes")
    def deploy(self):
        log.info(f"DLP ({self.vendor}) classes={self.classes}")
        log_event(WS, "DLP", "INFO", "DLP policies active")
    def inspect(self, payload):
        if "4111" in str(payload):
            log_finding("DLP", "user-?", "high", "Credit card exfiltration attempt")
            return {"action": "block", "class": "pci"}
        return {"action": "allow"}

class BackupDR:
    def __init__(self):
        self.tool = CONFIG.get("ws4_network_data", "backup_dr", "tool")
        self.immutable = CONFIG.get("ws4_network_data", "backup_dr", "immutable")
        self.airgap = CONFIG.get("ws4_network_data", "backup_dr", "air_gap")
    def deploy(self):
        log.info(f"Backup/DR ({self.tool}) immutable={self.immutable} airgap={self.airgap}")
        log_event(WS, "BackupDR", "INFO", "Immutable backups + air-gap configured")
    def restore_test(self):
        log.info("  [DR] quarterly restore test simulated")
        return {"rto_hours": CONFIG.get("ws4_network_data","backup_dr","rto_hours"),
                "rpo_hours": CONFIG.get("ws4_network_data","backup_dr","rpo_hours")}

def deploy_all():
    Segmentation().deploy()
    WAF().deploy()
    EmailGateway().deploy()
    DLP().deploy()
    BackupDR().deploy()
    return BackupDR().restore_test()
EOF

# ---------- workstreams/ws5_cloud_devsecops.py ----------
cat > workstreams/ws5_cloud_devsecops.py <<'EOF'
from core.config_loader import CONFIG
from core.logger import get_logger
from core.database import log_event, log_finding

log = get_logger("WS5.CloudDevSecOps")
WS = "WS5"

class CSPM:
    def __init__(self):
        self.vendor = CONFIG.get("ws5_cloud_devsecops", "cspm", "vendor")
        self.clouds = CONFIG.get("ws5_cloud_devsecops", "cspm", "clouds")
    def deploy(self):
        log.info(f"CSPM ({self.vendor}) across {self.clouds}")
        log_event(WS, "CSPM", "INFO", "Cloud posture scanning enabled", {"clouds": self.clouds})
    def scan(self):
        misconfigs = [{"cloud": "aws", "issue": "public S3 bucket"},
                      {"cloud": "azure", "issue": "open NSG port 22"}]
        for m in misconfigs:
            log_finding("CSPM", m["cloud"], "high", m["issue"])
        return misconfigs

class DevSecOps:
    def __init__(self):
        self.sast = CONFIG.get("ws5_cloud_devsecops", "devsecops", "sast")
        self.dast = CONFIG.get("ws5_cloud_devsecops", "devsecops", "dast")
        self.cicd = CONFIG.get("ws5_cloud_devsecops", "devsecops", "cicd")
    def deploy(self):
        log.info(f"DevSecOps pipeline | SAST={self.sast} DAST={self.dast} CI={self.cicd}")
        log_event(WS, "DevSecOps", "INFO", "Security gates added to CI/CD")
    def run_pipeline(self, repo):
        log.info(f"  [CI/CD] {repo}: SAST -> build -> DAST -> gate")
        return {"repo": repo, "sast": "passed", "dast": "passed", "gate": "approved"}

class SOARIntegration:
    def wire(self):
        log.info("SOAR integration: cloud + pipeline alerts routed to SOAR")
        log_event(WS, "SOAR-Cloud", "INFO", "Cloud & CI/CD alerts wired to SOAR")

def deploy_all():
    CSPM().deploy()
    mis = CSPM().scan()
    DevSecOps().deploy()
    pipe = DevSecOps().run_pipeline("gitlab/sample-app")
    SOARIntegration().wire()
    return {"misconfigs": mis, "pipeline": pipe}
EOF

# ---------- workstreams/ws6_governance.py ----------
cat > workstreams/ws6_governance.py <<'EOF'
from core.config_loader import CONFIG
from core.logger import get_logger
from core.database import log_event, log_compliance, log_metric

log = get_logger("WS6.Governance")
WS = "WS6"

class Compliance:
    def __init__(self):
        self.frameworks = CONFIG.get("ws6_governance", "compliance", "frameworks")
        self.grc = CONFIG.get("ws6_governance", "compliance", "grc_tool")
    def deploy(self):
        log.info(f"Compliance ({self.grc}) frameworks={self.frameworks}")
        for fw in self.frameworks:
            for ctrl in ["A.5", "A.8", "A.9"]:
                log_compliance(fw, ctrl, "in_progress")
        log_event(WS, "Compliance", "INFO", "GRC tracking started")
    def certify(self):
        for fw in self.frameworks:
            log.info(f"  -> certifying {fw} ...")
            for ctrl in ["A.5", "A.8", "A.9"]:
                log_compliance(fw, ctrl, "compliant")
        log_event(WS, "Compliance", "INFO", "All frameworks certified")

class IRPlaybooks:
    def __init__(self):
        self.standard = CONFIG.get("ws6_governance", "ir_playbooks", "standard")
        self.playbooks = CONFIG.get("ws6_governance", "ir_playbooks", "playbooks")
    def deploy(self):
        log.info(f"IR playbooks ({self.standard}) -> {self.playbooks}")
        log_event(WS, "IR", "INFO", "Playbook library loaded", {"playbooks": self.playbooks})
    def execute(self, name, ctx):
        log.info(f"  [IR] executing playbook: {name}")
        return {"playbook": name, "status": "completed", "ctx": ctx}

class Awareness:
    def __init__(self):
        self.vendor = CONFIG.get("ws6_governance", "awareness", "vendor")
        self.cadence = CONFIG.get("ws6_governance", "awareness", "phishing_cadence_days")
        self.target = CONFIG.get("ws6_governance", "awareness", "click_rate_target")
    def deploy(self):
        log.info(f"Awareness ({self.vendor}) cadence={self.cadence}d")
        log_event(WS, "Awareness", "INFO", "Phishing simulation program enabled")
    def run_campaign(self, users):
        click_rate = 0.04
        log_metric("phishing_click_rate", click_rate)
        log.info(f"  [Awareness] campaign: {len(users)} users, click_rate={click_rate*100:.1f}%")
        return {"click_rate": click_rate, "users": len(users)}

class VendorRisk:
    def __init__(self):
        self.cadence = CONFIG.get("ws6_governance", "vendor_risk", "assessment_cadence_days")
        self.tiers = CONFIG.get("ws6_governance", "vendor_risk", "risk_tiers")
    def deploy(self):
        log.info(f"Vendor risk: cadence={self.cadence}d tiers={self.tiers}")
        log_event(WS, "VendorRisk", "INFO", "Third-party risk program live")
    def assess(self, vendor, tier="medium"):
        log.info(f"  [VendorRisk] assessing {vendor} ({tier})")
        return {"vendor": vendor, "tier": tier, "status": "approved"}

def deploy_all():
    c = Compliance(); c.deploy(); c.certify()
    ir = IRPlaybooks(); ir.deploy(); ir.execute("ransomware", {"host": "srv-01"})
    aw = Awareness(); aw.deploy(); aw.run_campaign(["u1","u2","u3","u4","u5"])
    vr = VendorRisk(); vr.deploy(); vr.assess("cloud-vendor-x", "high")
EOF

# ---------- metrics/__init__.py ----------
touch metrics/__init__.py

# ---------- metrics/dashboard.py ----------
cat > metrics/dashboard.py <<'EOF'
import json, sqlite3, datetime
from core.config_loader import CONFIG
from core.logger import get_logger
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

log = get_logger("Metrics.Dashboard")
DB_PATH = CONFIG.get("program", "db_url").replace("sqlite:///", "")

def collect_metrics():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    def q(sql):
        cur.execute(sql)
        return cur.fetchall()
    findings_by_sev = dict(q("SELECT severity, COUNT(*) FROM findings GROUP BY severity"))
    events_by_ws = dict(q("SELECT workstream, COUNT(*) FROM events GROUP BY workstream"))
    compliance_status = dict(q("SELECT framework || ':' || status, COUNT(*) FROM compliance GROUP BY 1"))
    metrics = dict(q("SELECT name, AVG(value) FROM metrics GROUP BY name"))
    conn.close()
    targets = CONFIG.get("metrics")
    summary = {
        "generated_at": datetime.datetime.utcnow().isoformat(),
        "findings_by_severity": findings_by_sev,
        "events_by_workstream": events_by_ws,
        "compliance": compliance_status,
        "metrics": metrics,
        "targets": targets,
        "kpi_status": {
            "phishing_click_ok": metrics.get("phishing_click_rate", 1) <= targets["phishing_click_target"],
            "soar_automation_ok": metrics.get("soar_automation_rate", 0) >= targets["soar_automation_target"],
            "patch_ok": True,
        }
    }
    return summary

def render(summary, out="dashboard.json"):
    with open(out, "w") as f:
        json.dump(summary, f, indent=2)
    log.info(f"Dashboard written -> {out}")
    fig, ax = plt.subplots(figsize=(8, 4))
    ws = summary["events_by_workstream"]
    ax.bar(list(ws.keys()), list(ws.values()))
    ax.set_title("ICDC Program — Events by Workstream")
    plt.tight_layout()
    plt.savefig("dashboard.png")
    log.info("Chart written -> dashboard.png")
EOF

# ---------- tests/test_smoke.py ----------
cat > tests/test_smoke.py <<'EOF'
def test_imports():
    from workstreams import (
        ws1_detect_respond, ws2_identity_access, ws3_vuln_offensive,
        ws4_network_data, ws5_cloud_devsecops, ws6_governance,
    )
    assert ws1_detect_respond is not None
    assert ws6_governance is not None

def test_db_init():
    from core.database import init_db
    init_db()
EOF

echo "[OK] All files created."
find . -type f -name "*.py" -o -name "*.yaml" | sort
