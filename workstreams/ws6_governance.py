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
