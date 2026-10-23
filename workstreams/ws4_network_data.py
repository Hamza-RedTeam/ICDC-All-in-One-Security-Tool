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
