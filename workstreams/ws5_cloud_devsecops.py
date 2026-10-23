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
