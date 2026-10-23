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
