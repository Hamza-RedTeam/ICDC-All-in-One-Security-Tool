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
