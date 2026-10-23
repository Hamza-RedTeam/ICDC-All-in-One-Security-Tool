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
