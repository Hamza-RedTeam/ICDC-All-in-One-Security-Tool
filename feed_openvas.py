import xml.etree.ElementTree as ET
from core.database import init_db, log_finding

# Aapki OpenVAS report ka naam yahan likhein
REPORT_FILE = "openvas_report.xml"
TARGET_IP = "10.146.150.54"

def feed_report():
    init_db()
    try:
        tree = ET.parse(REPORT_FILE)
        root = tree.getroot()
        
        findings_count = 0
        # OpenVAS XML mein results <result> tag mein hote hain
        for result in root.findall(".//result"):
            name = result.find("name").text
            severity = result.find("severity").text
            host = result.find("host").text
            
            # Severity ko text mein convert karein
            sev_score = float(severity) if severity else 0.0
            if sev_score >= 7.0:
                sev_text = "critical"
            elif sev_score >= 4.0:
                sev_text = "high"
            else:
                sev_text = "medium"

            # Aapke tool ke database mein save karein
            log_finding("OpenVAS", host, sev_text, name)
            findings_count += 1

        print(f"[SUCCESS] {findings_count} findings OpenVAS se ICDC tool mein save ho gayi!")
        
    except Exception as e:
        print(f"[ERROR] Report read nahi ho saki: {e}")

if __name__ == "__main__":
    feed_report()
