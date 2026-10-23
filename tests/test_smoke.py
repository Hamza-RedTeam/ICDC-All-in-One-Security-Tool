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
