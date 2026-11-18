import json
import urllib.request

from arm_soc_sbsa.boot.mock import BootStateMachine
from arm_soc_sbsa.redfish.service import RedfishService, create_server


def _drive():
    svc = RedfishService()
    sm = BootStateMachine()
    sm.on_milestone(svc.record_milestone)
    sm.run()
    return svc


def test_event_ordering():
    svc = _drive()
    ids = [e.id for e in svc.event_log.events]
    assert ids == sorted(ids) and ids[0] == 1
    milestones = [e.milestone for e in svc.event_log.events if e.milestone not in ("", "SERVICE")]
    assert milestones[-1] == "LOGIN"
    assert svc.system()["PowerState"] == "On"


def test_bios_attributes():
    svc = _drive()
    bios = svc.bios()
    assert bios["Attributes"]["BootMode"] == "Uefi"
    assert "CpuCount" in bios["Attributes"]


def test_http_endpoints():
    svc = _drive()
    server = create_server(svc, port=0)
    port = server.server_address[1]
    import threading
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        for path in ["/redfish/v1", "/redfish/v1/Systems/1", "/redfish/v1/Systems/1/Bios",
                     "/redfish/v1/Managers/1/LogServices/Sel/Entries"]:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as r:
                assert r.status == 200
                json.loads(r.read())
    finally:
        server.shutdown()
