"""OpenBMC-style Redfish shim (stdlib http.server only).

Resources:
  GET /redfish/v1
  GET /redfish/v1/Systems/1
  GET /redfish/v1/Systems/1/Bios          (attribute model + Settings)
  GET /redfish/v1/Systems/1/LogServices/EventLog/Entries
  GET /redfish/v1/Managers/1/LogServices/Sel/Entries   (alias)
  GET /redfish/v1/EventService/Events     (ordered milestone events)
Boot milestones drive PowerState and append ordered SEL entries.
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..boot.mock import Milestone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Event:
    id: int
    created: str
    message: str
    severity: str = "OK"
    milestone: str = ""

    def to_redfish(self) -> dict:
        return {
            "@odata.type": "#LogEntry.v1_9_0.LogEntry",
            "Id": str(self.id),
            "Name": f"Event {self.id}",
            "Created": self.created,
            "Message": self.message,
            "Severity": self.severity,
            "EntryType": "Event",
            "Milestone": self.milestone,
        }


@dataclass
class EventLog:
    events: list[Event] = field(default_factory=list)
    _next: int = 1

    def emit(self, message: str, milestone: str = "", severity: str = "OK") -> Event:
        e = Event(id=self._next, created=_now(), message=message, severity=severity, milestone=milestone)
        self._next += 1
        self.events.append(e)
        return e

    def entries(self) -> list[dict]:
        return [e.to_redfish() for e in self.events]


# Milestones that cross a threshold worth a SEL entry
_THRESHOLDS = {Milestone.BL31_EL3, Milestone.DXE, Milestone.ACPI_SMBIOS_HANDOFF, Milestone.LINUX_KERNEL, Milestone.LOGIN}


class RedfishService:
    def __init__(self):
        self.event_log = EventLog()
        self.milestones: list[str] = []
        self.power_state = "Off"
        self.bios_attributes = {
            "BootMode": "Uefi",
            "SecureBootEnable": False,
            "AcpiTableMode": "Full",
            "SmbiosVersion": "3.0",
            "CpuCount": 4,
            "NumaNodes": 1,
            "WatchdogEnable": True,
        }
        self.event_log.emit("Redfish service initialized", milestone="SERVICE")

    def record_milestone(self, m: Milestone) -> None:
        self.milestones.append(m.value)
        if m == Milestone.RESET:
            self.power_state = "PoweringOn"
        if m == Milestone.LOGIN:
            self.power_state = "On"
        if m in _THRESHOLDS:
            self.event_log.emit(f"Boot milestone reached: {m.value}", milestone=m.value)

    def snapshot(self) -> dict:
        return {
            "service_root": self.service_root(),
            "system": self.system(),
            "bios": self.bios(),
            "event_log": {"Members": self.event_log.entries(), "Members@odata.count": len(self.event_log.events)},
        }

    def service_root(self) -> dict:
        return {
            "@odata.id": "/redfish/v1", "@odata.type": "#ServiceRoot.v1_16_0.ServiceRoot",
            "Id": "RootService", "Name": "arm-soc-sbsa Redfish Shim", "RedfishVersion": "1.16.0",
            "UUID": "00000000-0000-4000-8000-000000000001",
            "Systems": {"@odata.id": "/redfish/v1/Systems"},
            "Managers": {"@odata.id": "/redfish/v1/Managers"},
            "EventService": {"@odata.id": "/redfish/v1/EventService"},
        }

    def system(self) -> dict:
        return {
            "@odata.id": "/redfish/v1/Systems/1", "@odata.type": "#ComputerSystem.v1_20_0.ComputerSystem",
            "Id": "1", "Name": "sbsa-ref mock", "Manufacturer": "SBSA Lab", "Model": "sbsa-ref (mock/QEMU)",
            "PowerState": self.power_state, "Status": {"State": "Enabled", "Health": "OK"},
            "BootMilestones": list(self.milestones),
            "Bios": {"@odata.id": "/redfish/v1/Systems/1/Bios"},
            "LogServices": {"@odata.id": "/redfish/v1/Systems/1/LogServices"},
            "ProcessorSummary": {"Count": 4, "Model": "Arm Neoverse (model)"},
            "MemorySummary": {"TotalSystemMemoryGiB": 2},
        }

    def bios(self) -> dict:
        return {
            "@odata.id": "/redfish/v1/Systems/1/Bios", "@odata.type": "#Bios.v1_2_2.Bios",
            "Id": "Bios", "Name": "BIOS Attributes",
            "AttributeRegistry": "BiosAttributeRegistryArm.1.0.0",
            "Attributes": dict(self.bios_attributes),
            "@Redfish.Settings": {"SettingsObject": {"@odata.id": "/redfish/v1/Systems/1/Bios/Settings"}},
        }


def create_server(service: RedfishService | None = None, host: str = "127.0.0.1", port: int = 8000) -> ThreadingHTTPServer:
    svc = service or RedfishService()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # quiet
            pass

        def _json(self, obj, code=200):
            body = json.dumps(obj, indent=2).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            routes = {
                "/redfish/v1": svc.service_root,
                "/redfish/v1/": svc.service_root,
                "/redfish/v1/Systems/1": svc.system,
                "/redfish/v1/Systems/1/Bios": svc.bios,
                "/redfish/v1/Systems/1/Bios/Settings": svc.bios,
            }
            if self.path in routes:
                return self._json(routes[self.path]())
            if self.path in ("/redfish/v1/Systems/1/LogServices/EventLog/Entries",
                             "/redfish/v1/Managers/1/LogServices/Sel/Entries",
                             "/redfish/v1/EventService/Events"):
                entries = svc.event_log.entries()
                return self._json({"@odata.type": "#LogEntryCollection.LogEntryCollection",
                                   "Members": entries, "Members@odata.count": len(entries)})
            if self.path == "/redfish/v1/Systems":
                return self._json({"Members": [{"@odata.id": "/redfish/v1/Systems/1"}], "Members@odata.count": 1})
            return self._json({"error": {"code": "Base.1.13.GeneralError", "message": "not found"}}, 404)

    server = ThreadingHTTPServer((host, port), Handler)
    server.service = svc  # type: ignore[attr-defined]
    return server
