"""
EMULATED actuation endpoint (per dec_01KVWZV01Z23GWW41451NH96X6: M4-only, NO physical hardware).

`HAVirtualDevice` mirrors a Home Assistant `input_boolean` virtual device: an entity with state
"on"/"off" and the turn_on / turn_off / toggle services, recording every state transition with a
timestamp (a "logged command", exactly the emulated-actuation model the PI ratified). We NEVER claim
physical actuation.

`HARestActuator` is a drop-in for a LIVE Home Assistant instance (set base_url + long-lived token);
it speaks HA's /api/services/<domain>/<service> REST endpoint. The pipeline selects whichever is
configured; the formal property — not the actuation substrate — carries the contribution.
"""
from __future__ import annotations
import time
from dataclasses import dataclass, field


@dataclass
class HAVirtualDevice:
    entity_id: str = "input_boolean.front_door"
    state: str = "off"
    transitions: list[dict] = field(default_factory=list)

    _SERVICES = {"turn_on": "on", "turn_off": "off"}

    def call_service(self, command: str) -> dict:
        """Apply an HA service call to the virtual device; record and return the transition."""
        prev = self.state
        if command in self._SERVICES:
            self.state = self._SERVICES[command]
        elif command == "toggle":
            self.state = "on" if self.state == "off" else "off"
        else:
            raise ValueError(f"unknown input_boolean service: {command}")
        t = {"entity_id": self.entity_id, "service": command,
             "from": prev, "to": self.state, "ts": time.time(), "emulated": True}
        self.transitions.append(t)
        return t


class HARestActuator:
    """Live-Home-Assistant adapter, drop-in for HAVirtualDevice in QuorumActuationPipeline. Binds one
    entity_id and exposes the same call_service(command) interface, so selecting it drives a REAL device
    (e.g. a smart plug) through the full verified pipeline. Requires `requests` and a live HA instance.

    Config via env: HA_URL, HA_TOKEN, HA_ENTITY (see scripts/run_real_device.py). We keep the emulated
    path as the default; using this adapter is the only difference between emulated and physical actuation.
    """

    def __init__(self, base_url: str, token: str, entity_id: str, http=None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.entity_id = entity_id
        self.transitions: list[dict] = []
        self._http = http  # injectable for testing; defaults to `requests`

    def call_service(self, command: str) -> dict:
        domain = self.entity_id.split(".")[0]
        url = f"{self.base_url}/api/services/{domain}/{command}"
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        payload = {"entity_id": self.entity_id}
        http = self._http
        if http is None:
            import requests  # lazy; not needed for the emulated path
            http = requests
        r = http.post(url, headers=headers, json=payload, timeout=5)
        r.raise_for_status()
        t = {"entity_id": self.entity_id, "service": command, "url": url,
             "status": getattr(r, "status_code", None), "live": True}
        self.transitions.append(t)
        return t


if __name__ == "__main__":
    dev = HAVirtualDevice()
    print(dev.call_service("turn_on"))
    print(dev.call_service("toggle"))
