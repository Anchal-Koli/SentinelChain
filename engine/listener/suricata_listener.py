import json
from pathlib import Path
from .event import NetworkEvent


class SuricataListener:

    def __init__(self, eve_path: str):
        self.eve_path = Path(eve_path)

    def read_alerts(self):
        if not self.eve_path.exists():
            raise FileNotFoundError(
                f"Suricata eve.json not found: {self.eve_path}"
            )

        events = []

        with self.eve_path.open("r", encoding="utf-8") as file:

            for line in file:

                line = line.strip()

                if not line:
                    continue

                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if data.get("event_type") != "alert":
                    continue

                alert = data.get("alert", {})

                event = NetworkEvent(
                    event_id=(
                        f"suricata-{data.get('flow_id')}-"
                        f"{data.get('timestamp', '').replace(':', '-').replace('.', '-')}"
                    ),
                    timestamp=data.get("timestamp", ""),
                    source="suricata",

                    src_ip=data.get("src_ip"),
                    src_port=data.get("src_port"),

                    dst_ip=data.get("dest_ip"),
                    dst_port=data.get("dest_port"),

                    protocol=data.get("proto"),

                    event_type="alert",

                    severity=alert.get("severity"),
                    signature=alert.get("signature"),

                    mitre_id=None
                )

                events.append(event)

        return events