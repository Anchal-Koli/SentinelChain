from dataclasses import dataclass
from typing import Optional


@dataclass
class NetworkEvent:
    event_id: str
    timestamp: str

    source: str

    src_ip: Optional[str]
    src_port: Optional[int]

    dst_ip: Optional[str]
    dst_port: Optional[int]

    protocol: Optional[str]

    event_type: str

    severity: Optional[int]
    signature: Optional[str]

    mitre_id: Optional[str] = None
