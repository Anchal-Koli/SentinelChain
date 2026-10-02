import subprocess
from pathlib import Path


class DPIExtractor:
    """Extract packets associated with a Suricata alert from a PCAP."""

    def __init__(self, source_pcap: str, output_dir: str):
        self.source_pcap = Path(source_pcap)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def extract_by_frame(self, frame_number: int, output_name: str) -> Path:
        """Extract one packet/frame from the source PCAP."""

        if not self.source_pcap.exists():
            raise FileNotFoundError(
                f"Source PCAP not found: {self.source_pcap}"
            )

        output_path = self.output_dir / output_name

        command = [
            "tshark",
            "-r",
            str(self.source_pcap),
            "-Y",
            f"frame.number == {frame_number}",
            "-w",
            str(output_path),
        ]

        subprocess.run(command, check=True)

        return output_path

    def extract_for_alert(
        self,
        src_ip: str,
        dst_ip: str,
        alert_epoch: float,
        window_seconds: int = 5,
        output_name: str = "alert_slice.pcap",
    ) -> Path:
        """Extract packets around a Suricata alert timestamp."""

        if not self.source_pcap.exists():
            raise FileNotFoundError(
                f"Source PCAP not found: {self.source_pcap}"
            )

        output_path = self.output_dir / output_name

        start = alert_epoch - window_seconds
        end = alert_epoch + window_seconds

        display_filter = (
            f"ip.addr == {src_ip} && "
            f"ip.addr == {dst_ip} && "
            f"frame.time_epoch >= {start} && "
            f"frame.time_epoch <= {end}"
        )

        command = [
            "tshark",
            "-r",
            str(self.source_pcap),
            "-Y",
            display_filter,
            "-w",
            str(output_path),
        ]

        subprocess.run(command, check=True)

        return output_path
