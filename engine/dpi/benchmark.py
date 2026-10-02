import subprocess
from pathlib import Path


class DPIBenchmark:
    def __init__(self, source_pcap: str):
        self.source_pcap = Path(source_pcap)

    def get_total_packets(self):
        result = subprocess.run(
            [
                "tshark",
                "-r",
                str(self.source_pcap),
                "-T",
                "fields",
                "-e",
                "frame.number",
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        return len([line for line in result.stdout.splitlines() if line.strip()])

    def get_total_bytes(self):
        result = subprocess.run(
            [
                "tshark",
                "-r",
                str(self.source_pcap),
                "-T",
                "fields",
                "-e",
                "frame.len",
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        return sum(
            int(line)
            for line in result.stdout.splitlines()
            if line.strip()
        )

    def get_selected_packets(self, frame_numbers):
        if not frame_numbers:
            return 0

        filters = " || ".join(
            f"frame.number == {frame}"
            for frame in sorted(set(frame_numbers))
        )

        result = subprocess.run(
            [
                "tshark",
                "-r",
                str(self.source_pcap),
                "-Y",
                filters,
                "-T",
                "fields",
                "-e",
                "frame.number",
                "-e",
                "frame.len",
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        packets = []

        for line in result.stdout.splitlines():
            if not line.strip():
                continue

            frame, length = line.split("\t")
            packets.append(
                {
                    "frame": int(frame),
                    "bytes": int(length),
                }
            )

        return packets

    def calculate_metrics(self, frame_numbers):
        total_packets = self.get_total_packets()
        total_bytes = self.get_total_bytes()

        selected = self.get_selected_packets(frame_numbers)

        selected_packets = len(selected)
        selected_bytes = sum(packet["bytes"] for packet in selected)

        packet_reduction = (
            (total_packets - selected_packets)
            / total_packets
            * 100
        )

        byte_reduction = (
            (total_bytes - selected_bytes)
            / total_bytes
            * 100
        )

        return {
            "total_packets": total_packets,
            "selected_packets": selected_packets,
            "total_bytes": total_bytes,
            "selected_bytes": selected_bytes,
            "packet_reduction_percent": packet_reduction,
            "byte_reduction_percent": byte_reduction,
        }


if __name__ == "__main__":
    benchmark = DPIBenchmark(
        "/workspace/dataset/evilprogram.pcap"
    )

    # Temporary test using the packets identified from
    # the current Suricata alerts.
    metrics = benchmark.calculate_metrics([7, 8, 9])

    print("\n=== SentinelChain Selective DPI Benchmark ===")
    print(f"Full packets       : {metrics['total_packets']}")
    print(f"Selected packets   : {metrics['selected_packets']}")
    print(f"Full bytes         : {metrics['total_bytes']}")
    print(f"Selected bytes     : {metrics['selected_bytes']}")
    print(
        f"Packet reduction   : "
        f"{metrics['packet_reduction_percent']:.2f}%"
    )
    print(
        f"Byte reduction     : "
        f"{metrics['byte_reduction_percent']:.2f}%"
    )
