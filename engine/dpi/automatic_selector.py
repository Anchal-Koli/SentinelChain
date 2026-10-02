import subprocess
from datetime import datetime
from pathlib import Path

from engine.listener.suricata_listener import SuricataListener


EVE_PATH = "/workspace/capture/suricata_logs/eve.json"
SOURCE_PCAP = "/workspace/dataset/evilprogram.pcap"
OUTPUT_DIR = "/workspace/capture/dpi_slices"
OUTPUT_PCAP = "/workspace/capture/dpi_slices/selective_evidence.pcap"


def timestamp_to_epoch(timestamp: str) -> float:
    dt = datetime.strptime(
        timestamp,
        "%Y-%m-%dT%H:%M:%S.%f%z"
    )
    return dt.timestamp()


def find_matching_frames(event, window_seconds=5):
    alert_epoch = timestamp_to_epoch(event.timestamp)

    start = alert_epoch - window_seconds
    end = alert_epoch + window_seconds

    display_filter = (
        f"ip.addr == {event.src_ip} && "
        f"ip.addr == {event.dst_ip} && "
        f"frame.time_epoch >= {start} && "
        f"frame.time_epoch <= {end}"
    )

    result = subprocess.run(
        [
            "tshark",
            "-r",
            SOURCE_PCAP,
            "-Y",
            display_filter,
            "-T",
            "fields",
            "-e",
            "frame.number",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    frames = []

    for line in result.stdout.splitlines():
        if line.strip():
            frames.append(int(line.strip()))

    return frames


def create_evidence_pcap(frame_numbers):
    if not frame_numbers:
        raise RuntimeError("No packets were selected.")

    unique_frames = sorted(set(frame_numbers))

    display_filter = " || ".join(
        f"frame.number == {frame}"
        for frame in unique_frames
    )

    output_path = Path(OUTPUT_PCAP)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    subprocess.run(
        [
            "tshark",
            "-r",
            SOURCE_PCAP,
            "-Y",
            display_filter,
            "-w",
            str(output_path),
        ],
        check=True,
    )

    return output_path, unique_frames


def main():
    listener = SuricataListener(EVE_PATH)
    events = listener.read_alerts()

    print("=== SentinelChain Automatic Selective DPI ===")
    print(f"Alerts detected: {len(events)}")

    all_frames = set()

    for index, event in enumerate(events, start=1):
        frames = find_matching_frames(event)

        print(
            f"Alert {index}: "
            f"{event.event_id}"
        )
        print(f"  Matching frames: {frames}")

        all_frames.update(frames)

    output_path, unique_frames = create_evidence_pcap(all_frames)

    print("\n=== RESULT ===")
    print(f"Unique selected frames: {unique_frames}")
    print(f"Unique packet count: {len(unique_frames)}")
    print(f"Evidence PCAP: {output_path}")


if __name__ == "__main__":
    main()
