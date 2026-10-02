from datetime import datetime
from engine.listener.suricata_listener import SuricataListener
from engine.dpi.extractor import DPIExtractor


EVE_PATH = "/workspace/capture/suricata_logs/eve.json"
SOURCE_PCAP = "/workspace/dataset/evilprogram.pcap"
OUTPUT_DIR = "/workspace/capture/dpi_slices"


def timestamp_to_epoch(timestamp: str) -> float:
    dt = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")
    return dt.timestamp()


def main():
    listener = SuricataListener(EVE_PATH)

    events = listener.read_alerts()

    extractor = DPIExtractor(
        SOURCE_PCAP,
        OUTPUT_DIR
    )

    print(f"Alerts received: {len(events)}")

    for index, event in enumerate(events, start=1):

        alert_epoch = timestamp_to_epoch(event.timestamp)

        output_name = f"alert_{index}_{event.event_id}.pcap"

        output = extractor.extract_for_alert(
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            alert_epoch=alert_epoch,
            window_seconds=5,
            output_name=output_name
        )

        print(f"[DPI] {event.event_id}")
        print(f"      → {output}")


if __name__ == "__main__":
    main()
