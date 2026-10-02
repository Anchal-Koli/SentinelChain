from engine.listener.suricata_listener import SuricataListener


EVE_PATH = "/workspace/capture/suricata_logs/eve.json"


def main():

    listener = SuricataListener(EVE_PATH)

    events = listener.read_alerts()

    print(f"Total alerts detected: {len(events)}")

    for event in events[:10]:

        print("\n--- Network Event ---")

        print(f"ID        : {event.event_id}")
        print(f"Timestamp : {event.timestamp}")
        print(f"Source    : {event.source}")

        print(
            f"Flow      : "
            f"{event.src_ip}:{event.src_port}"
            f" -> "
            f"{event.dst_ip}:{event.dst_port}"
        )

        print(f"Protocol  : {event.protocol}")
        print(f"Severity  : {event.severity}")
        print(f"Signature : {event.signature}")


if __name__ == "__main__":
    main()