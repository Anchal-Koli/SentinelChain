import os
import json
import time
import subprocess
from datetime import datetime, timedelta

EVE_JSON_PATH = os.environ.get("EVE_JSON_PATH", "/workspace/capture/suricata_logs/eve.json")
PCAP_INTERFACE = os.environ.get("PCAP_INTERFACE", "eth0") # Interface or offline pcap path
CAPTURE_OUTPUT_DIR = os.environ.get("CAPTURE_OUTPUT_DIR", "/workspace/capture/dpi_slices")
TIME_WINDOW_SEC = 5

def extract_tshark_slice(src_ip, dest_ip, start_time, end_time, output_pcap):
    """
    Runs tshark to extract packets between src and dest in a specific time window.
    """
    try:
        t_start = datetime.strptime(start_time.split('.')[0], "%Y-%m-%dT%H:%M:%S") - timedelta(seconds=TIME_WINDOW_SEC)
        t_end = datetime.strptime(end_time.split('.')[0], "%Y-%m-%dT%H:%M:%S") + timedelta(seconds=TIME_WINDOW_SEC)
        
        bpf_filter = f"host {src_ip} and host {dest_ip}"
        
        cmd = [
            "tshark",
            "-i", PCAP_INTERFACE,
            "-a", f"duration:{TIME_WINDOW_SEC * 2}",
            "-f", bpf_filter,
            "-w", output_pcap
        ]
        
        print(f"Triggering DPI extraction: {' '.join(cmd)}")
        subprocess.Popen(cmd)
    except Exception as e:
        print(f"Error extracting DPI slice: {e}")

def monitor_eve_json():
    """
    Tails the eve.json file and triggers tshark when an alert is seen.
    """
    print(f"Starting Selective DPI Trigger on {EVE_JSON_PATH}")
    os.makedirs(CAPTURE_OUTPUT_DIR, exist_ok=True)
    
    if not os.path.exists(EVE_JSON_PATH):
        print(f"File {EVE_JSON_PATH} not found. Waiting...")
        while not os.path.exists(EVE_JSON_PATH):
            time.sleep(1)
            
    with open(EVE_JSON_PATH, 'r') as f:
        # Seek to the end for live tailing
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            
            try:
                event = json.loads(line)
                if event.get("event_type") == "alert":
                    src_ip = event.get("src_ip")
                    dest_ip = event.get("dest_ip")
                    timestamp = event.get("timestamp")
                    alert = event.get("alert", {})
                    signature = alert.get("signature", "unknown").replace(" ", "_").replace("/", "_")
                    
                    print(f"[ALERT] {timestamp} - {signature} ({src_ip} -> {dest_ip})")
                    
                    output_pcap = os.path.join(CAPTURE_OUTPUT_DIR, f"{int(time.time())}_{signature}.pcap")
                    extract_tshark_slice(src_ip, dest_ip, timestamp, timestamp, output_pcap)
            except json.JSONDecodeError:
                pass

if __name__ == "__main__":
    monitor_eve_json()
