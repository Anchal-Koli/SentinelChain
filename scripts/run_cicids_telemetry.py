import os
import subprocess
import json

def run_cmd(command, cwd=None):
    print(f"Running command: {command}")
    res = subprocess.run(command, shell=True, capture_output=True, text=True, cwd=cwd)
    if res.returncode != 0:
        print(f"Error executing command: {res.stderr}")
    return res

def main():
    base_dir = "/workspace"
    pcap_path = os.path.join(base_dir, "dataset", "CICIDS2017", "Monday-WorkingHours.pcap")
    
    if not os.path.exists(pcap_path):
        print(f"ERROR: {pcap_path} not found.")
        return
        
    print(f"Found benchmark PCAP file at {pcap_path}. Size: {os.path.getsize(pcap_path)} bytes.")
    
    # Create capture subfolders
    zeek_out_dir = os.path.join(base_dir, "capture", "cicids_zeek")
    suricata_out_dir = os.path.join(base_dir, "capture", "cicids_suricata")
    os.makedirs(zeek_out_dir, exist_ok=True)
    os.makedirs(suricata_out_dir, exist_ok=True)
    
    print("\n=== Run 1: TShark Packet Check ===")
    tshark_cmd = f"tshark -r {pcap_path} -c 5"
    res = run_cmd(tshark_cmd)
    if res.returncode == 0:
        print("SUCCESS: TShark successfully opened the PCAP.")
        print(res.stdout)
    else:
        print("FAILED: TShark failed to read PCAP.")
        
    print("\n=== Run 2: Zeek Connection Logs ===")
    # Clean previous runs if any
    for f in os.listdir(zeek_out_dir):
        if f.endswith(".log"):
            os.remove(os.path.join(zeek_out_dir, f))
            
    zeek_cmd = f"zeek -r {pcap_path}"
    res = run_cmd(zeek_cmd, cwd=zeek_out_dir)
    if res.returncode == 0:
        print("SUCCESS: Zeek finished processing.")
        generated_logs = [f for f in os.listdir(zeek_out_dir) if f.endswith(".log")]
        print(f"Generated Zeek Logs: {generated_logs}")
    else:
        print("FAILED: Zeek execution encountered errors.")
        
    print("\n=== Run 3: Suricata Threat Alerts ===")
    # Clean previous runs if any
    for f in ["eve.json", "fast.log", "stats.log", "suricata.log"]:
        fpath = os.path.join(suricata_out_dir, f)
        if os.path.exists(fpath):
            os.remove(fpath)
            
    suricata_cmd = f"suricata -r {pcap_path} -l {suricata_out_dir} -k none"
    res = run_cmd(suricata_cmd)
    if res.returncode == 0:
        print("SUCCESS: Suricata finished processing.")
        generated_suricata_files = os.listdir(suricata_out_dir)
        print(f"Generated Suricata Files: {generated_suricata_files}")
    else:
        print("FAILED: Suricata execution encountered errors.")

if __name__ == "__main__":
    main()
