import os
import urllib.request

def download_pcap_slice(url, dest_path, limit_mb=25):
    print(f"Downloading slice of {url} to {dest_path} (Limit: {limit_mb} MB)...")
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    
    limit_bytes = limit_mb * 1024 * 1024
    bytes_downloaded = 0
    block_size = 1024 * 64  # 64 KB blocks
    
    try:
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        with urllib.request.urlopen(req) as response:
            with open(dest_path, 'wb') as f:
                while bytes_downloaded < limit_bytes:
                    chunk = response.read(block_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    bytes_downloaded += len(chunk)
                    print(f"Downloaded {bytes_downloaded / (1024 * 1024):.2f} MB / {limit_mb} MB...", end='\r')
        print(f"\nSuccessfully downloaded slice of {bytes_downloaded / (1024 * 1024):.2f} MB to {dest_path}")
    except Exception as e:
        print(f"\nError downloading PCAP slice: {e}")

def main():
    base_dir = r"D:\BRAHMA\PROJECTS\SENTINELCHAIN"
    cicids_dir = os.path.join(base_dir, "dataset", "CICIDS2017")
    dest_path = os.path.join(cicids_dir, "Monday-WorkingHours.pcap")
    
    url = "https://huggingface.co/datasets/bvsam/cic-ids-2017/resolve/main/pcap/Monday-WorkingHours.pcap"
    download_pcap_slice(url, dest_path, limit_mb=25)

if __name__ == "__main__":
    main()
