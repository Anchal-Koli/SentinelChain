import os
import urllib.request

def download_file(url, destination):
    print(f"Downloading {url} -> {destination}...")
    try:
        urllib.request.urlretrieve(url, destination)
        print(f"Success: {destination} downloaded.")
    except Exception as e:
        print(f"Error downloading {url}: {e}")

def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dataset_dir = os.path.join(base_dir, "dataset")
    os.makedirs(dataset_dir, exist_ok=True)
    
    # We will download a few sample PCAPs from markofu/pcaps for verification
    pcaps = {
        "ftp.pcap": "https://raw.githubusercontent.com/markofu/pcaps/master/PracticalPacketAnalysis/ppa-capture-files/ftp.pcap",
        "evilprogram.pcap": "https://raw.githubusercontent.com/markofu/pcaps/master/PracticalPacketAnalysis/ppa-capture-files/evilprogram.pcap",
        "http.pcap": "https://raw.githubusercontent.com/markofu/pcaps/master/PracticalPacketAnalysis/ppa-capture-files/http.pcap"
    }
    
    for filename, url in pcaps.items():
        dest = os.path.join(dataset_dir, filename)
        download_file(url, dest)

if __name__ == "__main__":
    main()
