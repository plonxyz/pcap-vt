import pyshark
import requests
from tqdm import tqdm
import csv

VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"
API_KEY = "YOUR_VIRUSTOTAL_API_KEY"


def extract_destination_ips(pcap_file):
    cap = pyshark.FileCapture(pcap_file)
    dest_ips_set = set()

    for packet in tqdm(cap, desc="Extracting IPs from pcap", unit="packet"):
        if 'IP' in packet:
            dest_ips_set.add(packet.ip.dst)

    return list(dest_ips_set)

def check_ip_virustotal(ip):
    headers = {
        "x-apikey": API_KEY
    }
    response = requests.get(VIRUSTOTAL_URL.format(ip), headers=headers)
    if response.status_code == 200:
        data = response.json()
        malicious = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
        suspicious = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("suspicious", 0)
        harmless = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("harmless", 0)
        undetected = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("undetected", 0)
        return [ip, malicious, suspicious, harmless, undetected]
    else:
        return [ip, "Error", "Error", "Error", "Error"]

if __name__ == "__main__":
    pcap_path = input("Please enter the path to the pcap file: ")
    ips_list = extract_destination_ips(pcap_path)
    results = []

    print("Processing IPs...")
    for ip in tqdm(ips_list, desc="Checking IPs against VirusTotal"):
        result = check_ip_virustotal(ip)
        results.append(result)

    with open('results.csv', 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(["IP", "Malicious", "Suspicious", "Harmless", "Undetected"])
        csvwriter.writerows(results)

    print("Results written to results.csv")
