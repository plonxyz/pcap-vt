# PCAP IP Analyzer

This script parses a given pcap file to extract unique destination IPs and then checks each IP against the VirusTotal API for any malicious activities.

## Prerequisites

- Python 3.x
- `pyshark` library
- `requests` library
- `tqdm`library
- A VirusTotal API key
