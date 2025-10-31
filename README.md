# Project: Network Intrusion Detection System (IDS)  
## Objective  
Develop a Python-based network intrusion detection system (IDS) that captures live network traffic, analyses packet headers and flows, applies rule-based detection for suspicious patterns (e.g., SYN floods, port scans, unusual IPs), and logs alerts for further investigation.

## Scope  
- Use Scapy to sniff packets on a chosen network interface.  
- Extract relevant fields: source IP, destination IP, source port, destination port, protocol, TCP flags, timestamps.  
- Define detection rules, such as:  
  - High rate of SYN packets from a single source → potential SYN flood.  
  - Repeated connection attempts to closed ports → port scan.  
  - Packets from blacklisted or unusual IPs → alert.  
- Log alerts into a CSV file with timestamp, source, destination, description of alert.  
- (Optional) Build a simple GUI or console dashboard to display real-time alerts.  
- (Optional) Enable filtering/storage of suspicious packet captures (PCAP) for further analysis.

## Tools & Technologies  
- Python 3  
- Scapy (for packet capture & analysis)  
- CSV or simple database for logging  
- (Optional) Tkinter or Streamlit for GUI  
- Wireshark for verification of packet captures

## Deliverables  
- `ids.py` (main script)  
- `requirements.txt`  
- Sample config or rule file (if applicable)  
- `intrusion_log.csv` (sample output)  
- README.md with setup instructions, features, how to use  
- (Optional) GUI/dashboard  
- (Optional) PCAP file(s) of detected events  
- Repo published on GitHub with clear structure and documentation

## Evaluation  
- Demonstrate basic detection: e.g., simulate SYN flood or port scan and show alert logs.  
- Show correct packet capture and rule firing.  
- (Optional) Compare baseline traffic vs triggered attack traffic and show detection time or rate.

## Future Enhancements  
- Add anomaly-based detection (statistical/ML) alongside rule-based.  
- Support parsing PCAP files offline.  
- Integrate email/SMS alerting or Slack.  
- Use dashboards for visualization (charts of alerts over time).  

