# PCAP-Analyzer
## Overview
**PCAP Analyzer** is a comprehensive Python-based application designed for analyzing PCAP files, capturing live network traffic, visualizing traffic patterns, and detecting potential network attacks. It is an essential tool for network administrators, cybersecurity professionals, and researchers interested in monitoring and analyzing network behavior effectively. The intuitive interface makes it accessible to both technical and non-technical users, helping to automate system hardening while ensuring a secure environment.

---

## Features

1. **Load and Analyze PCAP Files:** Open, inspect, and filter packet capture (PCAP) files.

2. **Live Packet Capture:** Capture real-time network traffic.

3. **Traffic Analysis Window:** Visualize and monitor network traffic trends with detailed charts and statistics.

4. **Attack Detection:** Identify potential network threats such as DDoS attacks, port scans, malicious payloads, and suspicious traffic patterns.

5. **Protocol Filtering:** Filter packets based on protocol types such as TCP, UDP, ICMP, ARP, and more.

6. **Packet Inspection:** View detailed packet metadata, including headers, payload, and timestamps.

7. **Graphical Visualization:** Generate graphs for traffic volume, protocol distribution, and flow patterns.

---

## Installation

### Prerequisites
Before installing the PCAP-Analyzer Tool, ensure that your system meets the following requirements:

- **Python 3.x:** Ensure Python is installed (if not running as an executable). You can download it from [python.org](https://python.org).
- **Tkinter:** Included with Python by default.
- **Dependencies:**
  Install the required dependencies using pip:
  ```
  pip install scapy pandas matplotlib ttkthemes networkx
  ```

### Steps to Install

1. **Download the Repository:**
```
git clone https://github.com/hashid31/pcap-analyzer.git
cd pcap-analyzer
```

2. **Run the Application:**
Execute the following command in Command Prompt (as Administrator):
```
python main.py
```
> **Note:** The tool requires admin rights to capture packets. If prompted, allow the application to run as an administrator.

---

## Usage

### Run as Administrator
Since this program can capture live packets, ensure that you run it as admin/root. 

### Loading a PCAP File

1. Open the application.
2. Click on **Open PCAP** and select a **.pcap** file.
3. View the packet details, including timestamp, source, destination, protocol, and hex_dump.

### Live Packet Capture

1. Choose the network interface.
2. Click on **Start Live Capture**.
3. Start capturing packets and analyze them in real time.

### Attack Detection

The application will start scanning for known attack patterns such as:
1. Unusual traffic
2. Port scanning activity
3. Flood attack detection
5. DNS amplification attacks
6. ARP poisoning attempts
7. Alerts will be displayed in the attack detection window.

### Traffic Analysis

1. View real-time and historical network traffic insights.
2. Generate protocol distribution charts.
3. Identify top talkers and listeners on the network.
4. Visualize the network through network graphs.


### Navigating the Interface
The GUI is divided into several key sections:

- **Packet Treeview:** Get the main details of packets like the timestamps, source and destination ip addresses, protocols, and the lengths of the packets.
  
- **Notebook:** Check packet metadata, hex dump, domains accessed and other information.
  
- **Menu bar:** You can open a pcap file, analyze traffic, scan for attacks, and save the data in a pickle file.

## Contact
- For any questions or issues, reach out via email or open an issue on GitHub.
---
