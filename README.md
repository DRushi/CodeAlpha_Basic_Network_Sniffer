# 🔐 Basic Network Sniffer using Python, Scapy & Tkinter

A beginner-friendly **GUI-based Network Sniffer** built with **Python, Scapy, and Tkinter**.  
The project captures network packets in real time, analyzes basic packet information, and displays the results through a simple graphical interface.

> ⚠️ **Disclaimer:** Use this tool only on systems and networks that you own or have explicit permission to monitor.

---

## 📌 Project Overview

The Basic Network Sniffer is designed to help understand:

- How network packets travel through a network
- Basic packet structure
- IP addresses and ports
- TCP, UDP, ICMP, ARP, and IP protocols
- Basic packet and payload analysis
- Real-time network traffic monitoring

The application provides an easy-to-use GUI instead of requiring the user to work only from the command line.

---

## 🎯 Objectives

1. Capture network packets using Python and Scapy.
2. Identify common network protocols.
3. Extract useful packet information.
4. Display captured traffic in a graphical interface.
5. Filter packets based on protocol.
6. Inspect individual packet details.
7. Export captured packet information to CSV.
8. Build practical networking and cybersecurity knowledge.

---

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Main programming language |
| Scapy | Packet capture and analysis |
| Tkinter | Graphical User Interface |
| Threading | Background packet capture |
| CSV | Export captured packet information |

---

## 🔄 Project Workflow

```text
                    ┌──────────────────────┐
                    │   NETWORK TRAFFIC    │
                    │ Web / DNS / Ping /   │
                    │ Local Network Apps   │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   SCAPY CAPTURE      │
                    │  sniff() function    │
                    └──────────┬───────────┘
                               │
                               ▼
                 ┌────────────────────────────┐
                 │ PACKET PROCESSING & ANALYSIS│
                 │                            │
                 │ • Protocol Detection      │
                 │ • IP Addresses             │
                 │ • Source/Destination Ports│
                 │ • Packet Length            │
                 │ • Payload Preview          │
                 └─────────────┬──────────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │    TKINTER GUI       │
                    │                      │
                    │ Live Packet Table    │
                    │ Protocol Filter      │
                    │ Packet Details       │
                    └──────────┬───────────┘
                               │
                 ┌─────────────┴─────────────┐
                 ▼                           ▼
        ┌────────────────┐          ┌────────────────┐
        │ Packet Inspect │          │  Export CSV    │
        └────────────────┘          └────────────────┘
```

### Complete Flow

**Network Traffic → Scapy → Packet Capture → Protocol Detection → Packet Analysis → Tkinter GUI → Filter / Inspect / Export**

---

## ✨ Features

### 📡 Real-Time Packet Capture
Captures packets from the available network interface using Scapy.

### 🔎 Protocol Detection
The application identifies common protocols:

- TCP
- UDP
- ICMP
- ARP
- IP

### 🌐 IP Information

For IP packets, the application displays:

- Source IP
- Destination IP
- TTL

### 🔌 Port Information

For TCP and UDP traffic:

- Source Port
- Destination Port

### 📦 Packet Size

The application displays the total packet length in bytes.

### 📝 Payload Preview

If a raw payload is available, the application displays a limited payload preview.

For encrypted HTTPS traffic, readable application data generally cannot be displayed because the communication is encrypted.

### 🔍 Protocol Filtering

Users can filter captured packets by:

```text
ALL
TCP
UDP
ICMP
ARP
IP
```

### 👁️ Packet Inspection

Double-clicking a packet displays additional packet information and its Scapy packet structure.

### 💾 CSV Export

Captured packet information can be exported into a CSV file for documentation or further analysis.

### 🛑 Start / Stop Capture

The user can start and stop packet capture directly from the GUI.

---

## 📂 Project Structure

```text
basic-network-sniffer/
│
├── network_sniffer_gui.py
├── requirements.txt
├── README.md
└── workflow.png
```

---

## ⚙️ Installation

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/basic-network-sniffer.git
cd basic-network-sniffer
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

For Linux:

```bash
pip3 install -r requirements.txt
```

### 3. Install Npcap on Windows

Windows users may need **Npcap** for packet capture.

During installation, enabling WinPcap-compatible support can help applications that expect the WinPcap interface.

---

## ▶️ Running the Project

### Windows

Open **PowerShell or Command Prompt as Administrator**:

```powershell
python network_sniffer_gui.py
```

### Linux / Kali Linux

Run with appropriate privileges:

```bash
sudo python3 network_sniffer_gui.py
```

---

## 🧪 Testing the Sniffer

After starting the application, click:

```text
▶ Start Sniffing
```

Generate some traffic from another terminal.

### ICMP Traffic

```bash
ping 8.8.8.8
```

Expected protocol:

```text
ICMP
```

### DNS Traffic

```bash
nslookup example.com
```

Expected protocol:

```text
UDP
```

DNS commonly uses:

```text
Port 53
```

### HTTPS Traffic

Open a website in your browser.

You may observe TCP connections involving:

```text
Destination Port: 443
```

---

## 🖥️ GUI Components

The application contains the following main sections:

### Header

Displays:

- Project name
- Capture status

### Control Panel

Contains:

- Start Sniffing
- Stop
- Clear
- Export CSV
- Packet counter

### Protocol Filter

Allows selection of a specific protocol.

### Packet Table

Displays:

| Field | Description |
|---|---|
| No | Packet number |
| Time | Capture time |
| Protocol | Detected protocol |
| Source IP | Sender IP |
| Source Port | Sender port |
| Destination IP | Receiver IP |
| Destination Port | Receiver port |
| Length | Packet size |

### Packet Details

Displays additional information when a packet is selected.

---

## 🧠 How It Works

The application uses Scapy's packet sniffing capability:

```python
sniff(
    prn=self.process_packet,
    store=False
)
```

Each captured packet is passed to the packet-processing function.

The program then:

```text
Capture Packet
      ↓
Identify Protocol
      ↓
Extract IP Information
      ↓
Extract TCP/UDP Ports
      ↓
Calculate Packet Length
      ↓
Check Payload
      ↓
Display in GUI
```

The packet capture runs in a background thread so that the Tkinter interface remains responsive.

---

## 🔐 Cybersecurity Relevance

Network packet analysis is an important foundation for cybersecurity and SOC operations.

This project provides practical exposure to:

- Network traffic analysis
- IP communication
- TCP/UDP traffic
- Ports and protocols
- Packet structure
- Basic network monitoring
- Initial investigation of unusual connections

A security analyst can use similar concepts when investigating suspicious communication, unexpected ports, or abnormal network activity.

---

## 🚀 Future Enhancements

The project can be further improved by adding:

- [ ] PCAP file save and load
- [ ] Advanced IP filtering
- [ ] Source/destination port filtering
- [ ] Traffic statistics
- [ ] Network traffic charts
- [ ] Suspicious port detection
- [ ] IP reputation checking
- [ ] Alert generation
- [ ] Packet search
- [ ] Dark SOC dashboard
- [ ] Snort IDS integration
- [ ] SIEM integration
- [ ] Protocol statistics dashboard

---

## 📚 Learning Outcomes

After completing this project, you can gain practical understanding of:

- Python networking
- Scapy
- Packet capturing
- Packet structure
- TCP/IP
- UDP
- ICMP
- ARP
- IP addressing
- Network ports
- Payload analysis
- Tkinter GUI development
- Basic cybersecurity monitoring

---

## 📸 Workflow Diagram

Add the project workflow image to the repository as:

```text
workflow.png
```

Then it can be displayed in this README using:

```markdown
![Basic Network Sniffer Workflow](workflow.png)
```

---

## ⚠️ Ethical & Legal Use

This project is intended for:

- Educational purposes
- Personal lab environments
- Authorized network monitoring
- Cybersecurity training

Do **not** capture or inspect traffic on networks or devices without proper authorization.

---

## 👨‍💻 Author

**Rushikesh Dhawade**

Cybersecurity | SOC | Network Security | Python

---

## ⭐ Conclusion

The **Basic Network Sniffer** is a practical Python project for learning network packet capture and analysis.

It combines **Scapy for packet processing** with **Tkinter for visualization**, providing a simple foundation for understanding network traffic and developing more advanced cybersecurity monitoring tools.

If you found this project useful, consider giving the repository a ⭐.
