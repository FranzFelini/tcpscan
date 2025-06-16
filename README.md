# tcpscan

`tcpscan` is a Python command-line tool that leverages the core functionalities of `tcpdump` and `Scapy` to provide clear, concise output for TCP/IP packet analysis. It captures TCP packets, displaying source/destination IPs, MSS (Maximum Segment Size), Window Size, and ACK status—making it ideal for efficient network testing and debugging.

Designed for **macOS** and **Linux**, it supports interactive interface selection, command-line arguments, and automatic interface activation (e.g., enabling Wi-Fi on macOS).

---

## Features

- Capture TCP SYN packets (for MSS) or all TCP packets
- Clear output of packet details:
  - Source/Destination IPs
  - MSS
  - Window Size
  - ACK status
- Debug TCP options if MSS is not present
- Activate inactive interfaces (e.g., enable Wi-Fi, prompt for Ethernet cable)
- Command-line arguments for:
  - Interface
  - Packet count
  - Timeout
  - Packet type
- Compatible with macOS and Linux

---

## 📦 Prerequisites

**Python 3.6+**
```bash
python3 --version
```

**pip3**
```bash
python3 -m ensurepip --upgrade
```

**libpcap (required by Scapy for packet capture)**

macOS: Usually preinstalled  
Linux:
```bash
sudo apt-get install libpcap-dev
```

**Root Privileges:**  
Use `sudo` when running the script.

**Active Network Interface:**  
macOS: `en0`, `en1`, `lo0`  
Linux: `eth0`, `wlan0`, `lo`

---

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/FranzFelini/tcpscan.git
cd tcpscan
```

### 2. Install Dependencies
```bash
pip3 install -r requirements.txt
```

### (Optional) Use a Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

If `pip3` requires root:
```bash
sudo pip3 install -r requirements.txt
```

### 3. Install the Command
```bash
sudo mv tcpscan /usr/local/bin/tcpscan
sudo chmod +x /usr/local/bin/tcpscan
```


## Usage

Run interactively (prompts for interface):
```bash
sudo tcpscan
```

Specify interface:
```bash
sudo tcpscan -i en0
```

Capture 20 packets with a 30-second timeout:
```bash
sudo tcpscan -i en0 -c 20 -t 30
```

Capture all TCP packets (not just SYN):
```bash
sudo tcpscan -i en0 --all-tcp
```


## 📡 Generating Traffic

To generate SYN packets (which include MSS), start a new connection:
```bash
curl http://google.com
```

Or open a browser and visit:
```
https://example.com
```

---

## 🔍 Example Output

```
TCP Packet Fingerprint Tool
Capturing up to 10 TCP SYN packets on interface en0 (timeout: 10 seconds)...
172.16.4.47 -> 104.18.29.234, MSS: 1460, Window: 65535, ACK: No
Debug: TCP options for 172.16.4.47 -> 104.18.29.234: [('MSS', 1460), ('WScale', 7), ('SAckOK', ''), ('Timestamp', (123456, 0))]
Captured 3 TCP SYN packets.
```

---

## 📝 Notes

- MSS is only present in TCP SYN packets. Use `--all-tcp` to capture all TCP traffic (MSS will not be present in non-SYN packets).
- macOS interfaces:
  - `en0` = Wi-Fi
  - `en1` = Ethernet
  - `lo0` = loopback
- Linux interfaces:
  - `eth0`, `wlan0`, `lo`
- The script can:
  - Enable Wi-Fi on macOS
  - Prompt to plug in Ethernet cable
- Debug output shows full TCP options if MSS is not present
- Generate new connections during capture for best results

---

## 🐞 Troubleshooting

### No packets captured?
Ensure traffic:
```bash
curl http://example.com
```

Verify interface:
```bash
ifconfig en0  # macOS
ip link       # Linux
```

Test with tcpdump:
```bash
sudo tcpdump -i en0 -nn 'tcp[tcpflags] & tcp-syn != 0'
```

---

### pip errors?
Ensure pip is installed:
```bash
python3 -m ensurepip --upgrade
```

Install libpcap (Linux):
```bash
sudo apt-get install libpcap-dev
```

---

### Permission errors?
Run as root:
```bash
sudo tcpscan
```

Verify Scapy:
```bash
python3 -c "import scapy; print(scapy.__version__)"
```

---

### MSS not detected?
Check debug output. In rare cases, MSS may be stripped by:
- Firewalls
- Middleboxes
- Network filtering gear

---

## 📄 License

MIT License. See the [LICENSE](LICENSE) file.

