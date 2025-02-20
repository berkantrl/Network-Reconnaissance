# Network Reconnaissance

Network Reconnaissance is a Python script designed to perform network scanning and reconnaissance tasks. It helps security analysts and network administrators gather information about active devices on a network.

## Features

- Active and passive network scanning
- Retrieves MAC addresses and vendor details
- Provides a simple and efficient way to perform basic network reconnaissance

## Installation

1. Clone the repository:
   ```bash
   git clone [URL]
   ```
2. Navigate to the project directory:
   ```bash
   cd Network-Reconnaissance
   ```
3. Install the required dependencies individually:
   ```bash
   pip install scapy
   ```

## Usage

Run the script with Python in either **active** or **passive** mode:

### Active Mode

Active mode scans all IP addresses in the network by sending ping requests.

```bash
python net_recon.py -i interface_name -a
```

### Passive Mode

Passive mode listens to ARP packets on the network without actively sending any requests.

```bash
python net_recon.py -i interface_name -p
```

You may need administrator/root privileges to execute the script properly:

```bash
sudo python net_recon.py -i --iface interface_name -a --active
```

## Disclaimer

This script is intended for educational and security research purposes only. Use it only on networks you own or have explicit permission to scan. Unauthorized scanning may be illegal.

---

For contributions or issues, feel free to submit a pull request or open an issue in the repository.

