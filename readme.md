# Brutifi

**WiFi Brute Force Audit Tool**

<p align="center">
  <img src="https://img.shields.io/badge/C++-17-blue.svg" alt="C++17">
  <img src="https://img.shields.io/badge/license-GPL--v3-green.svg" alt="GPL v3">
  <img src="https://img.shields.io/badge/platform-Linux-orange.svg" alt="Linux">
</p>

**Author:** Nedjmeddine  
**GitHub:** [nedjmeddine-moh/brutifi](https://github.com/nedjmeddine-moh/brutifi)

Brutifi is a fast, interactive C++ tool for authorized WiFi security auditing. It enumerates all wireless interfaces on your system, lets you select one, scans for nearby networks, and performs controlled brute-force authentication testing against WPA/WPA2-PSK networks.

---

## Features

- **Auto-detects all wireless interfaces** — built-in cards, USB dongles, PCIe adapters, SDIO
- **Interactive interface selection** — pick your device from a clean table with driver info
- **Real-time network scanning** — uses `iw` / `iwlist` with deduplication and signal sorting
- **Live brute-force engine** — tests passwords via actual `wpa_supplicant` authentication
- **Cross-user compatible** — resolves `~` and environment variables automatically
- **Fast C++ implementation** — compiled with `-O3` for maximum performance
- **Clean result output** — saves cracked credentials to your home directory

---

## Requirements

- Linux (tested on Arch, Debian, Ubuntu, Fedora)
- Root privileges
- `g++` with C++17 support
- `iw`, `wpa_supplicant`, `wpa_cli`, `dhcpcd`

### Install dependencies (Arch)

```bash
sudo pacman -S iw wpa_supplicant dhcpcd

Install dependencies (Debian/Ubuntu):

sudo apt install iw wpasupplicant dhcpcd5

Install dependencies (Fedora):

sudo dnf install iw wpa_supplicant dhcpcd

Build:

git clone https://github.com/nedjmeddine-moh/brutifi.git
cd brutifi
make

Or manually:

g++ -O3 -std=c++17 -Wall -Wextra -pthread -o brutifi brutifi.cpp

With custom config:

sudo ./brutifi /path/to/config.json

Configuration (config.json):
Create config.json in the same directory for custom settings:

{
    "passlist_path": "~/passlist.txt",
    "interface": "wlan0",
    "timeout": 15,
    "scan_method": "auto"
}

| Key             | Description                                             |
| --------------- | ------------------------------------------------------- |
| `passlist_path` | Path to password list. Supports `~` for home directory. |
| `interface`     | Wireless interface to use. If omitted, auto-detected.   |
| `timeout`       | Seconds to wait for each password attempt. Default: 15  |
| `scan_method`   | `auto`, `iw`, or `iwlist`. Default: `auto`              |
If no config is found, Brutifi auto-detects your interface and looks for ~/passlist.txt

Creating a Password List:
# SecLists top 10k
curl -o ~/passlist.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt

# RockYou (unzip first)
curl -o ~/rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

Workflow
Launch with sudo ./brutifi
Select interface from detected wireless devices
Scan for target networks
Select network from discovered SSIDs
Confirm attack
Wait — Brutifi tests each password and shows live progress
Result — cracked credentials saved to ~/brutifi_<SSID>.txt

Output Example:

[*] Using configured interface: wlan0
[*] Interface: wlan0
[*] Passlist:  /home/user/passlist.txt

[*] Scanning on wlan0...

#########################################################
ID   SSID                        Signal    Ch    Sec      
---------------------------------------------------------
1    MyNetwork                   -42       6     WPA2      
2    Guest_WiFi                  -65       11    WPA2      
3    xfinitywifi                 -78       1     Open      
#########################################################
[?] Select network ID (1-3) or q: 1
[+] Target: MyNetwork

[!] Attack MyNetwork? (y/N): y

============================================================
  BRUTIFI ATTACK
  Target: MyNetwork
  BSSID:  aa:bb:cc:dd:ee:ff
============================================================
[*] 5000 passwords loaded
[*] Preparing wlan0...
[+] Ready
[1247/5000] Spring2023! (83.2/s)
============================================================
  [+] CRACKED!
  [+] SSID: MyNetwork
  [+] PSK:  Spring2023!
============================================================
[+] Saved: /home/user/brutifi_MyNetwork.txt

Project Structure:

brutifi/
├── brutifi.cpp      # Main source
├── Makefile         # Build rules
├── config.json      # Example config
├── README.md        # This file
└── LICENSE          # GPL v3

Legal Notice
Brutifi is intended for authorized security testing only.
Use this tool only on networks you own or have explicit written permission to test. Unauthorized access to computer networks is illegal in most jurisdictions. The author assumes no liability for misuse of this software.
