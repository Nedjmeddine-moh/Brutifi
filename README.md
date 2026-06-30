# Brutifi - Unified Security Testing Framework

> **Brutifi** (also known as **BruteWiFi**) is a comprehensive network testing tool designed for security professionals and penetration testers. Built with **C++** for speed and performance, it provides three powerful attack modules for network and credential testing.

⚠️ **LEGAL NOTICE**: This tool is intended for authorized security testing only. Unauthorized access to computer systems is illegal. Always obtain explicit written permission before testing any network or system you do not own.

---

## Features

### 🔓 Module 1: WiFi Brute Force
Advanced wireless network password cracking with intelligent scanning and testing:
- **Multi-Interface Support**: Automatically detect and manage WiFi interfaces
- **Dual Scanning**: `iwlist` and `iw` command compatibility for maximum compatibility
- **Network Intelligence**: Displays signal strength, channel, and security type (WPA2/WPA/WEP)
- **Live Monitoring**: Real-time password testing with attempt rate display
- **WPA/WPA2 Support**: Full wpa_supplicant integration for modern WiFi protocols
- **Automatic IP Assignment**: DHCP client integration (dhcpcd) for connection verification
- **Results Export**: Saves cracked credentials to home directory

### ⚡ Module 2: DDoS Strike
High-performance distributed denial-of-service testing framework:
- **Multi-threaded Attacks**: Configurable thread count (default: 200) for massive throughput
- **TCP Flood**: Direct socket-based connection flooding
- **Bot Referrer Hammering**: Simulated bot traffic from major search engines and validators
- **Real-time Statistics**: Live packet rate, error tracking, and duration monitoring
- **Customizable Parameters**:
  - Target IP or domain
  - Port selection (default: 80)
  - Thread count for parallelization
  - Attack duration in seconds
- **Randomized User Agents**: Diverse header spoofing to evade detection

### 📧 Module 3: Gmail Credential Tester
Email credential validation framework designed for authorized security testing:
- **Dual Wordlist Support**: Built-in rockyou.txt reference or custom password lists
- **SMTP Authentication**: Tests Gmail credentials via SMTP protocol
- **Rate Limiting**: Integrated delays to avoid triggering security blocks
- **Live Progress**: Real-time attempt counting and testing speed display
- **Security Awareness**: Built-in warnings about Gmail's app-password requirements (post-2022)
- **OAuth2 Ready**: Framework notes for modern authentication methods

> ⚠️ **Note**: Gmail blocks standard SMTP authentication. Use app-specific passwords or OAuth2 for real testing.

---

## Installation

### Requirements
```
- Linux system (Kali, Ubuntu, Debian, etc.)
- C++ compiler (g++)
- Root/sudo privileges
- Required utilities:
  - iw, iwlist (wireless-tools)
  - wpa_supplicant, wpa_cli
  - dhcpcd (DHCP client)
  - Standard network tools (ip, ifconfig)
```

### Build
```bash
# Clone or download the repository
git clone https://github.com/Nedjmeddine-moh/Brutifi.git
cd Brutifi

# Compile with make
make

# Or manually compile
g++ -std=c++17 -pthread brutifi.cpp -o brutifi
```

### Dependencies Setup (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install -y \
    wireless-tools \
    wpasupplicant \
    dhcpcd5 \
    build-essential
```

---

## Usage

### Interactive Menu
```bash
sudo ./brutifi
```
Launches the interactive menu to select modules and configure parameters.

### Direct Module Launch
```bash
# WiFi Brute Force
sudo ./brutifi --wifi
# or
sudo ./brutifi -w

# DDoS Strike
sudo ./brutifi --ddos
# or
sudo ./brutifi -d

# Gmail Credential Tester
sudo ./brutifi --gmail
# or
sudo ./brutifi -g

# Help
./brutifi --help
# or
./brutifi -h
```

---

## Module Details

### WiFi Brute Force Workflow
1. **Interface Selection**: Lists all available wireless adapters with details
2. **Network Scanning**: Discovers nearby WiFi networks with signal/channel info
3. **Target Selection**: Choose network from sorted list
4. **Confirmation**: Confirm before launching attack
5. **Password Testing**: Iterates through wordlist (rockyou.txt by default)
6. **Connection Verification**: Validates successful connection with IP assignment
7. **Results**: Saves credentials to `~/brutifi_[SSID].txt`

**Default Wordlist**: `~/passlist.txt`

### DDoS Strike Configuration
- **Target**: IP address or domain name
- **Port**: HTTP (80), HTTPS (443), or custom port
- **Threads**: Number of concurrent attack threads (recommended: 200-500)
- **Duration**: Attack length in seconds

**Attack Methods**:
- TCP SYN flooding from all threads
- Persistent HTTP/1.1 keep-alive connections
- Bot referrer injection (simulated search engine traffic)

### Gmail Tester Configuration
- **Target Email**: Full Gmail address (user@gmail.com)
- **Wordlist Options**:
  - Built-in: `~/rockyou.txt` (most common passwords)
  - Custom: User-provided password dictionary
- **Testing Speed**: ~50ms per attempt (rate-limiting aware)

---

## Code Structure

```
brutifi.cpp
├── Utilities
│   ├── run_cmd()           - Execute system commands with pipes
│   ├── check_root()        - Verify root privileges
│   └── expand_path()       - Handle ~ path expansion
├── Module 1: WiFi Brute Force
│   ├── Network scanning (iwlist/iw)
│   ├── Interface management
│   ├── WPA2 configuration
│   └── Password testing loop
├── Module 2: DDoS Strike
│   ├── Multi-threaded socket creation
│   ├── TCP connection flooding
│   ├── User agent randomization
│   └── Live statistics monitoring
├── Module 3: Gmail Tester
│   ├── Credential validation framework
│   ├── Wordlist parsing
│   └── SMTP authentication simulation
└── Main Menu
    └── Module selection interface
```

---

## Performance

- **WiFi Brute Force**: 1-5 passwords tested per minute (depends on network latency)
- **DDoS Strike**: 1000-5000+ packets per second (200 threads on modern hardware)
- **Gmail Tester**: 20+ attempts per second (limited by rate limiting for safety)

---

## Configuration Files

### Wordlists
Place password lists in your home directory:
```bash
# WiFi passwords
~/passlist.txt

# Gmail passwords (standard RockYou list)
~/rockyou.txt
```

### Output
Results are saved in home directory:
```
~/brutifi_[SSID].txt              # WiFi credentials
~/brutifi.log                     # DDoS/Gmail logs
```

---

## Security Considerations

✅ **Best Practices**:
- Only use on networks/systems with written authorization
- Run in controlled lab environments
- Use VPN for operational security
- Monitor system resources during DDoS tests
- Keep wordlists updated

❌ **Avoid**:
- Testing without explicit permission
- Using on production networks
- Running 500+ threads on single system (resource exhaustion)
- Ignoring rate-limiting warnings for Gmail

---

## Troubleshooting

### "Root required" Error
```bash
# Always run with sudo
sudo ./brutifi
```

### WiFi Interface Not Detected
```bash
# Check available interfaces
iwconfig

# Enable monitor mode if needed
sudo airmon-ng start wlan0
```

### DDoS Not Sending Packets
- Verify target is reachable: `ping target_ip`
- Check firewall rules
- Reduce thread count if system is resource-constrained

### Gmail Tester Not Authenticating
- Use app-specific passwords (Gmail requires this since 2022)
- Enable "Less secure apps" (deprecated but still works in some cases)
- Consider OAuth2 implementation for modern approach

---

## Future Enhancements

- [ ] Bruteforce attack optimization (GPU acceleration)
- [ ] Multi-proxy support for anonymization
- [ ] HTTPS/TLS certificate spoofing
- [ ] Advanced packet crafting (Scapy integration)
- [ ] OAuth2 implementation for Gmail
- [ ] Database logging and reporting
- [ ] Web UI dashboard
- [ ] Configuration file support

---

## Contributing

Contributions are welcome! Areas for improvement:
- Error handling refinement
- Additional wireless protocols (WEP, TKIP)
- Custom packet generation
- Performance optimizations
- Documentation improvements

---

## Disclaimer

**Brutifi** is provided for educational and authorized security testing purposes only. The author assumes no liability for:
- Unauthorized access to systems
- Network disruption
- Data loss
- Legal consequences from misuse

Users are solely responsible for ensuring they have proper authorization before using this tool on any system they do not own.

---

## Author

**Nedjmeddine** - Security Research & Penetration Testing

---

## License

Educational Use Only - See LICENSE file for details

---

## References

- [WPA2 Security](https://en.wikipedia.org/wiki/Wi-Fi_Protected_Access)
- [DDoS Attack Methods](https://owasp.org/www-community/attacks/Denial_of_Service)
- [SMTP Protocol](https://tools.ietf.org/html/rfc5321)
- [Linux Networking Tools](https://linux.die.net/man/8/iwconfig)

---

**Last Updated**: 2025  
**Version**: 2.0 (WiFi + DDoS + Gmail)
