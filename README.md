# Advanced Firewall Control Panel

A comprehensive, modern firewall solution for Windows with a graphical user interface (GUI), featuring:
- Real-time packet filtering
- Intrusion Detection System (IDS)
- Intrusion Prevention System (IPS)
- Vulnerability scanning (with NVD API integration)
- Antivirus scanning (file and folder)
- Rule management (IP and port blocking/whitelisting)
- Security statistics and logs
- Modern, user-friendly interface (Tkinter)

## Features

- **Firewall**: Block/allow IPs and ports, manage rules, and monitor network traffic.
- **IDS/IPS**: Detect and prevent common attacks (port scans, floods, SQLi, XSS, etc.).
- **Vulnerability Scanner**: Scan IPs for open ports and known vulnerabilities (NVD integration, security header checks, SSL/TLS checks).
- **Antivirus**: Scan files and folders for known malware signatures.
- **GUI**: Easy-to-use interface for all features, including logs, statistics, and configuration.

## Installation

### Prerequisites
- Python 3.8+
- Windows OS (raw socket capture requires admin privileges)

### Required Python Packages
Install dependencies with pip:
```bash
pip install requests
```

Tkinter is included with most Python installations. If not, install it via your OS package manager.

## Usage

1. **Run the Application**
   ```bash
   python firewall_with_gui.py
   ```
2. **Start/Stop Firewall**: Use the GUI buttons to start or stop the firewall.
3. **Manage Rules**: Add, remove, or manage IP and port rules from the menu or control panels.
4. **Vulnerability Scanning**:
   - Configure your [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) in the Vulnerability menu.
   - Scan any IP for open ports and known vulnerabilities.
5. **Antivirus**: Scan individual files or entire folders for malware.
6. **Logs & Reports**: Export logs and scan reports from the File and Vulnerability menus.

## Screenshots

*Add screenshots of the GUI here if desired.*

## Security Notes
- **Admin Rights**: Raw socket capture requires running as administrator.
- **NVD API**: For vulnerability scanning, request a free API key from the [NVD website](https://nvd.nist.gov/developers/request-an-api-key).
- **SSL/TLS**: The scanner disables certificate verification for scanning purposes. Do not use on untrusted networks.

## Limitations
- Windows-only (due to raw socket usage)
- Not a replacement for enterprise-grade firewalls
- Vulnerability scanning is basic and for educational/demo use

## License

MIT License. See [LICENSE](LICENSE) for details.

## Credits

Developed by Lightgync, 2024.

---

*This project is for educational and demonstration purposes. Use responsibly.*
