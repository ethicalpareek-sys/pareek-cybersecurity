
<div align="center">

# 🛡️ PAREEK

### Cybersecurity Recon Assistant for Termux

**Turn Your Android Phone into a Portable Hacking Machine.**

[![Made for Termux](https://img.shields.io/badge/Made%20for-Termux-00b894?style=for-the-badge&logo=gnu-bash&logoColor=white)](https://termux.dev)
[![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Stars](https://img.shields.io/github/stars/ethicalpareek-sys/pareek-cybertool?style=for-the-badge&color=gold)](https://github.com/ethicalpareek-sys/pareek-cybertool/stargazers)

**13 Powerful Modules in a Single Python File — No Root Needed!**

</div>

---

**PAREEK** is a lightweight, single-file cybersecurity toolkit built specifically for **Termux (Android)**. Whether you are a beginner learning cybersecurity or a professional doing authorized reconnaissance, PAREEK gives you everything you need in one simple command.

---

 


⚠️ Disclaimer

This tool is strictly for authorized security testing and educational purposes only. The author is not responsible for any misuse or damage caused by this program.



## 🚀 Features
- Information Gathering (WHOIS, DNS, IP info)
- Network Discovery (TCP Port Scanning)
- Web Security Checks (Headers, Cookies, CORS)
- SSL/TLS Analysis
- Subdomain Enumeration
- CVE Lookup (NVD API)
- Password & Hash Lab
- Linux Audit & Network Info
- Log Analysis
- JSON/CSV/HTML Reporting

## 📦 Installation (Termux)

1. Update Termux and install dependencies:
   ```bash
   pkg update && pkg upgrade -y
   pkg install python git clang make libffi openssl libxml2 libxslt ca-certificates -y
   pip install requests dnspython python-whois


git clone https://github.com/ethicalpareek-sys/pareek-cybersecurity.git

cd pareek-cybersecurity

use python pareek.py   to run


🛠️ Usage

Run the tool using Python:

```bash
python pareek.py recon example.com
python pareek.py portscan scanme.nmap.org
python pareek.py webcheck https://example.com
python pareek.py sslcheck example.com
python pareek.py subdomain tesla.com
python pareek.py vuln "apache 2.4.49"
python pareek.py password "P@ssw0rd!2024"
python pareek.py report -f html





```bash
python pareek.py recon example.com
```

🌐 2. Port Scanning

Scan the top 48 common ports of a target.

```bash
python pareek.py portscan scanme.nmap.org
```

Custom ports and faster scan:

```bash
python pareek.py portscan 192.168.1.1 -p 80,443,8080 -t 200
```

🕸️ 3. Web Security Check

Checks headers, cookies, CORS, and exposed files.

```bash
python pareek.py webcheck https://example.com
```

🔒 4. SSL/TLS Check

Check certificate expiry and TLS version.

```bash
python pareek.py sslcheck example.com
```

🌍 5. Subdomain Enumeration

Find subdomains passively via crt.sh.

```bash
python pareek.py subdomain tesla.com
```

🐞 6. CVE Vulnerability Lookup

Search for known vulnerabilities.

```bash
python pareek.py vuln "apache 2.4.49"
```

🔑 7. Password Strength Checker

Check entropy and get hashes.

```bash
python pareek.py password "Bharat@2026"
```

#️⃣ 8. Hash Identifier

Identify what type of hash it is.

```bash
python pareek.py hashid 5f4dcc3b5aa765d61d8327deb882cf99
```

🐧 9. Linux Audit (Runs on your Termux/Phone)

```bash
python pareek.py linux
```

📡 10. Network Info

```bash
python pareek.py netinfo
```

📄 11. Log Analysis

Detect brute-force attempts in log files.

```bash
python pareek.py logscan /var/log/auth.log
```

📊 12. Generate Report

Save all your scan results.

```bash
# HTML report (Open in browser)
python pareek.py report -f html

# JSON report
python pareek.py report -f json

# CSV report (Open in Excel)
python pareek.py report -f csv
```

🤖 13. AI Assistant (Offline)

```bash
python pareek.py ai "hsts kya hai"
```

💡 Pro Tip: JSON Output

Add --json before the command to get raw output.

```bash
python pareek.py --json recon example.com
```

❓ Troubleshooting (Common Beginner Errors)

Q: python: command not found
A: Use python3 instead:

```bash
python3 pareek.py recon example.com
```

Q: error: the following arguments are required: cmd
A: You forgot to add the command. You must specify what to do. Example:

```bash
python pareek.py recon example.com
```

Q: Port scan is very slow or hanging.
A: Termux runs without root, so scans can be slow. Increase timeout:

```bash
python pareek.py portscan example.com --timeout 2.0
```

Q: Permission denied on /var/log/
A: Termux cannot access system logs without root. Use a custom log file path you can read.

⚠️ Disclaimer

This tool is strictly for authorized security testing and educational purposes only. The author (Bharat Pareek) is not responsible for any misuse or damage caused by this program. Always get written permission before scanning any system you do not own.

📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

👨‍💻 Author

Bharat Pareek

· GitHub: @ethicalpareek-sys

---
