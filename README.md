# PAREEK - Cybersecurity Recon Assistant for Termux

A single-file, lightweight cybersecurity toolkit designed to run smoothly on Termux (Android). 

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
