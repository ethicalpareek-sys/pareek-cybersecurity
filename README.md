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
