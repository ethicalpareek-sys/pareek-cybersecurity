#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PAREEK-CYBERSECURITY v1.0  —  single-file toolkit
Authorized security testing & education ONLY.
"""

import argparse, concurrent.futures, csv, datetime, hashlib, json
import math, os, re, socket, ssl, subprocess, sys
from pathlib import Path

try:    import requests
except: requests = None
try:    import dns.resolver
except: dns = None
try:    import whois as _whois
except: _whois = None

class C:
    RED="\033[91m"; GRN="\033[92m"; YEL="\033[93m"
    BLU="\033[94m"; MAG="\033[95m"; CYA="\033[96m"
    BOLD="\033[1m"; END="\033[0m"
def col(t,c): return f"{c}{t}{C.END}"

SESSION_FILE = Path.home() / "pareek_session.json"
FINDINGS = []

def finding(sev, title, detail=""):
    FINDINGS.append({"severity":sev,"title":title,"detail":detail})
    cmap = {"CRITICAL":C.RED,"HIGH":C.RED,"MEDIUM":C.YEL,
            "LOW":C.CYA,"INFO":C.BLU}
    print(f"  {col('['+sev+']',cmap.get(sev,C.END))} {title}"
          + (f" — {detail}" if detail else ""))

def save_session(module, data):
    sess = {"scans":[], "findings":[]}
    if SESSION_FILE.exists():
        try: sess = json.loads(SESSION_FILE.read_text())
        except Exception: pass
    sess["scans"].append({"module":module,
        "timestamp":datetime.datetime.now().isoformat(),
        "data":data})
    sess["findings"] = FINDINGS
    SESSION_FILE.write_text(json.dumps(sess, indent=2, default=str))

def out(data, as_json=False):
    if as_json: print(json.dumps(data, indent=2, default=str))

def _run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, text=True,
                stderr=subprocess.DEVNULL, timeout=15).strip()
    except Exception as e:
        return f"[err] {e}"

# ============== 1 + 7. RECON / OSINT ==============
def cmd_recon(a):
    t = a.target
    r = {"target": t}
    print(col(f"\n[*] Recon {t}", C.BOLD+C.CYA))
    if _whois:
        try:
            w = _whois.whois(t)
            r["whois"] = {"registrar": w.registrar,
                "created": str(w.creation_date),
                "expires": str(w.expiration_date),
                "ns": w.name_servers}
            print(f"  Registrar: {w.registrar}")
        except Exception as e:
            r["whois"] = {"error": str(e)}
    recs = {}
    if dns:
        for rt in ("A","AAAA","MX","NS","TXT","CNAME"):
            try:
                ans = dns.resolver.resolve(t, rt, lifetime=5)
                recs[rt] = [str(x) for x in ans]
            except Exception: pass
    r["dns"] = recs
    for k,v in recs.items(): print(f"  {k:5s}: {', '.join(v)}")
    try:
        ip = socket.gethostbyname(t); r["ip"] = ip
        print(f"  IP   : {ip}")
        try:
            r["rdns"] = socket.gethostbyaddr(ip)[0]
            print(f"  rDNS : {r['rdns']}")
        except Exception: pass
        if requests:
            try:
                info = requests.get(f"http://ip-api.com/json/{ip}",timeout=10).json()
                r["ip_info"] = info
                print(f"  ASN  : {info.get('as')}")
                print(f"  Geo  : {info.get('country')} / {info.get('isp')}")
            except Exception: pass
    except Exception: pass
    if requests:
        try:
            resp = requests.get(f"http://{t}", timeout=8, allow_redirects=True)
            tech = []
            for h in ("Server","X-Powered-By","X-AspNet-Version","Via"):
                if h in resp.headers: tech.append(f"{h}: {resp.headers[h]}")
            r["tech"] = tech
            for x in tech: print(f"  Tech : {x}")
        except Exception: pass
    save_session("recon", r); out(r, a.json)

# ============== 2. PORT SCAN ==============
COMMON = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,
    1521,1723,2049,2082,2083,2181,2375,3000,3306,3389,4443,5000,5432,
    5601,5900,5984,6379,7001,8000,8008,8080,8081,8443,8888,9000,9090,
    9200,9300,10000,11211,27017,50000]

def _scan(host, port, timeout):
    s = socket.socket(); s.settimeout(timeout)
    try:
        if s.connect_ex((host, port)) == 0:
            b = ""
            try:
                s.settimeout(1.5); s.sendall(b"\r\n")
                b = s.recv(512).decode(errors="ignore").strip()
            except Exception: pass
            return port, True, b
        return port, False, ""
    finally: s.close()

def cmd_portscan(a):
    host = a.target
    ports = COMMON
    if a.ports:
        ports = []
        for part in a.ports.split(","):
            if "-" in part:
                x,y = part.split("-"); ports += list(range(int(x), int(y)+1))
            else: ports.append(int(part))
    print(col(f"\n[*] TCP scan {host} ({len(ports)} ports)", C.BOLD+C.CYA))
    opens = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.threads) as ex:
        for f in concurrent.futures.as_completed(
                [ex.submit(_scan, host, p, a.timeout) for p in ports]):
            p, ok, banner = f.result()
            if ok:
                opens.append({"port":p,"banner":banner})
                m = f"  {col('OPEN',C.GRN)} {p}"
                if banner: m += f"  {banner[:80]}"
                print(m)
    if opens: finding("INFO", f"{len(opens)} open ports on {host}")
    r = {"host":host, "open_ports":opens}
    save_session("portscan", r); out(r, a.json)

# ============== 3 + 9. WEB / API ==============
SEC_HDRS = ["Strict-Transport-Security","Content-Security-Policy",
    "X-Frame-Options","X-Content-Type-Options","Referrer-Policy",
    "Permissions-Policy"]

def cmd_webcheck(a):
    if not requests: print(col("[!] requests missing",C.RED)); return
    url = a.target
    if not url.startswith("http"): url = "https://" + url
    print(col(f"\n[*] Web {url}", C.BOLD+C.CYA))
    try: resp = requests.get(url, timeout=10, allow_redirects=True)
    except Exception as e:
        print(col(f"[!] {e}", C.RED)); return
    r = {"url":url,"status":resp.status_code,
         "server":resp.headers.get("Server",""),
         "headers":dict(resp.headers)}
    print(f"  Status: {resp.status_code}  Server: {r['server']}")
    missing = [h for h in SEC_HDRS if h not in resp.headers]
    r["missing_headers"] = missing
    if "Strict-Transport-Security" in missing: finding("MEDIUM","No HSTS")
    if "Content-Security-Policy"  in missing: finding("MEDIUM","No CSP")
    if "X-Frame-Options"          in missing: finding("LOW","No X-Frame-Options")
    if "X-Content-Type-Options"   in missing: finding("LOW","No X-Content-Type-Options")
    cks = []
    for ck in resp.cookies:
        cks.append({"name":ck.name,"secure":ck.secure})
        if not ck.secure: finding("LOW", f"Cookie '{ck.name}' not Secure")
    r["cookies"] = cks
    for p in ("robots.txt","sitemap.xml",".git/config",".env","admin/","backup.zip"):
        try:
            rr = requests.get(url.rstrip("/")+"/"+p, timeout=6, allow_redirects=False)
            if rr.status_code == 200:
                r.setdefault("exposed",[]).append(p)
                sev = "HIGH" if p in (".env",".git/config","backup.zip") else "LOW"
                finding(sev, f"Exposed /{p}")
        except Exception: pass
    try:
        opt = requests.options(url, timeout=8)
        allow = opt.headers.get("Allow","")
        r["methods"] = allow
        if "TRACE" in allow: finding("MEDIUM","TRACE enabled")
        if "PUT" in allow or "DELETE" in allow:
            finding("MEDIUM", f"Dangerous methods: {allow}")
    except Exception: pass
    try:
        h = requests.get(url, timeout=8, headers={"Origin":"https://evil.example"})
        acao = h.headers.get("Access-Control-Allow-Origin","")
        r["cors"] = acao
        if acao == "*" or "evil.example" in acao:
            finding("MEDIUM", f"Loose CORS: {acao}")
    except Exception: pass
    save_session("webcheck", r); out(r, a.json)

# ============== 5. SSL/TLS ==============
def cmd_sslcheck(a):
    host = a.target; port = a.port or 443
    print(col(f"\n[*] TLS {host}:{port}", C.BOLD+C.CYA))
    r = {"host":host,"port":port}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host,port),timeout=10) as sk:
            with ctx.wrap_socket(sk, server_hostname=host) as ss:
                cert = ss.getpeercert()
                r["tls"] = ss.version(); r["cipher"] = ss.cipher()
                r["subject"] = dict(x[0] for x in cert.get("subject",[]))
                r["issuer"]  = dict(x[0] for x in cert.get("issuer",[]))
                r["not_before"]=cert.get("notBefore"); r["not_after"]=cert.get("notAfter")
    except Exception as e:
        print(col(f"[!] {e}", C.RED)); return
    try:
        exp = datetime.datetime.strptime(r["not_after"],"%b %d %H:%M:%S %Y %Z")
        days = (exp - datetime.datetime.utcnow()).days
        r["days"] = days
        print(f"  CN      : {r['subject'].get('commonName')}")
        print(f"  Issuer  : {r['issuer'].get('organizationName')}")
        print(f"  Expires : {r['not_after']} ({days} d)")
        print(f"  TLS     : {r['tls']}  Cipher: {r['cipher'][0]}")
        if days < 0: finding("HIGH","Cert expired")
        elif days < 15: finding("MEDIUM", f"Cert expires in {days} d")
        if r["tls"] in ("TLSv1","TLSv1.1"): finding("HIGH", f"Old {r['tls']}")
    except Exception: pass
    save_session("sslcheck", r); out(r, a.json)

# ============== 6. SUBDOMAINS (crt.sh) ==============
def cmd_subdomain(a):
    if not requests: print(col("[!] requests missing",C.RED)); return
    d = a.target
    print(col(f"\n[*] Subdomains {d}", C.BOLD+C.CYA))
    try:
        data = requests.get(f"https://crt.sh/?q=%25.{d}&output=json",timeout=30).json()
    except Exception as e:
        print(col(f"[!] {e}", C.RED)); return
    subs = sorted({n.strip().lower() for e in data for n in e["name_value"].split("\n")})
    for s in subs: print(f"  {s}")
    print(f"  → {len(subs)} subdomains")
    r = {"domain":d,"count":len(subs),"subdomains":subs}
    save_session("subdomain", r); out(r, a.json)

# ============== 4. VULN — NVD CVE ==============
def cmd_vuln(a):
    if not requests: print(col("[!] requests missing",C.RED)); return
    kw = a.target
    print(col(f"\n[*] CVE: {kw}", C.BOLD+C.CYA))
    try:
        data = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch":kw,"resultsPerPage":20}, timeout=30).json()
    except Exception as e:
        print(col(f"[!] {e}", C.RED)); return
    vulns = []
    for it in data.get("vulnerabilities",[]):
        c = it["cve"]
        desc = next((x["value"] for x in c["descriptions"] if x["lang"]=="en"),"")
        sev, sc = "UNKNOWN", None
        for k in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
            if k in c.get("metrics",{}):
                m = c["metrics"][k][0]["cvssData"]
                sev = m.get("baseSeverity",sev); sc = m.get("baseScore"); break
        vulns.append({"id":c["id"],"sev":sev,"score":sc,"desc":desc[:200]})
        print(f"  {col(c['id'],C.YEL)} [{sev}] {desc[:90]}")
    r = {"keyword":kw,"count":len(vulns),"vulns":vulns}
    save_session("vuln", r); out(r, a.json)

# ============== 8. PASSWORD LAB ==============
HASH_PATS = [(r"^[a-f0-9]{32}$","MD5"),(r"^[a-f0-9]{40}$","SHA-1"),
    (r"^[a-f0-9]{64}$","SHA-256"),(r"^[a-f0-9]{128}$","SHA-512"),
    (r"^\$2[aby]\$.{56}$","bcrypt"),(r"^\$argon2","Argon2"),
    (r"^\$6\$.+\$.+$","SHA-512-crypt"),(r"^\$5\$.+\$.+$","SHA-256-crypt"),
    (r"^\$1\$.{0,8}\$.{22}$","MD5-crypt")]

def cmd_password(a):
    pw = a.target
    print(col("\n[*] Password lab", C.BOLD+C.CYA))
    L = len(pw); pool = 0
    if re.search(r"[a-z]",pw): pool += 26
    if re.search(r"[A-Z]",pw): pool += 26
    if re.search(r"\d",pw):    pool += 10
    if re.search(r"[^A-Za-z0-9]",pw): pool += 33
    ent = L * math.log2(pool) if pool else 0
    common = pw.lower() in {"password","123456","qwerty","admin","letmein"}
    print(f"  length={L}  entropy={ent:.1f} bits  common={common}")
    if ent < 40: finding("HIGH", f"Weak entropy {ent:.1f}")
    elif ent < 60: finding("MEDIUM", f"Low entropy {ent:.1f}")
    else: finding("INFO", f"Good entropy {ent:.1f}")
    if common: finding("CRITICAL","In common wordlist")
    for n,f in (("MD5",hashlib.md5),("SHA1",hashlib.sha1),("SHA256",hashlib.sha256)):
        print(f"  {n}: {f(pw.encode()).hexdigest()}")
    r = {"length":L,"entropy":round(ent,1),"common":common}
    save_session("password", r); out(r, a.json)

def cmd_hashid(a):
    h = a.target
    print(col("\n[*] Hash ID", C.BOLD+C.CYA))
    for pat, name in HASH_PATS:
        if re.match(pat, h):
            print(f"  → {col(name, C.GRN)}")
            save_session("hashid", {"hash":h,"guess":name}); return
    print("  unknown")

# ============== 11. LINUX AUDIT ==============
def cmd_linux(a):
    print(col("\n[*] Linux audit", C.BOLD+C.CYA))
    r = {
        "kernel":_run("uname -a"),
        "users":_run("cut -d: -f1,3 /etc/passwd 2>/dev/null | awk -F: '$2>=1000'"),
        "listening":_run("ss -tulnp 2>/dev/null | head -30"),
        "suid":_run("find / -perm -4000 -type f 2>/dev/null | head -20"),
        "world_writable":_run("find /etc /usr/bin /usr/sbin -perm -o+w 2>/dev/null | head -10"),
        "ssh_root":_run("grep -i permitrootlogin /etc/ssh/sshd_config 2>/dev/null"),
    }
    for k,v in r.items(): print(f"  --{k}--\n{v[:400]}")
    if r["world_writable"]: finding("HIGH","World-writable files")
    if "yes" in r["ssh_root"].lower(): finding("MEDIUM","SSH root login allowed")
    save_session("linux", r); out(r, a.json)

# ============== 13. NETWORK INFO ==============
def cmd_netinfo(a):
    print(col("\n[*] Network", C.BOLD+C.CYA))
    r = {
        "interfaces":_run("ip -brief addr 2>/dev/null || ifconfig -a 2>/dev/null"),
        "routes":_run("ip route 2>/dev/null || route -n 2>/dev/null"),
        "arp":_run("ip neigh 2>/dev/null || arp -a 2>/dev/null"),
        "dns":_run("cat /etc/resolv.conf 2>/dev/null"),
        "connections":_run("ss -tun 2>/dev/null | head -30"),
    }
    for k,v in r.items(): print(f"  --{k}--\n{v[:400]}")
    save_session("netinfo", r); out(r, a.json)

# ============== 14. LOG ANALYSIS ==============
FAIL_RE = re.compile(r"Failed password|authentication failure|Invalid user", re.I)
IP_RE   = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def cmd_logscan(a):
    p = Path(a.target)
    if not p.exists(): print(col(f"[!] not found: {p}", C.RED)); return
    print(col(f"\n[*] Log {p}", C.BOLD+C.CYA))
    fails = 0; ips = {}; samples = []
    with p.open(errors="ignore") as f:
        for i, line in enumerate(f, 1):
            if FAIL_RE.search(line):
                fails += 1
                for ip in IP_RE.findall(line): ips[ip]=ips.get(ip,0)+1
                if len(samples) < 5: samples.append(f"{i}: {line.strip()[:120]}")
    top = sorted(ips.items(), key=lambda x:-x[1])[:10]
    print(f"  failed auths: {fails}")
    for ip,c in top: print(f"    {ip} x{c}")
    if fails > 20: finding("HIGH", f"Brute-force? {fails} fails")
    elif fails > 5: finding("MEDIUM", f"{fails} failed logins")
    r = {"file":str(p),"fails":fails,"top_ips":top,"samples":samples}
    save_session("logscan", r); out(r, a.json)

# ============== 18. REPORT ==============
SEV = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}

def cmd_report(a):
    if not SESSION_FILE.exists():
        print(col("[!] No scan yet", C.YEL)); return
    data = json.loads(SESSION_FILE.read_text())
    fmt = a.format or "json"
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    if fmt == "json":
        fn = f"pareek_report_{ts}.json"
        Path(fn).write_text(json.dumps(data, indent=2, default=str))
    elif fmt == "csv":
        fn = f"pareek_report_{ts}.csv"
        with open(fn,"w",newline="") as f:
            w = csv.writer(f); w.writerow(["Severity","Title","Detail"])
            for x in sorted(data.get("findings",[]), key=lambda x:SEV.get(x["severity"],9)):
                w.writerow([x["severity"],x["title"],x["detail"]])
    elif fmt == "html":
        fn = f"pareek_report_{ts}.html"
        rows = "".join(f"<tr class='{x['severity']}'><td>{x['severity']}</td>"
            f"<td>{x['title']}</td><td>{x['detail']}</td></tr>"
            for x in sorted(data.get("findings",[]), key=lambda x:SEV.get(x["severity"],9)))
        Path(fn).write_text(f"""<!doctype html><html><head><meta charset='utf-8'>
<title>PAREEK Report</title><style>body{{font-family:sans-serif;margin:2em}}
.CRITICAL,.HIGH{{background:#ffdddd}}.MEDIUM{{background:#fff3cd}}
.LOW{{background:#e2f0ff}}td{{padding:6px;border:1px solid #ccc}}
table{{border-collapse:collapse;width:100%}}</style></head><body>
<h1>PAREEK-CYBERSECURITY Report</h1><p>{datetime.datetime.now()}</p>
<table><tr><th>Severity</th><th>Title</th><th>Detail</th></tr>{rows}</table>
<h2>Scans</h2><pre>{json.dumps(data.get('scans',[]),indent=2,default=str)[:8000]}</pre>
</body></html>""")
    else:
        print(col(f"[!] unknown fmt {fmt}", C.RED)); return
    print(col(f"[+] Report: {fn}", C.GRN))

# ============== 19. AI ASSISTANT (offline) ==============
KB = {
    "hsts":"Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    "csp" :"Content-Security-Policy restricts resource origins. e.g. default-src 'self'",
    "cors":"Avoid Access-Control-Allow-Origin: *. Use a whitelist.",
    "tls" :"Disable TLS 1.0/1.1. Use TLS 1.2+ with AES-GCM or ChaCha20-Poly1305.",
    "cve" :"Check NVD for CVSS score, patch version, and vendor advisory.",
    "brute":"Add fail2ban, rate-limit auth, and enforce key-based SSH login.",
}
def cmd_ai(a):
    print(col("\n[*] AI Assistant (offline)", C.BOLD+C.CYA))
    q = a.target.lower(); hit = False
    for k,v in KB.items():
        if k in q: print(f"  → {v}"); hit = True
    if not hit: print("  No match. Extend KB dict in code.")

# ============== CLI ==============
def build():
    p = argparse.ArgumentParser(prog="pareek",
        description="PAREEK-CYBERSECURITY Toolkit",
        epilog="Authorized testing ONLY.")
    p.add_argument("--json", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, help_ in [("recon","Recon/OSINT"),("portscan","TCP scan"),
        ("webcheck","Web checks"),("sslcheck","TLS check"),
        ("subdomain","Subdomain enum"),("vuln","CVE lookup"),
        ("password","Password strength"),("hashid","Hash identify"),
        ("linux","Linux audit"),("netinfo","Network info"),
        ("logscan","Log analysis"),("report","Generate report"),
        ("ai","AI assistant")]:
        s = sub.add_parser(name, help=help_)
        if name == "portscan":
            s.add_argument("target")
            s.add_argument("-p","--ports"); s.add_argument("-t","--threads",type=int,default=100)
            s.add_argument("--timeout",type=float,default=1.0)
        elif name == "sslcheck":
            s.add_argument("target"); s.add_argument("-p","--port",type=int)
        elif name == "report":
            s.add_argument("-f","--format",choices=["json","csv","html"],default="json")
        elif name in ("linux","netinfo"): pass
        else:
            s.add_argument("target")
    return p

H = {"recon":cmd_recon,"portscan":cmd_portscan,"webcheck":cmd_webcheck,
     "sslcheck":cmd_sslcheck,"subdomain":cmd_subdomain,"vuln":cmd_vuln,
     "password":cmd_password,"hashid":cmd_hashid,"linux":cmd_linux,
     "netinfo":cmd_netinfo,"logscan":cmd_logscan,"report":cmd_report,
     "ai":cmd_ai}

def main():
    print(col("╔══════════════════════════════════════╗", C.MAG+C.BOLD))
    print(col("║  PAREEK-CYBERSECURITY v1.0           ║", C.MAG+C.BOLD))
    print(col("║  Authorized testing only             ║", C.MAG+C.BOLD))
    print(col("╚══════════════════════════════════════╝", C.MAG+C.BOLD))
    args = build().parse_args()
    try: H[args.cmd](args)
    except KeyboardInterrupt:
        print(col("\n[!] Interrupted", C.YEL)); sys.exit(1)

if __name__ == "__main__":
    main()
