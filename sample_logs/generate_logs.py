"""
ANBU Sentinel — Industry Log Generator
Generates realistic logs with CRITICAL / HIGH / MEDIUM / LOW severity threats
"""
import random, datetime, os

BASE = "/Users/surajbayas/Developer/Sentinel/sample_logs"
NOW  = datetime.datetime(2024, 4, 29, 0, 0, 0)

def ts(offset_secs=0):
    t = NOW + datetime.timedelta(seconds=offset_secs)
    return t.strftime("%d/%b/%Y:%H:%M:%S +0000")

def syslog_ts(offset_secs=0):
    t = NOW + datetime.timedelta(seconds=offset_secs)
    return t.strftime("%b %d %H:%M:%S")

def zeek_ts(offset_secs=0):
    t = NOW + datetime.timedelta(seconds=offset_secs)
    return str(t.timestamp())

# ────────────────────────────────────────────────────────────────────────────
# 1. apache_access.log  — 800 lines, mixed severity
# ────────────────────────────────────────────────────────────────────────────
CLEAN_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) AppleWebKit/605.1.15",
]
CLEAN_IPS   = ["10.0.1.5","10.0.2.10","192.168.1.50","203.0.113.200","198.51.100.5"]
CLEAN_PATHS = ["/","/home","/login","/dashboard","/api/v1/health","/static/main.css",
               "/images/logo.png","/api/v1/users","/api/orders","/contact","/about"]

# --- CRITICAL: SQL Injection bursts ---
SQLi_PAYLOADS = [
    "GET /search?q=1'+OR+'1'='1 HTTP/1.1",
    "GET /login?user=admin'--&pass=x HTTP/1.1",
    "POST /api/user?id=1;DROP TABLE users-- HTTP/1.1",
    "GET /products?id=1 UNION SELECT username,password FROM users-- HTTP/1.1",
    "GET /items?sort=name);INSERT INTO logs VALUES('pwned')-- HTTP/1.1",
    "GET /search?q=1' AND SLEEP(5)-- HTTP/1.1",
    "POST /api/auth?user=1' OR 1=1-- HTTP/1.1",
]

# --- HIGH: Brute Force ---
BRUTE_IPS = ["45.33.32.156","89.248.167.131","194.165.16.11","185.220.101.45","91.108.4.20"]

# --- MEDIUM: XSS ---
XSS_PAYLOADS = [
    "GET /search?q=<script>alert('xss')</script> HTTP/1.1",
    "GET /comment?text=<img src=x onerror=alert(1)> HTTP/1.1",
    "GET /profile?name=<svg onload=fetch('//evil.com')> HTTP/1.1",
    "POST /feedback?msg=<iframe src=javascript:alert(1)> HTTP/1.1",
]

# --- LOW: Directory Traversal / Scanner ---
TRAVERSAL = [
    "GET /../../../../etc/passwd HTTP/1.1",
    "GET /../../../etc/shadow HTTP/1.1",
    "GET /static/../../../etc/hosts HTTP/1.1",
    "GET /.git/config HTTP/1.1",
    "GET /.env HTTP/1.1",
    "GET /wp-admin/install.php HTTP/1.1",
    "GET /phpmyadmin/ HTTP/1.1",
    "GET /admin/login HTTP/1.1",
]

lines = []
t = 0

# Normal traffic baseline (400 lines)
for _ in range(400):
    ip   = random.choice(CLEAN_IPS)
    path = random.choice(CLEAN_PATHS)
    code = random.choice([200,200,200,200,304,301])
    size = random.randint(512, 8192)
    ua   = random.choice(CLEAN_UAS)
    lines.append(f'{ip} - - [{ts(t)}] "GET {path} HTTP/1.1" {code} {size} "-" "{ua}"')
    t += random.randint(1, 8)

# CRITICAL: SQLi burst from 3 IPs (80 lines)
sqli_ips = ["45.33.32.156","195.54.160.149","103.235.47.188"]
for _ in range(80):
    ip  = random.choice(sqli_ips)
    req = random.choice(SQLi_PAYLOADS)
    lines.append(f'{ip} - admin [{ts(t)}] "{req}" 500 320 "-" "sqlmap/1.7.8"')
    t += random.randint(1, 3)

# HIGH: Brute force login (120 lines)
for i in range(120):
    ip   = random.choice(BRUTE_IPS)
    code = 401 if i % 12 != 0 else 200   # occasional success
    lines.append(f'{ip} - - [{ts(t)}] "POST /login HTTP/1.1" {code} 180 "-" "python-requests/2.31.0"')
    t += random.randint(1, 2)

# MEDIUM: XSS probes (60 lines)
xss_ips = ["172.16.0.88","10.10.10.77","203.0.113.99"]
for _ in range(60):
    ip  = random.choice(xss_ips)
    req = random.choice(XSS_PAYLOADS)
    lines.append(f'{ip} - - [{ts(t)}] "{req}" 200 1024 "-" "Mozilla/5.0"')
    t += random.randint(2, 6)

# LOW: Directory/file traversal (80 lines)
scan_ips = ["198.51.100.88","91.108.4.20","172.20.0.3"]
for _ in range(80):
    ip  = random.choice(scan_ips)
    req = random.choice(TRAVERSAL)
    lines.append(f'{ip} - - [{ts(t)}] "{req}" 403 512 "-" "Nikto/2.1.6"')
    t += random.randint(3, 10)

# More normal traffic (60 lines)
for _ in range(60):
    ip   = random.choice(CLEAN_IPS)
    path = random.choice(CLEAN_PATHS)
    lines.append(f'{ip} - - [{ts(t)}] "GET {path} HTTP/1.1" 200 {random.randint(512,4096)} "-" "{random.choice(CLEAN_UAS)}"')
    t += random.randint(2, 10)

random.shuffle(lines[:400])   # shuffle normal traffic only
with open(f"{BASE}/apache_access.log", "w") as f:
    f.write("\n".join(lines) + "\n")
print(f"✅ apache_access.log — {len(lines)} lines")

# ────────────────────────────────────────────────────────────────────────────
# 2. syslog.log — 800 lines, SSH brute + port scan + privilege escalation
# ────────────────────────────────────────────────────────────────────────────
HOST = "prod-server-01"
lines2 = []
t = 0

# Normal syslog
for _ in range(300):
    lines2.append(f"{syslog_ts(t)} {HOST} systemd[1]: Started Daily apt download and install activities.")
    t += random.randint(10, 60)
    lines2.append(f"{syslog_ts(t)} {HOST} kernel: [UFW ALLOW] IN=eth0 SRC={random.choice(CLEAN_IPS)} DST=10.0.1.1 PROTO=TCP DPT=443")
    t += random.randint(5, 30)

# CRITICAL: SSH brute force (200 lines)
ssh_ips = ["45.33.32.156","194.165.16.11","185.220.101.45","91.240.118.222","192.168.100.55"]
for i in range(200):
    ip   = random.choice(ssh_ips)
    user = random.choice(["root","admin","ubuntu","pi","deploy","postgres","oracle"])
    lines2.append(f"{syslog_ts(t)} {HOST} sshd[{random.randint(1000,9999)}]: Failed password for {user} from {ip} port {random.randint(1024,65535)} ssh2")
    t += random.randint(1, 3)
    if i % 50 == 0:
        lines2.append(f"{syslog_ts(t)} {HOST} sshd[{random.randint(1000,9999)}]: Accepted password for {user} from {ip} port {random.randint(1024,65535)} ssh2")

# HIGH: Privilege escalation attempts (100 lines)
priv_ips = ["10.10.10.5","192.168.1.200"]
for _ in range(100):
    ip = random.choice(priv_ips)
    lines2.append(f"{syslog_ts(t)} {HOST} sudo: www-data : command not allowed ; TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash")
    t += random.randint(5, 20)
    lines2.append(f"{syslog_ts(t)} {HOST} sudo: pam_unix(sudo:auth): authentication failure; logname= uid=33 euid=0 rhost={ip}")
    t += random.randint(2, 10)

# MEDIUM: Port scan detected (100 lines)
scan_ip = "198.51.100.88"
for port in range(20, 120):
    lines2.append(f"{syslog_ts(t)} {HOST} kernel: [UFW BLOCK] IN=eth0 SRC={scan_ip} DST=10.0.1.1 PROTO=TCP DPT={port} SYN")
    t += random.randint(0, 1)

# LOW: Miscellaneous auth failures (100 lines)
for _ in range(100):
    ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    lines2.append(f"{syslog_ts(t)} {HOST} sshd[{random.randint(1000,9999)}]: Invalid user {random.choice(['test','ftp','user','guest'])} from {ip}")
    t += random.randint(5, 30)

with open(f"{BASE}/syslog.log", "w") as f:
    f.write("\n".join(lines2) + "\n")
print(f"✅ syslog.log — {len(lines2)} lines")

# ────────────────────────────────────────────────────────────────────────────
# 3. nginx_access.log — 600 lines, DDoS + credential stuffing
# ────────────────────────────────────────────────────────────────────────────
lines3 = []
t = 0
DDOS_IP_POOL = [f"31.184.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(50)]

# Normal traffic (200)
for _ in range(200):
    ip   = random.choice(CLEAN_IPS)
    path = random.choice(CLEAN_PATHS)
    lines3.append(f'{ip} - - [{ts(t)}] "GET {path} HTTP/1.1" {random.choice([200,304])} {random.randint(1000,9000)} "-" "{random.choice(CLEAN_UAS)}" rt={random.uniform(0.01,0.5):.3f}ms')
    t += random.randint(2, 15)

# CRITICAL: DDoS flood (200 lines)
for _ in range(200):
    ip = random.choice(DDOS_IP_POOL)
    lines3.append(f'{ip} - - [{ts(t)}] "GET / HTTP/1.1" 408 0 "-" "-" rt=30000ms')
    t += random.randint(0, 1)

# HIGH: Credential stuffing (100 lines)
cred_ips = ["103.235.47.188","194.165.16.11","45.79.97.39"]
for i in range(100):
    ip   = random.choice(cred_ips)
    code = 401 if i % 10 != 0 else 302
    lines3.append(f'{ip} - - [{ts(t)}] "POST /api/auth/login HTTP/1.1" {code} 256 "https://evil.com/" "Go-http-client/2.0"')
    t += random.randint(1, 4)

# MEDIUM: Scanner (100 lines)
for _ in range(100):
    ip   = random.choice(["172.21.0.5","10.50.0.99","209.141.36.13"])
    path = random.choice(["/wp-login.php","/.git/HEAD","/xmlrpc.php","/admin/","/phpmyadmin/","/backup.zip"])
    lines3.append(f'{ip} - - [{ts(t)}] "GET {path} HTTP/1.1" 404 153 "-" "masscan/1.3"')
    t += random.randint(2, 8)

with open(f"{BASE}/nginx_access.log", "w") as f:
    f.write("\n".join(lines3) + "\n")
print(f"✅ nginx_access.log — {len(lines3)} lines")

# ────────────────────────────────────────────────────────────────────────────
# 4. nginx_error.log — 300 lines, traversal + injection errors
# ────────────────────────────────────────────────────────────────────────────
def nts(offset):
    t2 = NOW + datetime.timedelta(seconds=offset)
    return t2.strftime("%Y/%m/%d %H:%M:%S")

lines4 = []
t = 0
ERR_IPS = ["198.51.100.88","91.108.4.20","172.20.0.3","5.188.86.172","192.168.1.100","31.184.198.23"]

for _ in range(60):
    ip = random.choice(CLEAN_IPS)
    lines4.append(f"{nts(t)} [warn] 1234#0: connect() failed (111: Connection refused) while connecting to upstream, client: {ip}, server: api.corp.internal")
    t += random.randint(20,60)

# CRITICAL: Directory traversal → /etc/passwd
for _ in range(80):
    ip   = random.choice(ERR_IPS)
    path = random.choice(["/../../../etc/passwd","/../../../proc/self/environ","/..%2F..%2F..%2Fetc%2Fshadow"])
    lines4.append(f'{nts(t)} [error] 5678#1: access forbidden by rule, client: {ip}, server: _, request: "GET {path} HTTP/1.1", host: "target.corp"')
    t += random.randint(3, 15)

# HIGH: Backend injection errors
for _ in range(80):
    ip = random.choice(ERR_IPS)
    lines4.append(f'{nts(t)} [error] 9999#2: upstream timed out (110: Connection timed out) while reading response header from upstream, client: {ip}')
    t += random.randint(5, 20)

# MEDIUM: File not found (recon)
for _ in range(80):
    ip   = random.choice(ERR_IPS)
    path = random.choice(["/admin","/backup","/db_backup.sql","/config.php","/wp-config.php"])
    lines4.append(f'{nts(t)} [error] 1111#1: open() "{path}" failed (2: No such file or directory), client: {ip}')
    t += random.randint(3, 10)

with open(f"{BASE}/nginx_error.log", "w") as f:
    f.write("\n".join(lines4) + "\n")
print(f"✅ nginx_error.log — {len(lines4)} lines")

# ────────────────────────────────────────────────────────────────────────────
# 5. auth.log — 500 lines, PAM failures + sudo abuse + account lockouts
# ────────────────────────────────────────────────────────────────────────────
lines5 = []
t = 0

# Normal sudo (100)
for _ in range(100):
    user = random.choice(["devops","alice","bob","deploy"])
    lines5.append(f"{syslog_ts(t)} {HOST} sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/apt-get update")
    t += random.randint(60, 300)

# CRITICAL: root login attempts (150)
root_ips = ["45.33.32.156","185.220.101.45","194.165.16.11","91.240.118.222"]
for _ in range(150):
    ip = random.choice(root_ips)
    lines5.append(f"{syslog_ts(t)} {HOST} sshd[{random.randint(1000,9999)}]: Failed password for root from {ip} port {random.randint(1024,65535)} ssh2")
    t += random.randint(1, 4)

# HIGH: PAM account lockouts (100)
for _ in range(100):
    user = random.choice(["admin","ubuntu","deploy","postgres"])
    ip   = random.choice(root_ips)
    lines5.append(f"{syslog_ts(t)} {HOST} pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip} user={user}")
    t += random.randint(2, 8)
    lines5.append(f"{syslog_ts(t)} {HOST} pam_tally2[{random.randint(1000,9999)}]: user {user} ({random.randint(1000,2000)}) tally {random.randint(5,50)}, deny 5")
    t += random.randint(1, 4)

# MEDIUM: Unknown user attempts (100)
for _ in range(100):
    ip   = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    user = random.choice(["test","ftp","www","oracle","user1","admin123"])
    lines5.append(f"{syslog_ts(t)} {HOST} sshd[{random.randint(1000,9999)}]: Invalid user {user} from {ip} port {random.randint(1024,65535)}")
    t += random.randint(3, 15)

with open(f"{BASE}/auth.log", "w") as f:
    f.write("\n".join(lines5) + "\n")
print(f"✅ auth.log — {len(lines5)} lines")

# ────────────────────────────────────────────────────────────────────────────
# 6. zeek_conn.csv — 400 rows, network anomalies + data exfiltration
# ────────────────────────────────────────────────────────────────────────────
header = "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto,service,duration,orig_bytes,resp_bytes,conn_state,missed_bytes,history,orig_pkts,orig_ip_bytes,resp_pkts,resp_ip_bytes"
rows = [header]
t = 0

# Normal connections (150)
for _ in range(150):
    src  = random.choice(CLEAN_IPS)
    sp   = random.randint(1024, 65535)
    dst  = random.choice(["10.0.0.1","10.0.0.2","192.168.1.1"])
    dp   = random.choice([80,443,8080,8443])
    dur  = round(random.uniform(0.01, 2.5), 6)
    ob   = random.randint(100, 5000)
    rb   = random.randint(200, 50000)
    rows.append(f"{zeek_ts(t)},C{random.randint(100000,999999)},{src},{sp},{dst},{dp},tcp,http,{dur},{ob},{rb},SF,0,ShADadfF,{random.randint(3,20)},{ob+40*3},{random.randint(3,20)},{rb+40*3}")
    t += random.randint(1, 10)

# CRITICAL: Data exfiltration (large outbound, 100 rows)
exfil_ips = ["45.33.32.156","195.54.160.149"]
for _ in range(100):
    src  = random.choice(["10.0.1.5","192.168.1.50"])
    dst  = random.choice(exfil_ips)
    sp   = random.randint(1024, 65535)
    dur  = round(random.uniform(10, 300), 6)
    ob   = random.randint(5_000_000, 50_000_000)  # large upload = exfil
    rb   = random.randint(100, 1000)
    rows.append(f"{zeek_ts(t)},C{random.randint(100000,999999)},{src},{sp},{dst},443,tcp,ssl,{dur},{ob},{rb},SF,0,ShADadfF,{random.randint(100,500)},{ob+40*200},{random.randint(3,10)},{rb+40*5}")
    t += random.randint(30, 120)

# HIGH: Port scan (many short connections, 100 rows)
scan_src = "198.51.100.88"
for port in range(1, 101):
    rows.append(f"{zeek_ts(t)},C{random.randint(100000,999999)},{scan_src},{random.randint(40000,65535)},10.0.1.5,{port},tcp,-,0,0,0,REJ,0,S,1,40,0,0")
    t += random.randint(0, 1)

# MEDIUM: Unusual external services (50 rows)
for _ in range(50):
    src = random.choice(["10.0.1.5","192.168.1.50"])
    dst = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    dp  = random.choice([4444,6666,1337,8888,31337])  # suspicious ports
    ob  = random.randint(100, 1000)
    rb  = random.randint(1000, 10000)
    rows.append(f"{zeek_ts(t)},C{random.randint(100000,999999)},{src},{random.randint(1024,65535)},{dst},{dp},tcp,-,{round(random.uniform(1,60),6)},{ob},{rb},SF,0,ShADadfF,5,{ob+200},5,{rb+200}")
    t += random.randint(10, 60)

with open(f"{BASE}/zeek_conn.csv", "w") as f:
    f.write("\n".join(rows) + "\n")
print(f"✅ zeek_conn.csv — {len(rows)-1} rows")

print(f"\n🎯 All 6 log files regenerated in {BASE}/")
