# AXIS-TCP and AXIS-UDP - Advanced Layer 4 Combined Attack Methods

## Overview

The **AXIS-TCP** and **AXIS-UDP** attack methods are the most comprehensive Layer 4 DDoS attacks in the AXIS 2.0 arsenal, combining **multiple volumetric attack vectors** into single coordinated assaults with advanced bypass techniques.

---

## Features

### 🎯 Multi-Vector Attack

**AXIS-TCP (5 Attack Vectors):**
- TCP SYN flood with TCP options (40% of traffic)
- OVH TCP bypass (30% of traffic)
- ICMP ping flood (10% of traffic)
- GRE IP encapsulation (10% of traffic)
- GRE Ethernet encapsulation (10% of traffic)

**AXIS-UDP (11 Attack Vectors):**
- UDP flood (20-25% of traffic)
- OVH UDP bypass (15-17% of traffic)
- DNS Amplification (10-12% of traffic)
- NTP Amplification (10-12% of traffic)
- SSDP Amplification (10-12% of traffic)
- SNMP Amplification (10% of traffic)
- CLDAP Amplification (5% of traffic)
- VSE Source Engine Query (10-3% of traffic)
- ICMP ping flood (5-2% of traffic)
- GRE IP encapsulation (3-1% of traffic)
- GRE Ethernet encapsulation (2-1% of traffic)

**Weighted Distribution:**
- Intelligent traffic distribution for maximum impact
- Prevents any single vector from being filtered easily
- Forces target to defend against multiple attack types simultaneously

### 🎭 Advanced Bypass Techniques

**TCP Option Randomization (AXIS-TCP):**
- Random MSS (Maximum Segment Size): 536, 1460, 2048, 4096, 8192
- Random Window Scale: 0-8
- Random Timestamps: enabled/disabled
- Proper TCP options encoding with padding
- Confuses TCP-based DDoS mitigation

**Fragmentation Attack Support:**
- IP fragmentation to confuse reassembly logic
- Two-fragment packets (header + payload)
- Same fragment ID for proper reassembly
- Bypasses some DDoS mitigation appliances

**Adaptive Vector Weighting:**
- Two weight profiles: standard and adaptive
- AXIS-TCP adaptive: More TCP (50%), less GRE (5-7%)
- AXIS-UDP adaptive: More amplification (78%), less GRE (1-2%)
- Enabled via `adaptive=1` flag

**OVH Game Bypass:**
- TCP: SYN+ACK+PSH+URG flags combination
- UDP: DNS-like header structure
- Designed to bypass OVH Game protection systems

**GRE Encapsulation:**
- Double encapsulation (GRE IP)
- Triple encapsulation (GRE Ethernet)
- Bypasses some DDoS mitigation appliances

**Random TTL Values:**
- Randomized Time-To-Live: 32, 64, 128, 255
- Evades TTL-based filtering
- Complicates traffic analysis

**Random TOS Field:**
- Randomized Type of Service values
- Bypasses QoS-based prioritization
- Confuses traffic classification systems

### 📊 Intelligent Attack Coordination

- **Weighted Vector Selection**
  - Random selection based on predefined weights
  - Ensures consistent distribution across all vectors
  - Prevents predictable patterns

- **Efficient Socket Management**
  - Separate raw sockets for each protocol
  - Minimal resource overhead
  - High packet rate capability

---

## Usage

### From Admin Panel

```bash
# AXIS-TCP - Basic usage
!axis-tcp <target> <duration>

# AXIS-TCP - With custom packet size
!axis-tcp 1.2.3.4 300 len=1400

# AXIS-TCP - With specific TCP port
!axis-tcp 1.2.3.4 300 tcpport=80

# AXIS-TCP - With GRE port
!axis-tcp 1.2.3.4 300 tcpport=443 greport=27015

# AXIS-TCP - With fragmentation
!axis-tcp 1.2.3.4 300 tcpport=80 fragment=1

# AXIS-TCP - With adaptive weighting
!axis-tcp 1.2.3.4 300 tcpport=80 adaptive=1

# AXIS-TCP - With TCP options
!axis-tcp 1.2.3.4 300 tcpport=80 mss=1460 wscale=7 timestamp=1

# AXIS-UDP - Basic usage
!axis-udp <target> <duration>

# AXIS-UDP - With custom packet size
!axis-udp 1.2.3.4 300 len=1400

# AXIS-UDP - With specific UDP port
!axis-udp 1.2.3.4 300 udpport=53

# AXIS-UDP - With GRE port
!axis-udp 1.2.3.4 300 udpport=27015 greport=27015

# AXIS-UDP - With adaptive weighting
!axis-udp 1.2.3.4 300 udpport=53 adaptive=1

# Combined options
!axis-tcp 1.2.3.4 300 tcpport=80 mss=1460 wscale=7 timestamp=1 fragment=1 adaptive=1
```

### Available Options

| Option | Description | Example | Default |
|--------|-------------|---------|---------|
| `len` | Packet payload size in bytes | `len=1400` | 1400 |
| `tcpport` | TCP destination port (AXIS-TCP) | `tcpport=80` | Random |
| `udpport` | UDP destination port (AXIS-UDP) | `udpport=53` | Random |
| `greport` | GRE destination port | `greport=27015` | Random |
| `sport` | Source port | `sport=12345` | Random |
| `source` | Source IP address | `source=1.2.3.4` | Random |
| `fragment` | Enable IP fragmentation | `fragment=1` | 0 |
| `mss` | TCP MSS option value | `mss=1460` | Random |
| `wscale` | TCP window scale value | `wscale=7` | Random |
| `timestamp` | Enable TCP timestamps | `timestamp=1` | Random |
| `adaptive` | Enable adaptive vector weighting | `adaptive=1` | 0 |

---

## Technical Implementation

### Files Modified

1. **bot/attack.h**
   - Added `ATK_VEC_AXIS_TCP` (ID: 9)
   - Added `ATK_VEC_AXIS_UDP` (ID: 10)
   - Added new option flags: `ATK_OPT_FRAGMENT`, `ATK_OPT_TCP_MSS`, `ATK_OPT_TCP_WSCALE`, `ATK_OPT_TCP_TIMESTMP`, `ATK_OPT_ADAPTIVE`
   - Updated `ATK_VEC_MAX` to 16

2. **bot/attack.c**
   - Added `attack_axis_tcp()` function with fragmentation and adaptive support
   - Added `attack_axis_udp()` function with adaptive support
   - Added `send_fragmented_tcp()` function for IP fragmentation
   - Enhanced `send_ultimate_tcp()` with TCP option randomization
   - Registered in `attack_init()`

3. **cnc/attack.go**
   - Added "axis-tcp" attack method (ID: 9)
   - Added "axis-udp" attack method (ID: 10)
   - Added flag support for new options

4. **cnc/admin.go**
   - Updated L4 help display to show axis-tcp and axis-udp methods
   - Added help for new flags: `fragment`, `mss`, `wscale`, `timestamp`, `adaptive`

---

## Attack Vector Details

### AXIS-TCP Vectors

#### 1. TCP Flood with Options (40%)

**Characteristics:**
- Raw TCP SYN flood with TCP options
- Random MSS (536-8192 bytes)
- Random window scale (0-8)
- Random timestamps (enabled/disabled)
- Configurable packet size (default: 1400 bytes)
- Optimized for maximum bandwidth (Gbps)

**TCP Options:**
```c
/* MSS Option (Kind=2, Len=4) */
opts[0] = 2;  /* Kind: MSS */
opts[1] = 4;  /* Length: 4 */
opts[2] = (mss >> 8) & 0xFF;
opts[3] = mss & 0xFF;

/* Window Scale Option (Kind=3, Len=3) */
opts[4] = 3;  /* Kind: Window Scale */
opts[5] = 3;  /* Length: 3 */
opts[6] = wscale;  /* Shift count */

/* Timestamps Option (Kind=8, Len=10) - optional */
opts[7] = 8;  /* Kind: Timestamps */
opts[8] = 10; /* Length: 10 */
```

**Purpose:** Overwhelms TCP connection tracking, confuses TCP-based filtering

---

#### 2. OVH TCP Bypass (30%)

**Characteristics:**
- TCP with special flag combination
- SYN+ACK+PSH+URG flags set
- Designed to bypass OVH Game protection
- Appears as established connection traffic

**Bypass Technique:**
```c
tcph->syn = TRUE;
tcph->ack = TRUE;
tcph->psh = TRUE;
tcph->urg = TRUE;  // Unusual flag combination
```

**Purpose:** Evades OVH-style TCP mitigation filters

---

#### 3. ICMP Flood (10%)

**Characteristics:**
- ICMP Echo Request (Ping) flood
- No port dependency (Layer 3)
- Consumes ICMP rate limits
- Bypasses port-based filtering

**Purpose:** Additional pressure, targets IP stack directly

---

#### 4. GRE IP Flood (10%)

**Characteristics:**
- Outer IP header (real bot IP)
- GRE header (protocol 47)
- Inner IP header (spoofed source)
- Inner UDP payload
- Double encapsulation

**Packet Structure:**
```
[Outer IP][GRE Header][Inner IP][UDP Header][Payload]
   (real)              (spoofed)
```

**Purpose:** Evades simple packet inspection, bypasses some appliances

---

#### 5. GRE Ethernet Flood (10%)

**Characteristics:**
- Outer IP header (real bot IP)
- GRE header (ETH_P_TEB)
- Fake Ethernet header (6 bytes)
- Inner IP header (spoofed source)
- Inner UDP payload
- Triple encapsulation

**Packet Structure:**
```
[Outer IP][GRE Header][Ethernet][Inner IP][UDP][Payload]
   (real)             (fake)     (spoofed)
```

**Purpose:** Maximum confusion for DDoS mitigation systems

---

### AXIS-UDP Vectors

#### 1. UDP Flood (20-25%)

**Characteristics:**
- Raw UDP flood
- Random payload generation
- Optimized for maximum bandwidth (Gbps)
- Configurable packet size

**Purpose:** Overwhelms UDP services, consumes bandwidth

---

#### 2. OVH UDP Bypass (15-17%)

**Characteristics:**
- UDP with DNS-like header structure
- Transaction ID randomization
- Query format mimics DNS response
- Designed to bypass OVH Game protection

**Bypass Technique:**
```c
payload[0] = transaction_id_high;
payload[1] = transaction_id_low;
payload[2] = 0x01;  // Standard query
payload[3] = 0x00;
// ... DNS-like structure
```

**Purpose:** Confuses UDP flood filters, appears as DNS traffic

---

#### 3-7. Amplification Attacks (45-52% combined)

**DNS Amplification (10-12%):**
- ANY query for google.com
- 50x-100x amplification factor

**NTP Amplification (10-12%):**
- monlist command
- 100x-500x amplification factor

**SSDP Amplification (10-12%):**
- M-SEARCH request
- 30x-50x amplification factor

**SNMP Amplification (10%):**
- GetBulk request
- 50x-100x amplification factor

**CLDAP Amplification (5%):**
- LDAP search request
- 50x-70x amplification factor

---

#### 8. VSE Source Engine Query (10-3%)

**Characteristics:**
- Source Engine query packet
- 0xFF 0xFF 0xFF 0xFF "TSource Engine Query"
- Triggers response from game servers

**Purpose:** Additional pressure on game servers

---

#### 9. ICMP Flood (5-2%)

**Characteristics:**
- ICMP Echo Request flood
- No port dependency (Layer 3)
- Varied TTL values

**Purpose:** Additional pressure on IP stack

---

#### 10-11. GRE Floods (3-1% combined)

**GRE IP (3-1%)** and **GRE Ethernet (2-1%)**
- Same as AXIS-TCP GRE vectors
- Lower weight in adaptive mode

---

## Comparison: L4 Attack Methods

| Method | Vectors | TCP Options | Fragmentation | Adaptive | OVH Bypass | GRE | Best For |
|--------|---------|-------------|---------------|----------|------------|-----|----------|
| **tcp** | TCP only | ❌ | ❌ | ❌ | ❌ | ❌ | Basic TCP flood |
| **udp** | UDP only | ❌ | ❌ | ❌ | ❌ | ❌ | Basic UDP flood |
| **ovhtcp** | TCP | ❌ | ❌ | ❌ | ✅ | ❌ | OVH TCP bypass |
| **ovhudp** | UDP | ❌ | ❌ | ❌ | ✅ | ❌ | OVH UDP bypass |
| **icmp** | ICMP | ❌ | ❌ | ❌ | ❌ | ❌ | Layer 3 attack |
| **greip** | GRE-IP | ❌ | ❌ | ❌ | ❌ | ✅ | Encapsulation |
| **greeth** | GRE-ETH | ❌ | ❌ | ❌ | ❌ | ✅ | Triple encapsulation |
| **axis-tcp** | **5 vectors** | ✅ | ✅ | ✅ | ✅ | ✅ | **TCP services** |
| **axis-udp** | **11 vectors** | ❌ | ❌ | ✅ | ✅ | ✅ | **UDP services** |

---

## Performance Characteristics

### Resource Usage

- **Sockets:** 3-4 raw sockets (TCP, UDP, ICMP, GRE)
- **Memory:** ~8KB per attack instance (with TCP options)
- **CPU:** Moderate (packet generation + checksums + options)
- **Bandwidth:** Maximum available (all vectors combined)

### Packet Rate

With typical bot hardware:
- **Small bots (100 Mbps):** ~30,000 PPS combined
- **Medium bots (1 Gbps):** ~300,000 PPS combined
- **Large bots (10 Gbps):** ~3,000,000 PPS combined

### Effectiveness

| Target Type | AXIS-TCP | AXIS-UDP | Notes |
|-------------|----------|----------|-------|
| Unprotected | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Overwhelming |
| Basic firewall | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Multiple vectors |
| OVH Game | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | OVH bypass included |
| Rate-limited | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | Multi-vector pressure |
| Cloudflare | ⭐⭐⭐ | ⭐⭐⭐ | L4 saturation only |
| AWS Shield | ⭐⭐ | ⭐⭐ | Anycast + scrubbing |

---

## Best Practices

### 1. Use Against Protected Targets

**AXIS-TCP** is most effective against:
- TCP-based services (HTTP, HTTPS, SSH)
- OVH Game-protected game servers
- Services with TCP rate limiting
- Targets with basic DDoS protection

**AXIS-UDP** is most effective against:
- UDP-based services (DNS, VoIP, gaming)
- OVH Game-protected UDP services
- Services with UDP rate limiting
- Amplification-friendly targets

### 2. Combine with Other Attacks

For maximum impact:
```bash
# Start AXIS-TCP for TCP saturation
!axis-tcp 1.2.3.4 300 tcpport=80 fragment=1 adaptive=1

# Simultaneously hit with AXIS-UDP
!axis-udp 1.2.3.4 300 udpport=53 adaptive=1

# Add L7 attack for application pressure
!axis-l7 https://1.2.3.4/ 300 domain=target.com
```

### 3. Optimal Duration

- **Minimum:** 60 seconds (to overwhelm buffers)
- **Optimal:** 300+ seconds (sustained pressure)
- **Maximum:** As allowed by botnet limits

### 4. Port Selection

**AXIS-TCP:**
- Web services: tcpport=80, 443
- Gaming: tcpport=27015, 7777, 25565
- SSH: tcpport=22
- Mail: tcpport=25, 587

**AXIS-UDP:**
- DNS: udpport=53
- Gaming: udpport=27015, 7777
- VoIP: udpport=5060, 5061
- NTP: udpport=123

---

## Example Attack Scenarios

### Scenario 1: OVH Game Server

```bash
# Target: OVH-protected game server (TCP)
!axis-tcp 1.2.3.4 300 tcpport=27015 fragment=1 adaptive=1

# Target: OVH-protected game server (UDP)
!axis-udp 1.2.3.4 300 udpport=27015 adaptive=1
```

**Why it works:**
- OVH TCP/UDP bypass flags
- Multiple vectors overwhelm filters
- Fragmentation confuses reassembly
- GRE may bypass inspection

---

### Scenario 2: Web Service

```bash
# Target: HTTP/HTTPS service
!axis-tcp 1.2.3.4 300 tcpport=80 mss=1460 wscale=7 timestamp=1

# Add L7 for application layer
!axis-l7 https://target.com/ 300 domain=target.com
```

**Why it works:**
- TCP options confuse filtering
- L4 overwhelms network stack
- L7 targets application layer

---

### Scenario 3: DNS Server

```bash
# Target: DNS infrastructure
!axis-udp 1.2.3.4 300 udpport=53 adaptive=1
```

**Why it works:**
- UDP appears as DNS traffic
- DNS amplification (50-100x)
- ICMP adds pressure
- Adaptive weighting optimizes for DNS

---

### Scenario 4: Combined L4 + L7

```bash
# Layer 4 saturation (TCP)
!axis-tcp 1.2.3.4 300 tcpport=80 fragment=1 adaptive=1

# Layer 4 saturation (UDP)
!axis-udp 1.2.3.4 300 udpport=53 adaptive=1

# Layer 7 application attack
!axis-l7 https://target.com/ 300 domain=target.com
```

**Why it works:**
- L4 overwhelms network infrastructure
- L7 targets application logic
- Defense must split resources across layers

---

## Limitations

### 1. No Proxy Infrastructure

**Important:** AXIS-TCP and AXIS-UDP do **NOT** use:
- Residential proxies
- VPN networks
- Tor routing
- Any relay infrastructure

All traffic originates directly from bot IPs.

### 2. Return Traffic

Since some packets may have spoofed sources (GRE, fragmentation):
- Return traffic goes to wrong IPs
- Attack doesn't need responses (fire-and-forget)
- This is intentional

### 3. Effectiveness Varies

Against advanced protection:
- Cloudflare: Limited (they handle L4 well)
- AWS Shield: Limited (anycast + scrubbing)
- Akamai: Limited (distributed mitigation)
- Basic firewalls: Highly effective

---

## Implemented Improvements (v2.0)

### ✅ TCP Option Randomization
- Random MSS (536-8192 bytes)
- Random window scale (0-8)
- Random timestamps (enabled/disabled)
- Proper TCP options encoding with padding

### ✅ Fragmentation Attack Support
- IP fragmentation to confuse reassembly
- Two-fragment packets (header + payload)
- Same fragment ID for proper reassembly
- Enabled via `fragment=1` flag

### ✅ Adaptive Vector Weighting
- Two weight profiles: standard and adaptive
- AXIS-TCP adaptive: More TCP (50%), less GRE (5-7%)
- AXIS-UDP adaptive: More amplification (78%), less GRE (1-2%)
- Enabled via `adaptive=1` flag

---

## Technical Specifications

### Packet Sizes

| Vector | Min Size | Max Size | Default |
|--------|----------|----------|---------|
| TCP (with options) | 52 bytes | 65535 bytes | 1400 bytes |
| TCP (fragmented) | 72 bytes | 65535 bytes | 1400 bytes |
| UDP | 28 bytes | 65535 bytes | 1400 bytes |
| ICMP | 28 bytes | 65535 bytes | 350 bytes |
| GRE-IP | 48 bytes | 65535 bytes | 1400 bytes |
| GRE-ETH | 54 bytes | 65535 bytes | 1400 bytes |

### Protocol Numbers

| Protocol | Number |
|----------|--------|
| TCP | 6 |
| UDP | 17 |
| ICMP | 1 |
| GRE | 47 |

### TCP Option Types

| Option | Kind | Length |
|--------|------|--------|
| MSS | 2 | 4 |
| Window Scale | 3 | 3 |
| Timestamps | 8 | 10 |
| NOP (padding) | 1 | 1 |
| End of Options | 0 | 1 |

### Port Ranges

| Service Type | Port Range |
|--------------|------------|
| Well Known | 0-1023 |
| Registered | 1024-49151 |
| Dynamic/Private | 49152-65535 |

---

## Disclaimer

**EDUCATIONAL PURPOSES ONLY**. This attack method is provided for:
- Security research
- DDoS mitigation testing
- Network stress testing (your own infrastructure)
- Educational purposes

**DO NOT** use against targets you do not own or have explicit permission to test.

Unauthorized use of DDoS tools is **illegal** in most jurisdictions and can result in:
- Criminal charges
- Civil liability
- Imprisonment
- Fines

---

## Credits

**AXIS Group** - Advanced Layer 4 Attack Development

---

**Version**: 2.0  
**Date**: March 2026  
**Classification**: AXIS

**Related Documentation:**
- `AXIS-L7_README.md` - AXIS-L7 Layer 7 attack documentation
- `README.md` - Complete AXIS 2.0 documentation
