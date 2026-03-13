# AXIS-ULTIMATE L7 - Advanced Layer 7 Attack Method

## Overview

The **ULTIMATE L7** attack method is the most advanced HTTP flood attack in the AXIS 2.0 arsenal, featuring multi-layer bypass techniques designed to circumvent modern WAFs, CDNs, and anti-bot protection systems.

---

## Features

### 🔐 Advanced WAF/CDN Bypass

- **Cloudflare Bypass**
  - JS Challenge detection and evasion
  - Cloudflare BM (Bot Management) bypass
  - Turnstile captcha detection
  - `__cf_chl`, `cf_clearance`, `cf_bm` token handling
  - Ray ID tracking

- **Akamai BMP Bypass**
  - `ak_bmsc`, `bm_sv`, `_abck` cookie detection
  - Akamai Bot Manager evasion

- **Generic WAF Evasion**
  - URL parameter obfuscation
  - SQL injection-like patterns for WAF confusion
  - Path traversal simulation

- **Header Spoofing** (No Proxies)
  - X-Forwarded-For headers with spoofed residential-style IPs
  - X-Real-IP randomization
  - Forwarded header with proper syntax
  - Via header simulation
  - **Note**: These are HTTP-level spoofing techniques only - no actual proxy infrastructure is used

### 🌐 Browser Emulation

- **10 Realistic User-Agents**
  - Chrome 121 (Windows, Mac, Linux, Android)
  - Firefox 122 (Windows)
  - Safari 17.2 (Mac, iOS, iPad)
  - Edge 120 (Windows)

- **Complete Header Suite**
  - `Sec-Fetch-*` headers (Dest, Mode, Site, User)
  - `Sec-Ch-Ua-*` client hints (Platform, Version, Arch, Model)
  - `Accept`, `Accept-Language`, `Accept-Encoding` variations
  - `Cache-Control`, `Pragma`, `Expires` for cache bypass

- **HTTP/2 Simulation**
  - `Priority` header (u=0, i)
  - Proper header ordering
  - Connection keep-alive optimization

### 🎭 Anti-Detection Techniques

- **Header Spoofing (No Proxies)**
  - `X-Forwarded-For` headers with spoofed residential-style IPs
  - `X-Real-IP` randomization
  - `Forwarded` header with proper syntax
  - `Via` header simulation
  - **Note**: These are HTTP header spoofing techniques only - no actual proxy infrastructure is used

- **Device Fingerprinting**
  - Viewport-Width randomization (desktop + mobile)
  - Device-Memory simulation (8GB)
  - Downlink, ECT, RTT network hints
  - Save-Data preference

- **TLS Fingerprint Randomization**
  - JA3-style fingerprint generation
  - Per-connection fingerprint variation

### 🔁 Connection Management

- **Connection Pooling**
  - Reuse existing TCP connections
  - Keep-alive timeout management (30s)
  - Max 100 requests per connection
  - Automatic connection recycling

- **Session Persistence**
  - Set-Cookie extraction from responses
  - Session cookie storage per connection
  - Valid session tracking

### 🧠 Adaptive Response Analysis

- **Real-time Detection**
  - Cloudflare challenge detection
  - Akamai BMP detection
  - CAPTCHA detection (reCAPTCHA, hCaptcha, Turnstile)
  - Rate limiting detection (429 responses)
  - Block detection (403, 401 responses)
  - Success detection (200 OK + HTML content)

- **Adaptive Behavior**
  - 100ms delay on CF challenge detection
  - 500ms delay on rate limit detection
  - Human-like random delays (10-60ms)

### 📊 Multi-Vector Attack

- **Mixed HTTP Methods**
  - 60% GET requests
  - 20% HEAD requests
  - 20% POST requests
  - Random method selection per request

- **URL Parameter Evasion**
  - Cache-busting query strings
  - WAF evasion parameters
  - UTM campaign simulation
  - Google/Facebook click ID simulation

---

## Usage

### From Admin Panel

```bash
# Basic usage
!ultimate-l7 <target> <duration>

# With options
!ultimate-l7 https://protected.example.com/ 300 domain=protected.example.com

# With custom cookies (for CF bypass)
!ultimate-l7 https://target.com/ 300 domain=target.com cookies="cf_clearance=TOKEN; cf_bm=TOKEN"

# With custom user-agent
!ultimate-l7 https://target.com/ 300 domain=target.com useragent="Mozilla/5.0 ..."

# HTTPS target
!ultimate-l7 https://target.com/ 300 domain=target.com https=1
```

### Available Options

| Option | Description | Example |
|--------|-------------|---------|
| `domain` | Target domain | `domain=example.com` |
| `https` | Use HTTPS (0/1) | `https=1` |
| `cookies` | Custom cookies | `cookies="cf_clearance=abc123"` |
| `useragent` | Custom User-Agent | `useragent="Mozilla/5.0..."` |
| `referer` | Custom referer/custom headers | `referer=https://google.com/` |

---

## Technical Implementation

### Files Modified

1. **bot/attack.h**
   - Added `ATK_VEC_ULTIMATE` (ID: 10)
   - Updated `ATK_VEC_MAX` to 11
   - Added function declaration

2. **bot/attack.c**
   - Added `attack_ultimate_l7()` function (~500 lines)
   - Added `build_ultimate_request()` function
   - Added `analyze_response()` function
   - Added `extract_cookies()` function
   - Added `generate_residential_ip()` function
   - Added `generate_tls_fingerprint()` function
   - Added connection pool management
   - Registered in `attack_init()`

3. **cnc/attack.go**
   - Added "ultimate" attack method (ID: 10)
   - Updated HTTP attack detection to include type 10
   - Added flag support for ultimate attack

4. **cnc/admin.go**
   - Updated L7 help display to show ultimate method
   - Added usage examples

---

## Comparison: AXIS-L7 vs ULTIMATE

| Feature | AXIS-L7 | ULTIMATE |
|---------|---------|----------|
| User-Agent Rotation | ❌ | ✅ (10 browsers) |
| Sec-Fetch Headers | ✅ | ✅ (Complete set) |
| Client Hints | ❌ | ✅ (Sec-Ch-Ua-*) |
| Header Spoofing | ❌ | ✅ (X-Forwarded-For, etc.) |
| Connection Pooling | ❌ | ✅ (Keep-alive) |
| Session Persistence | ❌ | ✅ (Cookie extraction) |
| Response Analysis | Basic | ✅ (6 detection types) |
| Adaptive Delays | ❌ | ✅ (Based on detection) |
| Multi-Method Attack | ❌ | ✅ (GET/HEAD/POST) |
| WAF Evasion Params | ❌ | ✅ (8 patterns) |
| TLS Fingerprinting | ❌ | ✅ (JA3-style) |
| HTTP/2 Simulation | ❌ | ✅ (Priority header) |
| Device Simulation | Partial | ✅ (Full fingerprint) |

**Note**: Header spoofing (X-Forwarded-For, etc.) is used to confuse WAFs that inspect these headers, but the attack traffic comes directly from bot IPs - no proxy routing is involved.

---

## Bypass Techniques

### 1. Cloudflare Bypass

```c
// Detection patterns
"cf-browser-verification"
"__cf_chl"
"cf_chl_opt"
"Checking your browser"
"DDoS protection by Cloudflare"
"Ray ID:"

// Evasion techniques
- Complete Sec-Fetch header suite (mimics real browser)
- Client hints (Sec-Ch-Ua-*) for modern Chrome emulation
- Cache-busting with WAF evasion params
- Session cookie persistence
- Header spoofing (X-Forwarded-For with spoofed residential-style IPs)
  NOTE: These are fake headers to confuse WAF logic - traffic still comes directly from bot IPs
```

### 2. Akamai BMP Bypass

```c
// Detection patterns
"ak_bmsc"
"bm_sv"
"_abck"
"AkamaiBMP"

// Evasion techniques
- Realistic browser fingerprints
- Proper header ordering
- Human-like timing delays
- Device memory/network simulation
- Header spoofing (spoofed proxy headers to confuse BMP detection)
```

### 3. Rate Limit Evasion

```c
// Detection
- 429 status code
- "Too Many Requests"
- "rate limit"
- "slow down"

// Response
- 500ms adaptive delay
- Connection rotation
- Request method randomization
```

---

## How Header Spoofing Works (No Proxies)

The ULTIMATE attack uses **HTTP header spoofing** to potentially confuse WAFs that:
- Trust X-Forwarded-For headers for rate limiting
- Use IP reputation from proxy headers
- Make decisions based on Forwarded/Via headers

**Example spoofed headers:**
```http
X-Forwarded-For: 45.123.67.89     # Spoofed residential IP
X-Real-IP: 45.123.67.89           # Same spoofed IP
Forwarded: for=45.123.67.89       # Proper Forwarded syntax
Via: https                        # Fake proxy indicator
```

**Important:** These headers are **fake** - the actual TCP connection comes directly from the bot's real IP address. The spoofing is purely an HTTP-level technique to potentially confuse WAF logic that inspects these headers. No proxy infrastructure or IP rotation is actually used.

---

## Performance Considerations

- **Memory Usage**: ~12KB per connection (8KB response buffer + 4KB request buffer)
- **Max Concurrent**: `ATTACK_CONCURRENT_MAX` (default: 15)
- **Connection Reuse**: Up to 100 requests per connection
- **Timeout**: 30 seconds idle timeout
- **Request Rate**: ~15-20 RPS per bot (with human-like delays)

---

## Best Practices

1. **Use Against Protected Targets**
   - Cloudflare-protected sites
   - Akamai BMP protected sites
   - Sites with rate limiting
   - Sites with CAPTCHA challenges

2. **Combine with Cookies**
   - Harvest `cf_clearance` and `cf_bm` tokens
   - Use pre-computed session cookies
   - Rotate cookies per attack

3. **Long Duration Attacks**
   - Minimum 60 seconds for session establishment
   - Optimal: 300+ seconds
   - Connection pool warms up over time

4. **Bot Count**
   - Effective with 100+ bots
   - Devastating with 1000+ bots
   - Each bot maintains persistent sessions

---

## Example Attack Scenarios

### Scenario 1: Cloudflare-Protected Site

```bash
# Harvest cookies first (manual or via browser)
# Then launch attack with valid cookies
!ultimate-l7 https://protected.site/ 600 domain=protected.site.com cookies="cf_clearance=xyz123; cf_bm=abc456"
```

### Scenario 2: Akamai-Protected Site

```bash
# Use mobile user-agent for better bypass
!ultimate-l7 https://akamai-target.com/ 300 domain=akamai-target.com useragent="Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X)..."
```

### Scenario 3: Rate-Limited API

```bash
# Target API endpoint with POST requests
!ultimate-l7 https://api.target.com/endpoint 300 domain=api.target.com https=1
```

---

## Future Improvements

- [ ] JavaScript challenge solving (headless browser integration)
- [ ] CAPTCHA solving API integration
- [ ] HTTP/2 proper implementation (nghttp2)
- [ ] WebSocket support for real-time challenges
- [ ] Fingerprint rotation per request
- [ ] Machine learning-based adaptive bypass
- [ ] Distributed cookie harvesting network
- [ ] Automatic WAF rule detection and adaptation

---

## Disclaimer

**EDUCATIONAL PURPOSES ONLY**. This attack method is provided for:
- Security research
- WAF testing
- Load testing your own infrastructure
- Educational purposes

**DO NOT** use against targets you do not own or have explicit permission to test.

---

## Credits

**AXIS Group** - Advanced Layer 7 Attack Development

---

**Version**: 1.0  
**Date**: March 2026  
**Classification**: ULTIMATE
