
package lib

import (
	//"github.com/quirkio/Endpoint/stun"
	"net"
	"fmt"
	"time"
)

func IsUDPOnline(peerip string, port string) bool{
	timeout := 5 * time.Second
	addr := fmt.Sprintf("%s:%s", peerip, port)
	
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil{
		return false
	}

	if conn != nil{
		conn.Close()
		return true
	}

	return false
}

func IsTCPOnline(peerip string, port string) bool{ //TCP && UPnP
	timeout := 5 * time.Second
	addr := fmt.Sprintf("%s:%s", peerip, port)
	
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil{
		return false
	}

	if conn != nil{
		conn.Close()
		return true
	}

	return false
}

func SetProto() (string, stun.Endpoints){}