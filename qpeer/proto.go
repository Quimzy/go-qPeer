
package lib

import (
	"github.com/quirkio/Endpoint"
	"net"
	"fmt"
	"time"
)

func IsUDPOnline(peerip string, port string) bool{
	timeout := 5 * time.Second
	addr := fmt.Sprintf("%s:%s", host, port)
	
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

