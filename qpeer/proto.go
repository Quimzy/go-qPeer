
package lib

import (
	"github.com/quirkio/Endpoint/stun"
	"github.com/quirkio/Endpoint/upnp"
	"net"
	"fmt"
	"time"
)

func IsOnline(peerip string, port string) bool{ //TCP && UPnP
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

func IsPeeridValid(conn *net.UDPConn, peerid string, peerip string, port string) bool{
	//check if PrivateEndpoint is related to peer or not using peerid

	addr := fmt.Sprintf("%s:%s", peerip, port)

	_, write_err := conn.WriteToUDP([]byte("ping"), addr)

	buffer := make([]byte, 1024)
	n, read_err := conn.Read(buffer)
	if read_err != nil {
		log.Fatal(read_err)
	}
	recvd_peerid := string(buffer[:n])

	if recvd_peerid == peerid{
		return true
	}

	return false
}

func SetProto(AES_key, signal_ip, signal_port string) (*net.UDPConn, string, stun.Endpoints){
	var conn *net.UDPConn
	var proto string
	var endpoints stun.Endpoints
	
	//UDP
	
	proto = "udp"
	conn, endpoints = stun.Udp(AES_key, signal_ip, signal_port)
	
	if IsUDPOnline(endpoints.PublicEndpoint.Ip, endpoints.PublicEndpoint.Port) != true{
		//UPNP
		
		conn = nil 
		proto = "upnp"
		port := "1691"

		endpoints.PublicEndpoint = upnp.OpenPort(port)
		endpoints.PrivateEndpoint = endpoints.PublicEndpoint

		if IsOnline(endpoints.PublicEndpoint.Ip, endpoints.PublicEndpoint.Port) != true{
			//No method works, m sorry...

			conn = nil
			proto = ""
			endpoints = stun.Endpoints{} //empty endpoints		
		}
	}

	return conn, proto, endpoints
}

func LockEndpointUDP(conn *net.UDPConn, peerid string, endpoints stun.Endpoints) stun.Endpoint{
	privendpoint := endpoints.PrivateEndpoint
	if IsUDPOnline(privendpoint.Ip, privendpoint.Port) == true && IsPeeridValid(conn, peerid, peerip, port) == true{
		return privendpoint
	}

	return endpoints.PublicEndpoint
}