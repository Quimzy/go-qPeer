
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

func SetProto(AES_key, signal_ip, signal_port string) (*net.UDPConn, string, stun.Endpoints){
	var conn *net.UDPConn
	var proto string
	var endpoints stun.Endpoints
	endpoints = stun.Endpoints{} //empty endpoints

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
		}
	}

	return conn, proto, endpoints

}

func LockEndpoint(proto string, endpoints stun.Endpoints){
	
}