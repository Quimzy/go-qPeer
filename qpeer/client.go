
package qpeer

import ("net"
	"log"
	"encoding/json"
)

func Greet(conn net.Conn, peerid string) Init{
	msg, err := json.Marshal(Setup(peerid))
	if err != nil{
		log.Fatal(err)
	}
	_, write_err := conn.Write(msg)
	if write_err != nil{
		log.Fatal(write_err)
	}
	
	buffer := make([]byte, 1024)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		log.Fatal(read_err)
	}
	var recvd Init
	json.Unmarshal(buffer[:n], &recvd)
	return recvd

}

