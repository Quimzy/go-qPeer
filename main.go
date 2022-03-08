
package main

import("github.com/Quimzy/go-qPeer/qpeer"
	"fmt"
	"os"
	//"encoding/json"
	"net"
	"log"
)

//func Server()

//func Client()

func main(){
	var all_peers qpeer.All_peers
	//var temp_peers []qpeer.Lpeer

	privkey, pubkey := qpeer.Set_RSA_Keys()
	pubkey_pem := qpeer.RSA_ExportPubkey(pubkey)

	lpeer := qpeer.Set_lpeer(pubkey_pem)

	if _, err := os.Stat("peers.json"); err == nil{
		all_peers = qpeer.Read_peers()
	}

	addr := "localhost:1691" //Change to fmt.Sprintf("%s:%s", lpeer.Peerip, lpeer.Port)

	srv, err := net.Listen("tcp", addr)
	if err != nil{
		log.Fatal(err)
	}
	defer srv.Close()

	for {
		conn, err := srv.Accept()
		if err != nil{
			panic(err)
		}
		buffer := make([]byte, 2048)

		n, read_err := conn.Read(buffer)
		if read_err != nil {
			log.Fatal(read_err)
		}
		fmt.Println(string(buffer[:n]))

		all_peers = qpeer.Server_setup(conn, all_peers, lpeer, privkey, pubkey_pem)
		fmt.Println(all_peers)
	}

	//all_peers = qpeer.Client_setup(all_peers, lpeer, "localhost", "1691", pubkey_pem)
}