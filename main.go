
package main

import("github.com/Quimzy/go-qPeer/qpeer"
	"os"
	"encoding/json"
	"net"
	"log"
)

//func Client()

func main(){

	privkey, pubkey := qpeer.Set_RSA_Keys()
	pubkey_pem := qpeer.RSA_ExportPubkey(pubkey)

	lpeer := qpeer.Set_lpeer(pubkey_pem)

	addr := "localhost:1691"

	srv, err := net.Listen("tcp", addr)
	if err != nil{
		log.Fatal(err)
	}
	defer srv.Close()
	
	for {
		conn, err := srv.Accept()
        if err != nil {
            log.Fatal(err)
        }

        buffer := make([]byte, 2048)

		n, read_err := conn.Read(buffer)
		if read_err != nil {
			log.Fatal(read_err)
		}

		var firstmsg qpeer.Firstmsg
		json.Unmarshal(buffer[:n], &firstmsg)

		switch firstmsg.Msgtype{
		case "setup":
			var all_peers qpeer.All_peers
			if _, err := os.Stat("peers.json"); err == nil{
				all_peers = qpeer.Read_peers()
			}

			go qpeer.Server_setup(conn, all_peers, lpeer, privkey, pubkey_pem, firstmsg.Peerid)
		case "exchange_peers":
			var temp_peers []qpeer.Lpeer
			if _, err := os.Stat("temp_peers"); err == nil{
				temp_peers = qpeer.Read_temp_peers()
			}

			if qpeer.Check_peer(firstmsg.Peerid, qpeer.Read_peers().Offline_peers) == true{
				qpeer.Write_peers(qpeer.Getback_peer(firstmsg.Peerid, qpeer.Read_peers()))
			}

			go qpeer.Server_exchange_peers(conn, qpeer.Read_peers(), lpeer, temp_peers, firstmsg.Peerid, privkey)
		}
	}

}