
package main

import("github.com/Quimzy/go-qPeer/qpeer"
	//"fmt"
	"os"
	"encoding/json"
	"net"
	"log"
	"crypto/rsa"
)

func Server(srv net.Listener, lpeer qpeer.Lpeer, privkey *rsa.PrivateKey, pubkey_pem string){
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

		var setup qpeer.Qpeer
		json.Unmarshal(buffer[:n], &setup)

		switch setup.Msgtype{
		case "setup":
			go qpeer.Server_setup(conn, qpeer.Read_peers(), lpeer, privkey, pubkey_pem, setup.Peerid)
		case "exchange_peers":
			var temp_peers []qpeer.Lpeer
			if _, err := os.Stat("temp_peers"); err == nil{
				temp_peers = qpeer.Read_temp_peers()
			}

			if qpeer.Check_peer(setup.Peerid, qpeer.Read_peers().Offline_peers) == true{
				qpeer.Write_peers(qpeer.Getback_peer(setup.Peerid, qpeer.Read_peers()))
			}

			go qpeer.Server_exchange_peers(conn, qpeer.Read_peers(), lpeer, temp_peers, setup.Peerid, privkey)
		}
	}

}

//func Client()

func main(){
	var all_peers qpeer.All_peers

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

	go Server(srv, lpeer, privkey, pubkey_pem)

}