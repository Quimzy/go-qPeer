
package main

import("github.com/Quimzy/go-qPeer/qpeer"
	"os"
	"encoding/json"
	"net"
	"crypto/rsa"
	"log"
	"math/rand"
	"time"
	"fmt"
	"sync"
)

func Server(lpeer qpeer.Lpeer, privkey *rsa.PrivateKey, pubkey_pem string, wg *sync.WaitGroup){
	defer wg.Done()
	
	addr := "localhost:1691"

	srv, err := net.Listen("tcp", addr)
	if err != nil{
		log.Fatal(err)
	}
	defer srv.Close()
	
	for{
		conn, err := srv.Accept()
	    if err != nil {
	        log.Fatal(err)
	    }
	    fmt.Println(conn)
	        	
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

			qpeer.Server_setup(conn, all_peers, lpeer, privkey, pubkey_pem, firstmsg.Peerid)
		case "exchange_peers":
			var temp_peers []qpeer.Lpeer
			if _, err := os.Stat("temp_peers"); err == nil{
				temp_peers = qpeer.Read_temp_peers()
			}

			if qpeer.Check_peer(firstmsg.Peerid, qpeer.Read_peers().Offline_peers) == true{
				qpeer.Write_peers(qpeer.Getback_peer(firstmsg.Peerid, qpeer.Read_peers()))
			}

			qpeer.Server_exchange_peers(conn, qpeer.Read_peers(), lpeer, temp_peers, firstmsg.Peerid, privkey)
		}
	}
}

func Client(lpeer qpeer.Lpeer, privkey *rsa.PrivateKey, pubkey_pem string, wg *sync.WaitGroup){
	defer wg.Done()
	
	for {
		var all_peers qpeer.All_peers
		if _, err := os.Stat("peers.json"); err == nil{
			all_peers = qpeer.Read_peers()
		}

		switch len(all_peers.Peers){
		case 0:
			fmt.Println("Bootstrap")
			qpeer.Client_bootstrap(all_peers, lpeer, privkey, "", "", "") // Change AES_key, peerip, port respectively. AES_key should be the same as what's set in the bootsrap node
		default:
			var temp_peers []qpeer.Lpeer
			if _, err := os.Stat("temp_peers"); err == nil{
				temp_peers = qpeer.Read_temp_peers()
			}
			switch len(temp_peers){
			case 0:
				fmt.Println("Exchange_peers")
				rand.Seed(time.Now().UnixNano())
				enc_peer := all_peers.Peers[rand.Intn(len(all_peers.Peers))]
				peer := qpeer.Decrypt_peer(enc_peer.Peerid, privkey, all_peers.Peers)
				
				var peerinfo qpeer.Peerinfo 
				json.Unmarshal([]byte(peer.Peerinfo), &peerinfo)
				err := qpeer.Client_exchange_peers(all_peers, lpeer, privkey, peer.AES_key, peerinfo.Peerip, peerinfo.Port)
				if err != nil{
					all_peers = qpeer.Remove_peer(peer.Peerid, all_peers)			}

			default:
				fmt.Println("Setup")
				temp_peer := temp_peers[rand.Intn(len(temp_peers))]
				qpeer.Client_setup(all_peers, lpeer, temp_peer.Peerip, temp_peer.Port, pubkey_pem)
			}
		}
	}
}

func main(){

	privkey, pubkey := qpeer.Set_RSA_Keys()
	pubkey_pem := qpeer.RSA_ExportPubkey(pubkey)

	lpeer := qpeer.Set_lpeer(pubkey_pem)
	
	var wg sync.WaitGroup
	wg.Add(2)
	go Client(lpeer, privkey, pubkey_pem, &wg)
	
	go Server(lpeer, privkey, pubkey_pem, &wg)
		
	wg.Wait()


}