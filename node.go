
package main

import("github.com/quirkio/go-qPeer/qpeer"
	"os"
	"encoding/json"
	"net"
	"crypto/rsa"
	"log"
	"math/rand"
	"time"
	"sync"
	"os/signal"
	"syscall"
)

func Server(lpeer qpeer.Lpeer, privkey *rsa.PrivateKey, pubkey_pem string, wg *sync.WaitGroup){
	defer wg.Done()
	
	addr := ":1691"

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
			log.Println("Retrieving peers from db")
		}

		switch len(all_peers.Peers){
		case 0:
			AES_key := ""
			peerip := ""

			qpeer.Client_bootstrap(all_peers, lpeer, privkey, AES_key, peerip, "1691") // Change AES_key, peerip, port respectively. AES_key should be the same as what's set in the bootsrap node
			temp_peers := qpeer.Read_temp_peers()
			
			switch len(temp_peers){
			case 0:
				qpeer.Client_bootstrap(all_peers, lpeer, privkey, AES_key, peerip, "1691")
			default:
				rand.Seed(time.Now().UnixNano())
				temp_peer := temp_peers[rand.Intn(len(temp_peers))]
				qpeer.Client_setup(all_peers, lpeer, temp_peer.Peerip, temp_peer.Port, pubkey_pem)
			}
			
		default:
			var temp_peers []qpeer.Lpeer
			if _, err := os.Stat("temp_peers"); err == nil{
				temp_peers = qpeer.Read_temp_peers()
			}
			switch len(temp_peers){
			case 0:
				rand.Seed(time.Now().UnixNano())
				enc_peer := all_peers.Peers[rand.Intn(len(all_peers.Peers))]
				peer := qpeer.Decrypt_peer(enc_peer.Peerid, privkey, all_peers.Peers)
				
				var peerinfo qpeer.Peerinfo 
				json.Unmarshal([]byte(peer.Peerinfo), &peerinfo)
				err := qpeer.Client_exchange_peers(all_peers, lpeer, privkey, peer.AES_key, peerinfo.Peerip, peerinfo.Port)
				if err != nil{
					all_peers = qpeer.Remove_peer(peer.Peerid, all_peers)			
				}

			default:
				rand.Seed(time.Now().UnixNano())
				temp_peer := temp_peers[rand.Intn(len(temp_peers))]
				qpeer.Client_setup(all_peers, lpeer, temp_peer.Peerip, temp_peer.Port, pubkey_pem)
			}
		}
	}
}

func Ping(privkey *rsa.PrivateKey, wg *sync.WaitGroup){
	for {
		var all_peers qpeer.All_peers
		if _, err := os.Stat("peers.json"); err == nil{
			all_peers = qpeer.Read_peers()
		}
		if len(all_peers.Peers) > 0{
			rand.Seed(time.Now().UnixNano())
			enc_peer := all_peers.Peers[rand.Intn(len(all_peers.Peers))]
			peer := qpeer.Decrypt_peer(enc_peer.Peerid, privkey, all_peers.Peers)

			qpeer.Client_ping(all_peers, peer.Peerid, privkey)
		}
	}
}

func Getback(privkey *rsa.PrivateKey, wg *sync.WaitGroup){
	for {
		var all_peers qpeer.All_peers
		if _, err := os.Stat("peers.json"); err == nil{
			all_peers = qpeer.Read_peers()
		}
		if len(all_peers.Offline_peers) > 0{
			rand.Seed(time.Now().UnixNano())
			enc_peer := all_peers.Offline_peers[rand.Intn(len(all_peers.Offline_peers))]
			peer := qpeer.Decrypt_peer(enc_peer.Peerid, privkey, all_peers.Offline_peers)

			qpeer.Client_getback(all_peers, peer.Peerid, privkey)
		}
	}
}

func Node(){
	log.Println("qPeer node started")
	privkey, pubkey := qpeer.Set_RSA_Keys()
	pubkey_pem := qpeer.RSA_ExportPubkey(pubkey)

	lpeer := qpeer.Set_lpeer(pubkey_pem)
	var wg sync.WaitGroup
	wg.Add(4)

	go Client(lpeer, privkey, pubkey_pem, &wg)
	go Server(lpeer, privkey, pubkey_pem, &wg)
	go Ping(privkey, &wg)
	go Getback(privkey, &wg)
	
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
	    <-c
	    err := os.Remove("temp_peers")
	    if err != nil{
	    	log.Fatal(err)
	    }
	    os.Exit(1)
	}()

	wg.Wait()
}
