package main

import (
	"crypto/rsa"
	"encoding/json"
	"log"
	"net"
	"os"
	"sync"

	lib "github.com/quirkio/go-qPeer/qpeer"
	udp "github.com/quirkio/go-qPeer/qpeer/udp"
)

// UDP is different from TCP. Two server functions for each protocol, one long client function for both.
//Server_UDP && Server_TCP do the same thing, but on different protocols. Can we join them into one function?

func Server_UDP(conn *net.UDPConn, privkey *rsa.PrivateKey, pubkey_pem string, lpeer lib.Lpeer, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		buffer := make([]byte, 2048)

		n, public_addr, read_err := conn.ReadFromUDP(buffer)
		if read_err != nil {
			log.Fatal(read_err)
		}

		var firstmsg lib.Firstmsg
		json.Unmarshal(buffer[:n], &firstmsg)

		switch firstmsg.Msgtype {
		case "setup":
			var all_peers lib.All_peers
			if _, err := os.Stat("peers.json"); err == nil {
				all_peers = lib.Read_peers()
			}

			udp.Server_setup(conn, public_addr, all_peers, lpeer, privkey, pubkey_pem, firstmsg.Peerid)

		case "exchange_peers":
			var temp_peers []lib.Lpeer
			if _, err := os.Stat("temp_peers"); err == nil {
				temp_peers = lib.Read_temp_peers()
			}

			if lib.Check_peer(firstmsg.Peerid, lib.Read_peers().Offline_peers) {
				lib.Getback_peer(firstmsg.Peerid, lib.Read_peers())
			}

			udp.Server_exchange_peers(conn, public_addr, lib.Read_peers(), lpeer, temp_peers, firstmsg.Peerid, privkey)
		}

	}
}
