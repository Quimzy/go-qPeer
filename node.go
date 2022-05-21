package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"

	lib "github.com/quirkio/go-qPeer/qpeer"
	udp "github.com/quirkio/go-qPeer/qpeer/udp"
	upnp "github.com/quirkio/go-qPeer/qpeer/upnp"
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

func Server_TCP(lpeer lib.Lpeer, privkey *rsa.PrivateKey, pubkey_pem string, wg *sync.WaitGroup) { // Works with TCP && UPnP
	defer wg.Done()

	addr := ":1691"

	srv, err := net.Listen("tcp", addr)
	if err != nil {
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

		var firstmsg lib.Firstmsg
		json.Unmarshal(buffer[:n], &firstmsg)

		switch firstmsg.Msgtype {
		case "setup":
			var all_peers lib.All_peers
			if _, err := os.Stat("peers.json"); err == nil {
				all_peers = lib.Read_peers()
			}

			upnp.Server_setup(conn, all_peers, lpeer, privkey, pubkey_pem, firstmsg.Peerid)
		case "exchange_peers":
			var temp_peers []lib.Lpeer
			if _, err := os.Stat("temp_peers"); err == nil {
				temp_peers = lib.Read_temp_peers()
			}

			if lib.Check_peer(firstmsg.Peerid, lib.Read_peers().Offline_peers) {
				lib.Getback_peer(firstmsg.Peerid, lib.Read_peers())
			}

			upnp.Server_exchange_peers(conn, lib.Read_peers(), lpeer, temp_peers, firstmsg.Peerid, privkey)
		}
	}
}

func Client(conn_udp *net.UDPConn, lpeer lib.Lpeer, privkey *rsa.PrivateKey, pubkey_pem, bootsrap_AES_key, bootstrap_ip, bootstrap_port string, wg *sync.WaitGroup) { // TCP & UDP, longer function, more tears
	defer wg.Done()

	for {
		var all_peers lib.All_peers
		if _, err := os.Stat("peers.json"); err == nil {
			all_peers = lib.Read_peers()
			log.Println("Retrieving peers from db")
		}

		switch len(all_peers.Peers) {
		case 0: // no peers ?? bootstrap it
			upnp.Client_bootstrap(all_peers, lpeer, privkey, bootsrap_AES_key, bootstrap_ip, bootstrap_port)

			temp_peers := lib.Read_temp_peers()

			switch len(temp_peers) { //no temp_peers received from bootstrap ??
			case 0:
				upnp.Client_bootstrap(all_peers, lpeer, privkey, bootsrap_AES_key, bootstrap_ip, bootstrap_port)

			default: //let's setup some temp_peers
				rand.Seed(time.Now().UnixNano())
				temp_peer := temp_peers[rand.Intn(len(temp_peers))]
				proto := temp_peer.Protocol

				if proto == "udp" {
					endpoint := lib.LockEndpointUDP(conn_udp, temp_peer.Peerid, temp_peer.Endpoints)
					addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%s", endpoint.Ip, endpoint.Port))
					udp.Client_setup(conn_udp, addr, all_peers, lpeer, pubkey_pem)
				} else if proto == "upnp" {
					endpoint := temp_peer.Endpoints.PublicEndpoint
					upnp.Client_setup(all_peers, lpeer, endpoint.Ip, endpoint.Port, pubkey_pem)
				}
			}

		default: //there's peers, let's get more...
			var temp_peers []lib.Lpeer
			if _, err := os.Stat("temp_peers"); err == nil {
				temp_peers = lib.Read_temp_peers()
			}

			switch len(temp_peers) { //there's no temp_peers, let's get some...
			case 0:
				rand.Seed(time.Now().UnixNano())
				enc_peer := all_peers.Peers[rand.Intn(len(all_peers.Peers))]
				peer := lib.Decrypt_peer(enc_peer.Peerid, privkey, all_peers.Peers)

				var peerinfo lib.Peerinfo
				json.Unmarshal([]byte(peer.Peerinfo), &peerinfo)

				if peerinfo.Protocol == "udp" {
					endpoint := lib.LockEndpointUDP(conn_udp, peer.Peerid, peerinfo.Endpoints)
					addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%s", endpoint.Ip, endpoint.Port))
					udp.Client_exchange_peers(conn_udp, addr, all_peers, lpeer, privkey, peer.AES_key)

				} else if peerinfo.Protocol == "upnp" {
					endpoint := peerinfo.Endpoints.PublicEndpoint
					upnp.Client_exchange_peers(all_peers, lpeer, privkey, peer.AES_key, endpoint.Ip, endpoint.Port)
				}

			default: //let's setup some temp_peers
				rand.Seed(time.Now().UnixNano())
				temp_peer := temp_peers[rand.Intn(len(temp_peers))]
				proto := temp_peer.Protocol

				if proto == "udp" {
					endpoint := lib.LockEndpointUDP(conn_udp, temp_peer.Peerid, temp_peer.Endpoints)
					addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%s", endpoint.Ip, endpoint.Port))
					udp.Client_setup(conn_udp, addr, all_peers, lpeer, pubkey_pem)
				} else if proto == "upnp" {
					endpoint := temp_peer.Endpoints.PublicEndpoint
					upnp.Client_setup(all_peers, lpeer, endpoint.Ip, endpoint.Port, pubkey_pem)
				}
			}

		}
	}
}
