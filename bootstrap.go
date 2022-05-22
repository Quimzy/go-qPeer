package main

import (
	"crypto/rsa"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"sync"

	stun "github.com/quirkio/Endpoint/stun"
	lib "github.com/quirkio/go-qPeer/qpeer"
	upnp "github.com/quirkio/go-qPeer/qpeer/upnp"
)

func getmyip() string {
	req, err := http.Get("https://api.ipify.org")
	if err != nil {
		log.Fatal(err)
	}
	ip, _ := ioutil.ReadAll(req.Body)
	return string(ip)
}

func handling(lpeer lib.Lpeer, AES_key *string, privkey *rsa.PrivateKey, wg *sync.WaitGroup) { //handling node requests
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

		var all_peers lib.All_peers
		var temp_peers []lib.Lpeer
		if _, err := os.Stat("temp_peers"); err == nil {
			temp_peers = lib.Read_temp_peers()
		}

		upnp.Server_bootstrap(conn, all_peers, lpeer, temp_peers, *AES_key, privkey)
	}
}

func Bootstrap() {
	log.Println("qPeer bootstrap node started")

	//Setting RSA_keys
	privkey, pubkey := lib.Set_RSA_Keys()
	pubkey_pem := lib.RSA_ExportPubkey(pubkey)

	//Setting Endpoints
	var endpoints stun.Endpoints
	var endpoint stun.Endpoint
	endpoint.Ip = getmyip()
	endpoint.Port = "1691"
	//public and private endpoints are the same
	endpoints.PublicEndpoint = endpoint
	endpoints.PrivateEndpoint = endpoint

	//Setting Lpeer
	var lpeer lib.Lpeer
	lpeer.Peerid = lib.Sha1_encrypt(pubkey_pem)
	lpeer.Protocol = "tcp"
	lpeer.Endpoints = endpoints
	log.Println("Lpeer:", lpeer)

	//Setting AES_key for bootstrap node, u pick or i pick...
	var AES_key = flag.String("key", lib.AES_keygen(), "set bootstrap AES_key")
	log.Println("AES_key:", AES_key)

	//some goroutines and threading...
	var wg sync.WaitGroup
	wg.Add(2)

	go handling(lpeer, AES_key, privkey, &wg)
	go stun.Udp_Rendezvous(*AES_key, &wg)

	wg.Wait()
}
