package main

import (
	"os"
	"net"
	"log"
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"

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

func Bootstrap() {
	log.Println("qPeer bootstrap node started")

	//Setting RSA_keys
	privkey, pubkey := lib.Set_RSA_Keys()
	pubkey_pem := lib.RSA_ExportPubkey(pubkey)

	//Setting Endpoints
	var endpoints stun.Endpoints
	var endpoint stun.Endpoint
	endpoint = stun.Endpoint{getmyip(), "1691"}
	endpoints.PublicEndpoint = endpoint
	endpoints.PrivateEndpoint = endpoint

	lpeer := lib.Lpeer{lib.Sha1_encrypt(pubkey_pem), "tcp", endpoints}
	log.Println("Lpeer:", lpeer)

	AES_key := lib.AES_keygen() //Setting AES_key for bootstrap node
	log.Println("AES_key:", AES_key)

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

		go upnp.Server_bootstrap(conn, all_peers, lpeer, temp_peers, AES_key, privkey)
		go stun.Udp_Rendezvous(AES_key)

		//Add sync.Waitgroup support
	}
}
