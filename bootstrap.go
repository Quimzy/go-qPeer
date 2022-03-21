
package main

import("github.com/Quirk-io/go-qPeer/qpeer"
	"os"
	"net"
	"log"
	"encoding/json"
)

func Bootstrap(){
	log.Println("qPeer bootstrap node started")
	privkey, pubkey := qpeer.Set_RSA_Keys()
	pubkey_pem := qpeer.RSA_ExportPubkey(pubkey)

	AES_key := "" //Set AES_key for bootstrap node
	log.Println("AES_key:", AES_key)
	lpeer := qpeer.Set_lpeer(pubkey_pem)

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
	   
	    var all_peers qpeer.All_peers
	    var temp_peers []qpeer.Lpeer
		if _, err := os.Stat("temp_peers"); err == nil{
			temp_peers = qpeer.Read_temp_peers()
		}

		go qpeer.Server_bootstrap(conn, all_peers, lpeer, temp_peers, AES_key, privkey)
	}
}
