
package qpeer

import ("net"
	"log"
	"encoding/json"
	"crypto/rsa"
)

func send_init(conn net.Conn, init Init) string{//Recv AES_key
	jsonized_init, err := json.Marshal(init)

	_, write_err := conn.Write([]byte(jsonized_init))
	if write_err != nil{
		log.Fatal(write_err)
	}

	buffer := make([]byte, 2048)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		log.Fatal(read_err)
	}

	return string(buffer[:n])
}

func send_peerinfo_server(conn net.Conn, lpeer Lpeer, pubkey_pem string, AES_key string) string{//Recv kenc_peerinfo
	lpeerinfo := peerinfo(lpeer.Role, lpeer.Peerip, lpeer.Port, pubkey_pem)
	kenc_lpeerinfo := Kenc_peerinfo(lpeerinfo, AES_key)

	_, write_err := conn.Write([]byte(kenc_lpeerinfo))
	if write_err != nil{
		log.Fatal(write_err)
	}

	buffer := make([]byte, 2048)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		log.Fatal(read_err)
	}

	return string(buffer[:n])
}

func Server_setup(conn net.Conn, all_peers All_peers, lpeer Lpeer, pubkey_pem string, peerid string) All_peers{
	pubkey := RSA_ImportPubkey(pubkey_pem)
	init := Init_enc(lpeer.Peerid, pubkey_pem)

	AES_key := send_init(conn, init)

	kenc_peerinfo := send_peerinfo_server(conn, lpeer, pubkey_pem, AES_key)
	peerinfo := Dkenc_peerinfo(kenc_peerinfo, AES_key)

	switch strings.Compare(init.Peerid, peerid){
	case 0:
		all_peers = Save_peer(peerid, peerinfo, AES_key, pubkey, all_peers)
		Write_peers(all_peers)
	default:
	}

	send_bye(conn)
	buffer := make([]byte, 1024)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		log.Fatal(read_err)
	}

	if string(buffer[:n]) != "bye"{
		log.Fatal("Bye not received")
	}

	return all_peers
}