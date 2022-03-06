
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

//Exchange peers

func send_kenc_verify(conn net.Conn, verify_msg string, AES_key string) string{
	kenc_verify := Kenc_verify(verify_msg, AES_key)

	_, write_err := conn.Write([]byte(kenc_verify))
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

func send_temp_peers(conn net.Conn, privkey *rsa.PrivateKey, peers []Peer, AES_key string) string{
	enc_temp_peers := Share_temp_peers(Return_temp_peers(privkey, peers), AES_key)

	_, write_err := conn.Write([]byte(enc_temp_peers))
	if write_err != nil{
		log.Fatal(write_err)
	}

	buffer := make([]byte, 8192)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		log.Fatal(read_err)
	}

	return string(buffer[:n])
}

func Server_exchange_peers(conn net.Conn, all_peers All_peers, temp_peers []Lpeer, AES_key string, privkey *rsa.PrivateKey) []Lpeer{
	verify_msg := RandomString(32)
	dkenc_verify := send_kenc_verify(conn, verify_msg, AES_key)

	if dkenc_verify != verify_msg{
		log.Fatal("Peer doesn't have the right AES_key")
	}

	recvd := send_temp_peers(conn, privkey, all_peers.Peers, AES_key)
	
	if recvd != "bye"{
		temp_peers = Save_temp_peers(enc_temp_peers, privkey, all_peers, AES_key, lpeer)
	}

	return temp_peers

}