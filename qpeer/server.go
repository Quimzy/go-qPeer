
package qpeer

import ("net"
	"log"
	"encoding/json"
	"crypto/rsa"
)

func send_init(conn net.Conn, init Init) string{//Recv AES_key
	jsonized_init, err := json.Marshal(init)
	if err != nil{
		log.Fatal(err)
	}

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
	lpeerinfo := peerinfo(lpeer.Peerip, lpeer.Port, pubkey_pem)
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

func Server_setup(conn net.Conn, all_peers All_peers, lpeer Lpeer, privkey *rsa.PrivateKey, pubkey_pem string, peerid string){
	pubkey := RSA_ImportPubkey(pubkey_pem)
	init := Init_enc(lpeer.Peerid, pubkey_pem)

	AES_key := Dpenc_AES(send_init(conn, init), privkey)

	kenc_peerinfo := send_peerinfo_server(conn, lpeer, pubkey_pem, AES_key)
	peerinfo := Dkenc_peerinfo(kenc_peerinfo, AES_key)

	if lpeer.Peerid != peerid{
		all_peers = Save_peer(peerid, peerinfo, AES_key, pubkey, all_peers)
		Write_peers(all_peers)		
	}
	
	Send_bye(conn)
	buffer := make([]byte, 1024)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		log.Fatal(read_err)
	}

	if string(buffer[:n]) != "bye"{
		log.Fatal("Bye not received")
	}

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

func send_temp_peers_server(conn net.Conn, privkey *rsa.PrivateKey, temp_peers []Lpeer, AES_key string) string{
	enc_temp_peers := Share_temp_peers(temp_peers, AES_key)

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


func Server_exchange_peers(conn net.Conn, all_peers All_peers, lpeer Lpeer, temp_peers []Lpeer, peerid string, privkey *rsa.PrivateKey){
	peer := Decrypt_peer(peerid, privkey, all_peers.Peers) 

	verify_msg := RandomString(32)
	dkenc_verify := send_kenc_verify(conn, verify_msg, peer.AES_key)

	if dkenc_verify != verify_msg{
		log.Fatal("Peer doesn't have the right AES_key")
	}

	recvd := send_temp_peers_server(conn, privkey, Return_temp_peers(privkey, all_peers.Peers), peer.AES_key)
	
	if recvd != "bye"{
		Save_temp_peers(recvd, privkey, all_peers, peer.AES_key, lpeer)
	}
}

// Bootstrap

func Server_bootstrap(conn net.Conn, all_peers All_peers, lpeer Lpeer, temp_peers []Lpeer, AES_key string, privkey *rsa.PrivateKey){
	verify_msg := RandomString(32)
	dkenc_verify := send_kenc_verify(conn, verify_msg, AES_key)
	if dkenc_verify != verify_msg{
		log.Fatal("Peer doesn't have the right AES_key")
	}

	temp_peer := send_temp_peers_server(conn, privkey, Return_temp_peers_bootstrap(privkey, temp_peers), AES_key)
	Save_temp_peers(temp_peer, privkey, all_peers, AES_key, lpeer)

	Send_bye(conn)

}