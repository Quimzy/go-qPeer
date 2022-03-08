
package qpeer

import ("net"
	"log"
	"encoding/json"
	"fmt"
	"crypto/rsa"
	"strings"
)

// Setup

func greet_setup(conn net.Conn, peerid string) Init{
	msg, err := json.Marshal(Setup(peerid))
	if err != nil{
		log.Fatal(err)
	}
	_, write_err := conn.Write(msg)
	if write_err != nil{
		log.Fatal(write_err)
	}
	
	buffer := make([]byte, 2048)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		log.Fatal(read_err)
	}

	var init Init
	json.Unmarshal(buffer[:n], &init)

	return init

}

func send_key(conn net.Conn, AES_key string, pubkey *rsa.PublicKey) string{
	enc_AES_key := Penc_AES(AES_key, pubkey)

	_, write_err := conn.Write([]byte(enc_AES_key))
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

func send_peerinfo(conn net.Conn,lpeer Lpeer, pubkey_pem string, AES_key string) string{
	lpeerinfo := peerinfo(lpeer.Role, lpeer.Peerip, lpeer.Port, pubkey_pem)
	kenc_lpeerinfo := Kenc_peerinfo(lpeerinfo, AES_key)

	_, write_err := conn.Write([]byte(kenc_lpeerinfo))
	if write_err != nil{
		log.Fatal(write_err)
	}

	buffer := make([]byte, 1024)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		log.Fatal(read_err)
	}

	return string(buffer[:n])
}

func Send_bye(conn net.Conn){
	_, write_err := conn.Write([]byte("bye"))
	if write_err != nil{
		log.Fatal(write_err)
	}
}

func Client_setup(all_peers All_peers, lpeer Lpeer, peerip string, port string, pubkey_pem string) All_peers{
	pubkey := RSA_ImportPubkey(pubkey_pem)

	address := string(fmt.Sprintf("%s:%s", peerip, port))
	protocol := "tcp"
	
	conn, err := net.Dial(protocol, address)
	if err != nil{
		log.Fatal(err)
	}
	defer conn.Close()

	init := greet_setup(conn, lpeer.Peerid)
	if init.Peerid != Sha1_encrypt(init.Pubkey_pem){
		log.Fatal("Peerid doesn't match public key")
	}

	server_pubkey := RSA_ImportPubkey(init.Pubkey_pem)

	AES_key := AES_keygen()

	kenc_peerinfo := send_key(conn, AES_key, server_pubkey)
	peerinfo := Dkenc_peerinfo(kenc_peerinfo, AES_key)
	
	switch strings.Compare(init.Peerid, lpeer.Peerid){
	case 0:
		all_peers = Save_peer(init.Peerid, peerinfo, AES_key, pubkey, all_peers)
		Write_peers(all_peers)
	default:
	}
	
	bye := send_peerinfo(conn, lpeer, pubkey_pem, AES_key)
	if bye == "bye"{
		Send_bye(conn)
	}else{
		log.Fatal("Bye not received")
	}

	return all_peers
}

// Exchange Peers

func greet_exchange_peers(conn net.Conn, peerid string) string{
	msg, err := json.Marshal(Exchange_peers(peerid))
	if err != nil{
		log.Fatal(err)
	}
	_, write_err := conn.Write(msg)
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

func send_dkenc_verify(conn net.Conn, dkenc_verify string) string{
	_, write_err := conn.Write([]byte(dkenc_verify))
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

func send_temp_peers(conn net.Conn, privkey *rsa.PrivateKey, peers []Peer, AES_key string){
	enc_temp_peers := Share_temp_peers(Return_temp_peers(privkey, peers), AES_key)
	_, write_err := conn.Write([]byte(enc_temp_peers))
	if write_err != nil{
		log.Fatal(write_err)
	}

	buffer := make([]byte, 1024)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		log.Fatal(read_err)
	}

	if string(buffer[:n]) == "bye"{
		return
	}//Add panic(ByeError)
}

func Client_exchange_peers(all_peers All_peers, lpeer Lpeer, privkey *rsa.PrivateKey, AES_key string, peerip string, port string) []Lpeer{

	address := string(fmt.Sprintf("%s:%s", peerip, port))
	protocol := "tcp"
	
	conn, err := net.Dial(protocol, address)
	if err != nil{
		log.Fatal(err)
	}
	defer conn.Close()

	kenc_verify := greet_exchange_peers(conn, lpeer.Peerid)
	dkenc_verify := Dkenc_verify(kenc_verify, AES_key)

	enc_temp_peers := send_dkenc_verify(conn, dkenc_verify)
	temp_peers := Save_temp_peers(enc_temp_peers, privkey, all_peers, AES_key, lpeer)

	if len(all_peers.Peers) >= 5{
		send_temp_peers(conn, privkey, all_peers.Peers, AES_key)
	}else{
		Send_bye(conn)
	}

	return temp_peers

}

// Bootstrap

func send_lpeer(conn net.Conn, kenc_lpeer string) string{
	_, write_err := conn.Write([]byte(kenc_lpeer))
	if write_err != nil{
		log.Fatal(write_err)
	}

	buffer := make([]byte, 1024)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		log.Fatal(read_err)
	}

	return string(buffer[:n])
}

func Client_bootstrap(all_peers All_peers, lpeer Lpeer, privkey *rsa.PrivateKey, AES_key string, peerip string, port string) []Lpeer{

	address := string(fmt.Sprintf("%s:%s", peerip, port))
	protocol := "tcp"
	
	conn, err := net.Dial(protocol, address)
	if err != nil{
		log.Fatal(err)
	}
	defer conn.Close()

	kenc_verify := greet_exchange_peers(conn, lpeer.Peerid)
	dkenc_verify := Dkenc_verify(kenc_verify, AES_key)

	enc_temp_peers := send_dkenc_verify(conn, dkenc_verify)
	temp_peers := Save_temp_peers(enc_temp_peers, privkey, all_peers, AES_key, lpeer)

	kenc_lpeer := Kenc_lpeer(lpeer, AES_key)
	bye := send_lpeer(conn, kenc_lpeer)

	if bye != "bye"{//Improve this with better error handling
		log.Fatal("Bye wasn't received")
	}

	return temp_peers
}

// Ping

func Client_ping(all_peers All_peers, peerid string, privkey *rsa.PrivateKey) All_peers{
	peer := Decrypt_peer(peerid, privkey, all_peers.Peers)
	var peerinfo Peerinfo
	json.Unmarshal([]byte(peer.Peerinfo), &peerinfo)

	address := string(fmt.Sprintf("%s:%s", peerinfo.Peerip, peerinfo.Port))
	protocol := "tcp"

	conn, err := net.Dial(protocol, address)
	if err != nil{
		all_peers = Remove_peer(peer.Peerid, all_peers)
	}
	defer conn.Close()

	return all_peers
}

// Getback

func Client_getback(all_peers All_peers, peerid string, privkey *rsa.PrivateKey) All_peers{
	peer := Decrypt_peer(peerid, privkey, all_peers.Offline_peers)
	var peerinfo Peerinfo
	json.Unmarshal([]byte(peer.Peerinfo), &peerinfo)

	address := string(fmt.Sprintf("%s:%s", peerinfo.Peerip, peerinfo.Port))
	protocol := "tcp"

	conn, err := net.Dial(protocol, address)
	if err == nil{
		all_peers = Getback_peer(peer.Peerid, all_peers)
	}
	defer conn.Close()

	return all_peers
}
