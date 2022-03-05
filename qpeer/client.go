
package qpeer

import ("net"
	"log"
	"encoding/json"
	"fmt"
	"crypto/rsa"
)

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

	var recvd Init
	json.Unmarshal(buffer[:n], &recvd)

	return recvd

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

	buffer := make([]byte, 8192)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		log.Fatal(read_err)
	}

	return string(buffer[:n])

}

func send_temp_peers(conn net.Conn, privkey *rsa.PrivateKey, peers []Peer, AES_key string){
	enc_temp_peers := Share_temp_peers(privkey, peers, AES_key)
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

func send_bye(conn net.Conn){
	_, write_err := conn.Write([]byte("bye"))
	if write_err != nil{
		log.Fatal(write_err)
	}
}

func Client_setup(all_peers All_peers, lpeer Lpeer, peerip string, port string, peerid string, privkey *rsa.PrivateKey, pubkey *rsa.PublicKey, pubkey_pem string) []Lpeer{
	address := string(fmt.Sprintf("%s:%s", peerip, port))
	protocol := "tcp"
	
	conn, err := net.Dial(protocol, address)
	if err != nil{
		log.Fatal(err)
	}
	defer conn.Close()

	init := greet_setup(conn, peerid)
	if init.Peerid != Sha1_encrypt(init.Pubkey_pem){
		log.Fatal("Peerid doesn't match public key")
	}

	AES_key := AES_keygen()

	kenc_peerinfo := send_key(conn, AES_key, pubkey)
	peerinfo := Dkenc_peerinfo(kenc_peerinfo, AES_key)
	all_peers = Save_peer(init.Peerid, peerinfo, AES_key, pubkey, all_peers)

	Write_peers(all_peers)

	enc_temp_peers := send_peerinfo(conn, lpeer, pubkey_pem, AES_key)
	temp_peers := Save_temp_peers(enc_temp_peers, privkey, all_peers, AES_key, lpeer)
	

	if len(all_peers.Peers) >= 5{
		send_temp_peers(conn, privkey, all_peers.Peers, AES_key)
	}else{
		send_bye(conn)
	}

	return temp_peers

}

func Client_exchange_peers(lpeer Lpeer, peerid string, privkey *rsa.PrivateKey, peers []Peer){
	peer := Decrypt_peer(peerid, privkey, peers)
	var peerinfo Peerinfo
	json.Unmarshal([]byte(peer.Peerinfo), &peerinfo)

	address := string(fmt.Sprintf("%s:%s", peerinfo.Peerip, peerinfo.Port))
	protocol := "tcp"
	
	conn, err := net.Dial(protocol, address)
	if err != nil{
		log.Fatal(err)
	}
	defer conn.Close()

}