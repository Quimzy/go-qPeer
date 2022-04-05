
package qpeer

import ("net"
	"log"
	"encoding/json"
	"crypto/rsa"
	"github.com/Quirk-io/go-qPeer/qpeer"
)

// Setup

func greet_setup(conn *net.UDPConn, addr *net.UDPAddr, peerid string) lib.Init{
	msg, err := json.Marshal(lib.Setup(peerid))
	if err != nil{
		log.Fatal(err)
	}
	_, write_err := conn.WriteToUDP(msg, addr)
	if write_err != nil{
		log.Fatal(write_err)
	}
	
	buffer := make([]byte, 2048)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		log.Fatal(read_err)
	}

	var init lib.Init
	json.Unmarshal(buffer[:n], &init)

	return init

}

func send_key(conn *net.UDPConn, addr *net.UDPAddr, AES_key string, pubkey *rsa.PublicKey) string{
	enc_AES_key := lib.Penc_AES(AES_key, pubkey)

	_, write_err := conn.WriteToUDP([]byte(enc_AES_key), addr)
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

func send_peerinfo(conn *net.UDPConn, addr *net.UDPAddr, lpeer lib.Lpeer, pubkey_pem string, AES_key string) string{
	lpeerinfo := lib.Peerinfo{lpeer.Endpoints, pubkey_pem}
	kenc_lpeerinfo := lib.Kenc_peerinfo(lpeerinfo, AES_key)

	_, write_err := conn.WriteToUDP([]byte(kenc_lpeerinfo), addr)
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

func Send_bye(conn *net.UDPConn, addr *net.UDPAddr){
	_, write_err := conn.WriteToUDP([]byte("bye"), addr)
	if write_err != nil{
		log.Fatal(write_err)
	}
}

func Client_setup(conn *net.UDPConn, addr *net.UDPAddr, all_peers lib.All_peers, lpeer lib.Lpeer, peerip string, port string, pubkey_pem string){
	pubkey := lib.RSA_ImportPubkey(pubkey_pem)

	init := greet_setup(conn, addr, lpeer.Peerid)
	if init.Peerid != lib.Sha1_encrypt(init.Pubkey_pem){
		log.Fatal("Peerid doesn't match public key")
	}

	server_pubkey := lib.RSA_ImportPubkey(init.Pubkey_pem)

	AES_key := lib.AES_keygen()

	kenc_peerinfo := send_key(conn, addr, AES_key, server_pubkey)
	peerinfo := lib.Dkenc_peerinfo(kenc_peerinfo, AES_key)

	if init.Peerid != lpeer.Peerid{
		all_peers = lib.Save_peer(init.Peerid, peerinfo, AES_key, pubkey, all_peers)
		lib.Write_peers(all_peers)
	}
	
	bye := send_peerinfo(conn, addr, lpeer, pubkey_pem, AES_key)
	if bye == "bye"{
		Send_bye(conn, addr)
	}else{
		log.Fatal("Bye not received")
	}

}

// Exchange Peers

func greet_exchange_peers(conn *net.UDPConn, addr *net.UDPAddr, peerid string) string{
	msg, err := json.Marshal(lib.Exchange_peers(peerid))
	if err != nil{
		log.Fatal(err)
	}
	_, write_err := conn.WriteToUDP(msg, addr)
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

func send_dkenc_verify(conn *net.UDPConn, addr *net.UDPAddr, dkenc_verify string) string{
	_, write_err := conn.WriteToUDP([]byte(dkenc_verify), addr)
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

func send_temp_peers(conn *net.UDPConn, addr *net.UDPAddr, privkey *rsa.PrivateKey, peers []lib.Peer, AES_key string){
	enc_temp_peers := lib.Share_temp_peers(lib.Return_temp_peers(privkey, peers), AES_key)
	_, write_err := conn.WriteToUDP([]byte(enc_temp_peers), addr)
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

func Client_exchange_peers(conn *net.UDPConn, addr *net.UDPAddr, all_peers lib.All_peers, lpeer lib.Lpeer, privkey *rsa.PrivateKey, AES_key string, peerip string, port string) error{

	kenc_verify := greet_exchange_peers(conn, addr, lpeer.Peerid)
	dkenc_verify := lib.Dkenc_verify(kenc_verify, AES_key)

	enc_temp_peers := send_dkenc_verify(conn, addr, dkenc_verify)
	lib.Save_temp_peers(enc_temp_peers, privkey, all_peers, AES_key, lpeer)

	if len(all_peers.Peers) >= 5{
		send_temp_peers(conn, addr, privkey, all_peers.Peers, AES_key)
	}else{
		Send_bye(conn, addr)
	}

	return nil
}

// Bootstrap

func send_lpeer(conn *net.UDPConn, addr *net.UDPAddr, kenc_lpeer string) string{
	_, write_err := conn.WriteToUDP([]byte(kenc_lpeer), addr)
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

func Client_bootstrap(conn *net.UDPConn, addr *net.UDPAddr, all_peers lib.All_peers, lpeer lib.Lpeer, privkey *rsa.PrivateKey, AES_key string, peerip string, port string){

	kenc_verify := greet_exchange_peers(conn, addr, lpeer.Peerid)

	dkenc_verify := lib.Dkenc_verify(kenc_verify, AES_key)
	enc_temp_peers := send_dkenc_verify(conn, addr, dkenc_verify)
	lib.Save_temp_peers(enc_temp_peers, privkey, all_peers, AES_key, lpeer)

	kenc_lpeer := lib.Kenc_lpeer(lpeer, AES_key)
	bye := send_lpeer(conn, addr, kenc_lpeer)

	if bye != "bye"{//Improve this with better error handling
		log.Fatal("Bye wasn't received")
	}
}

// Ping

func Client_ping(conn *net.UDPConn, addr *net.UDPAddr, all_peers lib.All_peers, peerid string, privkey *rsa.PrivateKey){
	peer := lib.Decrypt_peer(peerid, privkey, all_peers.Peers)
	var peerinfo lib.Peerinfo
	json.Unmarshal([]byte(peer.Peerinfo), &peerinfo)

	_, write_err := conn.WriteToUDP([]byte("ping"), addr)
	if write_err != nil{
		lib.Remove_peer(peerid, all_peers)
	}
}

// Getback

func Client_getback(conn *net.UDPConn, addr *net.UDPAddr, all_peers lib.All_peers, peerid string, privkey *rsa.PrivateKey){
	peer := lib.Decrypt_peer(peerid, privkey, all_peers.Offline_peers)
	var peerinfo lib.Peerinfo
	json.Unmarshal([]byte(peer.Peerinfo), &peerinfo)

	_, write_err := conn.WriteToUDP([]byte("ping"), addr)
	if write_err != nil{
		lib.Remove_peer(peerid, all_peers)
	}
}
