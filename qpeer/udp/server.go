
package qpeer

import ("net"
	"log"
	"encoding/json"
	"crypto/rsa"
	"github.com/Quirk-io/go-qPeer/qpeer"
)

func send_init(conn *net.UDPConn, addr *net.UDPAddr, init lib.Init) string{//Recv AES_key
	jsonized_init, err := json.Marshal(init)
	if err != nil{
		log.Fatal(err)
	}

	_, write_err := conn.WriteToUDP([]byte(jsonized_init), addr)
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

func send_peerinfo_server(conn *net.UDPConn, addr *net.UDPAddr, lpeer lib.Lpeer, pubkey_pem string, AES_key string) string{//Recv kenc_peerinfo
	lpeerinfo := lib.Peerinfo{lpeer.Endpoints, pubkey_pem}
	kenc_lpeerinfo := lib.Kenc_peerinfo(lpeerinfo, AES_key)

	_, write_err := conn.WriteToUDP([]byte(kenc_lpeerinfo), addr)
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

func Server_setup(conn *net.UDPConn, addr *net.UDPAddr, all_peers lib.All_peers, lpeer lib.Lpeer, privkey *rsa.PrivateKey, pubkey_pem string, peerid string){
	pubkey := lib.RSA_ImportPubkey(pubkey_pem)
	init := lib.Init_enc(lpeer.Peerid, pubkey_pem)

	AES_key := lib.Dpenc_AES(send_init(conn, addr, init), privkey)

	kenc_peerinfo := send_peerinfo_server(conn, addr, lpeer, pubkey_pem, AES_key)
	peerinfo := lib.Dkenc_peerinfo(kenc_peerinfo, AES_key)

	if lpeer.Peerid != peerid{
		lib.Save_peer(peerid, peerinfo, AES_key, pubkey, all_peers)
	}
	
	Send_bye(conn, addr)
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

func send_kenc_verify(conn *net.UDPConn, addr *net.UDPAddr, verify_msg string, AES_key string) string{
	kenc_verify := lib.Kenc_verify(verify_msg, AES_key)

	_, write_err := conn.WriteToUDP([]byte(kenc_verify), addr)
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

func send_temp_peers_server(conn *net.UDPConn, addr *net.UDPAddr, privkey *rsa.PrivateKey, temp_peers []lib.Lpeer, AES_key string) string{
	enc_temp_peers := lib.Share_temp_peers(temp_peers, AES_key)

	_, write_err := conn.WriteToUDP([]byte(enc_temp_peers), addr)
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


func Server_exchange_peers(conn *net.UDPConn, addr *net.UDPAddr ,all_peers lib.All_peers, lpeer lib.Lpeer, temp_peers []lib.Lpeer, peerid string, privkey *rsa.PrivateKey){
	peer := lib.Decrypt_peer(peerid, privkey, all_peers.Peers) 

	verify_msg := lib.RandomString(32)
	dkenc_verify := send_kenc_verify(conn, addr, verify_msg, peer.AES_key)

	if dkenc_verify != verify_msg{
		log.Fatal("Peer doesn't have the right AES_key")
	}

	recvd := send_temp_peers_server(conn, addr, privkey, lib.Return_temp_peers(privkey, all_peers.Peers), peer.AES_key)
	
	if recvd != "bye"{
		lib.Save_temp_peers(recvd, privkey, all_peers, peer.AES_key, lpeer)
	}
}

// Bootstrap

func Server_bootstrap(conn *net.UDPConn, addr *net.UDPAddr, all_peers lib.All_peers, lpeer lib.Lpeer, temp_peers []lib.Lpeer, AES_key string, privkey *rsa.PrivateKey){
	verify_msg := lib.RandomString(32)
	dkenc_verify := send_kenc_verify(conn, addr, verify_msg, AES_key)
	if dkenc_verify != verify_msg{
		log.Fatal("Peer doesn't have the right AES_key")
	}

	temp_peer := send_temp_peers_server(conn, addr, privkey, lib.Return_temp_peers_bootstrap(privkey, temp_peers), AES_key)
	lib.Save_temp_peers(temp_peer, privkey, all_peers, AES_key, lpeer)

	Send_bye(conn, addr)

}