package qpeer

import (
	"crypto/rsa"
	"encoding/json"
	"log"
	"net"

	lib "github.com/quirkio/go-qPeer/qpeer"
)

func send_init(conn net.Conn, init lib.Init) string { //Recv AES_key
	jsonized_init, err := json.Marshal(init)
	if err != nil {
		log.Fatal(err)
	}

	_, write_err := conn.Write([]byte(jsonized_init))
	if write_err != nil {
		log.Fatal(write_err)
	}

	buffer := make([]byte, 2048)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		log.Fatal(read_err)
	}

	return string(buffer[:n])
}

func send_peerinfo_server(conn net.Conn, lpeer lib.Lpeer, pubkey_pem string, AES_key string) string { //Recv kenc_peerinfo
	var lpeerinfo lib.Peerinfo
	lpeerinfo.Protocol = lpeer.Protocol
	lpeerinfo.Endpoints = lpeer.Endpoints
	lpeerinfo.RSA_Pubkey = pubkey_pem

	kenc_lpeerinfo := lib.Kenc_peerinfo(lpeerinfo, AES_key)

	_, write_err := conn.Write([]byte(kenc_lpeerinfo))
	if write_err != nil {
		log.Fatal(write_err)
	}

	buffer := make([]byte, 2048)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		log.Fatal(read_err)
	}

	return string(buffer[:n])
}

func Server_setup(conn net.Conn, all_peers lib.All_peers, lpeer lib.Lpeer, privkey *rsa.PrivateKey, pubkey_pem string, peerid string) {
	pubkey := lib.RSA_ImportPubkey(pubkey_pem)
	init := lib.Init_enc(lpeer.Peerid, pubkey_pem)

	AES_key := lib.Dpenc_AES(send_init(conn, init), privkey)

	kenc_peerinfo := send_peerinfo_server(conn, lpeer, pubkey_pem, AES_key)
	peerinfo := lib.Dkenc_peerinfo(kenc_peerinfo, AES_key)

	if lpeer.Peerid != peerid {
		all_peers = lib.Save_peer(peerid, peerinfo, AES_key, pubkey, all_peers)
		lib.Write_peers(all_peers)
	}

	Send_bye(conn)
	buffer := make([]byte, 1024)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		log.Fatal(read_err)
	}

	if string(buffer[:n]) != "bye" {
		log.Fatal("Bye not received")
	}

}

//Exchange peers

func send_kenc_verify(conn net.Conn, verify_msg string, AES_key string) string {
	kenc_verify := lib.Kenc_verify(verify_msg, AES_key)

	_, write_err := conn.Write([]byte(kenc_verify))
	if write_err != nil {
		log.Fatal(write_err)
	}

	buffer := make([]byte, 2048)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		log.Fatal(read_err)
	}

	return string(buffer[:n])
}

func send_temp_peers_server(conn net.Conn, privkey *rsa.PrivateKey, temp_peers []lib.Lpeer, AES_key string) string {
	enc_temp_peers := lib.Share_temp_peers(temp_peers, AES_key)

	_, write_err := conn.Write([]byte(enc_temp_peers))
	if write_err != nil {
		log.Fatal(write_err)
	}

	buffer := make([]byte, 8192)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		log.Fatal(read_err)
	}

	return string(buffer[:n])
}

func Server_exchange_peers(conn net.Conn, all_peers lib.All_peers, lpeer lib.Lpeer, temp_peers []lib.Lpeer, peerid string, privkey *rsa.PrivateKey) {
	peer := lib.Decrypt_peer(peerid, privkey, all_peers.Peers)

	verify_msg := lib.RandomString(32)
	dkenc_verify := send_kenc_verify(conn, verify_msg, peer.AES_key)

	if dkenc_verify != verify_msg {
		log.Fatal("Peer doesn't have the right AES_key")
	}

	recvd := send_temp_peers_server(conn, privkey, lib.Return_temp_peers(privkey, all_peers.Peers), peer.AES_key)

	if recvd != "bye" {
		lib.Save_temp_peers(recvd, privkey, all_peers, peer.AES_key, lpeer)
	}
}

// Bootstrap

func Server_bootstrap(conn net.Conn, all_peers lib.All_peers, lpeer lib.Lpeer, temp_peers []lib.Lpeer, AES_key string, privkey *rsa.PrivateKey) {
	verify_msg := lib.RandomString(32)
	dkenc_verify := send_kenc_verify(conn, verify_msg, AES_key)
	if dkenc_verify != verify_msg {
		log.Fatal("Peer doesn't have the right AES_key")
	}

	enc_temp_peers := send_temp_peers_server(conn, privkey, lib.Return_temp_peers_bootstrap(privkey, temp_peers), AES_key)
	lib.Save_temp_peers(enc_temp_peers, privkey, all_peers, AES_key, lpeer)

	Send_bye(conn)

}
