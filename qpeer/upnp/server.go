package qpeer

import (
	"crypto/rsa"
	"encoding/json"
	"net"

	lib "github.com/quark-io/go-qPeer/qpeer"
)

func send_init(conn net.Conn, init lib.Init) (string, error) { //Recv AES_key
	jsonized_init, json_err := json.Marshal(init)
	if json_err != nil {
		return "", json_err
	}

	_, write_err := conn.Write([]byte(jsonized_init))
	if write_err != nil {
		return "", write_err
	}

	buffer := make([]byte, 2048)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		return "", read_err
	}

	return string(buffer[:n]), nil
}

func send_peerinfo_server(conn net.Conn, lpeer lib.Lpeer, pubkey_pem string, AES_key string) (string, error) { //Recv kenc_peerinfo
	var lpeerinfo lib.Peerinfo
	lpeerinfo.Protocol = lpeer.Protocol
	lpeerinfo.Endpoints = lpeer.Endpoints
	lpeerinfo.RSA_Pubkey = pubkey_pem

	kenc_lpeerinfo := lib.Kenc_peerinfo(lpeerinfo, AES_key)

	_, write_err := conn.Write([]byte(kenc_lpeerinfo))
	if write_err != nil {
		return "", write_err
	}

	buffer := make([]byte, 2048)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		return "", read_err
	}

	return string(buffer[:n]), nil
}

func Server_setup(conn net.Conn, all_peers lib.All_peers, lpeer lib.Lpeer, privkey *rsa.PrivateKey, pubkey_pem string, peerid string) error {
	pubkey := lib.RSA_ImportPubkey(pubkey_pem)
	init := lib.Init_enc(lpeer.Peerid, pubkey_pem)

	penc_AES_key, penc_err := send_init(conn, init)
	if penc_err != nil {
		return lib.ErrorPenckey
	}
	AES_key := lib.Dpenc_AES(penc_AES_key, privkey)

	kenc_peerinfo, peerinfo_err := send_peerinfo_server(conn, lpeer, pubkey_pem, AES_key)
	if peerinfo_err != nil {
		return lib.ErrorKencpeerinfo
	}
	peerinfo := lib.Dkenc_peerinfo(kenc_peerinfo, AES_key)

	if lpeer.Peerid != peerid {
		all_peers = lib.Save_peer(peerid, peerinfo, AES_key, pubkey, all_peers)
		lib.Write_peers(all_peers)
	}

	bye_err := Send_bye(conn)
	if bye_err != nil {
		return lib.ErrorBye
	}
	buffer := make([]byte, 1024)

	n, read_err := conn.Read(buffer)
	if read_err != nil || string(buffer[:n]) != "bye" {
		return lib.ErrorBye
	}

	return nil

}

//Exchange peers

func send_kenc_verify(conn net.Conn, verify_msg string, AES_key string) (string, error) {
	kenc_verify := lib.Kenc_verify(verify_msg, AES_key)

	_, write_err := conn.Write([]byte(kenc_verify))
	if write_err != nil {
		return "", write_err
	}

	buffer := make([]byte, 2048)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		return "", read_err
	}

	return string(buffer[:n]), nil
}

func send_temp_peers_server(conn net.Conn, privkey *rsa.PrivateKey, temp_peers []lib.Lpeer, AES_key string) (string, error) {
	enc_temp_peers := lib.Share_temp_peers(temp_peers, AES_key)

	_, write_err := conn.Write([]byte(enc_temp_peers))
	if write_err != nil {
		return "", write_err
	}

	buffer := make([]byte, 8192)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		return "", read_err
	}

	return string(buffer[:n]), nil
}

func Server_exchange_peers(conn net.Conn, all_peers lib.All_peers, lpeer lib.Lpeer, temp_peers []lib.Lpeer, peerid string, privkey *rsa.PrivateKey) error {
	peer := lib.Decrypt_peer(peerid, privkey, all_peers.Peers)
	verify_msg := lib.RandomString(32)

	dkenc_verify, verify_err := send_kenc_verify(conn, verify_msg, peer.AES_key)
	if verify_err != nil || dkenc_verify != verify_msg {
		return lib.ErrorVerify
	}

	recvd, recvd_error := send_temp_peers_server(conn, privkey, lib.Return_temp_peers(privkey, all_peers.Peers), peer.AES_key)

	if recvd_error != nil {
		return lib.ErrorBye
	}

	//TODO: check if recvd data is temp_peers
	if recvd != "bye" {
		lib.Save_temp_peers(recvd, privkey, all_peers, peer.AES_key, lpeer)
		bye_err := Send_bye(conn)
		if bye_err != nil {
			return lib.ErrorBye
		}
	}

	return nil
}

// Bootstrap

func Server_bootstrap(conn net.Conn, all_peers lib.All_peers, lpeer lib.Lpeer, temp_peers []lib.Lpeer, AES_key string, privkey *rsa.PrivateKey) error {
	verify_msg := lib.RandomString(32)

	dkenc_verify, verify_err := send_kenc_verify(conn, verify_msg, AES_key)
	if verify_err != nil || dkenc_verify != verify_msg {
		return lib.ErrorVerify
	}

	enc_temp_peers, temp_peers_error := send_temp_peers_server(conn, privkey, lib.Return_temp_peers_bootstrap(privkey, temp_peers), AES_key)
	if temp_peers_error != nil {
		return lib.ErrorRcvTempPeers
	}
	lib.Save_temp_peers(enc_temp_peers, privkey, all_peers, AES_key, lpeer)

	bye_err := Send_bye(conn)
	if bye_err != nil {
		return lib.ErrorBye
	}

	return nil
}
