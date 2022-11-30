package qpeer

import (
	"crypto/rsa"
	"encoding/json"
	"net"

	lib "github.com/quark-io/go-qPeer/qpeer"
)

func send_init(conn *net.UDPConn, addr *net.UDPAddr, init lib.Init) (string, error) { //Recv AES_key
	jsonized_init, json_err := json.Marshal(init)
	if json_err != nil {
		return "", lib.ErrorJSON
	}

	_, write_err := conn.WriteToUDP([]byte(jsonized_init), addr)
	if write_err != nil {
		return "", lib.ErrorWriteUDP
	}

	buffer := make([]byte, 2048)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		return "", lib.ErrorReadUDP
	}

	return string(buffer[:n]), nil
}

func send_peerinfo_server(conn *net.UDPConn, addr *net.UDPAddr, lpeer lib.Lpeer, pubkey_pem string, AES_key string) (string, error) { //Recv kenc_peerinfo
	var lpeerinfo lib.Peerinfo
	lpeerinfo.Protocol = lpeer.Protocol
	lpeerinfo.Endpoints = lpeer.Endpoints
	lpeerinfo.RSA_Pubkey = pubkey_pem

	kenc_lpeerinfo, kenc_peerinfo_err := lib.Kenc_peerinfo(lpeerinfo, AES_key)
	if kenc_peerinfo_err != nil {
		return "", kenc_peerinfo_err
	}

	_, write_err := conn.WriteToUDP([]byte(kenc_lpeerinfo), addr)
	if write_err != nil {
		return "", lib.ErrorWriteUDP
	}

	buffer := make([]byte, 2048)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		return "", lib.ErrorReadUDP
	}

	return string(buffer[:n]), nil
}

func Server_setup(conn *net.UDPConn, addr *net.UDPAddr, all_peers lib.All_peers, lpeer lib.Lpeer, privkey *rsa.PrivateKey, pubkey_pem string, peerid string) error {
	pubkey, rsa_err := lib.RSA_ImportPubkey(pubkey_pem)
	if rsa_err != nil {
		return rsa_err
	}

	init := lib.Init_enc(lpeer.Peerid, pubkey_pem)

	penc_AES_key, penc_err := send_init(conn, addr, init)
	if penc_err != nil {
		return penc_err
	}

	AES_key, aes_err := lib.Dpenc_AES(penc_AES_key, privkey)
	if aes_err != nil {
		return aes_err
	}

	kenc_peerinfo, peerinfo_err := send_peerinfo_server(conn, addr, lpeer, pubkey_pem, AES_key)
	if peerinfo_err != nil {
		return peerinfo_err
	}

	peerinfo, kdec_peerinfo_err := lib.Dkenc_peerinfo(kenc_peerinfo, AES_key)
	if kdec_peerinfo_err != nil {
		return kdec_peerinfo_err
	}

	if lpeer.Peerid != peerid {
		lib.Save_peer(peerid, peerinfo, AES_key, pubkey, all_peers)
	}

	bye_err := Send_bye(conn, addr)
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

func send_kenc_verify(conn *net.UDPConn, addr *net.UDPAddr, verify_msg string, AES_key string) (string, error) {
	kenc_verify, verify_err := lib.Kenc_verify(verify_msg, AES_key)
	if verify_err != nil {
		return "", verify_err
	}

	_, write_err := conn.WriteToUDP([]byte(kenc_verify), addr)
	if write_err != nil {
		return "", lib.ErrorWriteUDP
	}

	buffer := make([]byte, 2048)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		return "", lib.ErrorWriteUDP
	}

	return string(buffer[:n]), nil
}

func send_temp_peers_server(conn *net.UDPConn, addr *net.UDPAddr, privkey *rsa.PrivateKey, temp_peers []lib.Lpeer, AES_key string) (string, error) {
	enc_temp_peers, temp_peer_err := lib.Share_temp_peers(temp_peers, AES_key)
	if temp_peer_err != nil {
		return "", temp_peer_err
	}

	_, write_err := conn.WriteToUDP([]byte(enc_temp_peers), addr)
	if write_err != nil {
		return "", lib.ErrorWriteUDP
	}

	buffer := make([]byte, 8192)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		return "", lib.ErrorReadUDP
	}

	return string(buffer[:n]), nil
}

func Server_exchange_peers(conn *net.UDPConn, addr *net.UDPAddr, all_peers lib.All_peers, lpeer lib.Lpeer, temp_peers []lib.Lpeer, peerid string, privkey *rsa.PrivateKey) error {
	peer, peer_err := lib.Decrypt_peer(peerid, privkey, all_peers.Peers)
	if peer_err != nil {
		return peer_err
	}

	verify_msg := lib.RandomString(32)
	dkenc_verify, verify_err := send_kenc_verify(conn, addr, verify_msg, peer.AES_key)

	if verify_err != nil || dkenc_verify != verify_msg {
		return lib.ErrorVerify
	}

	recvd, recvd_error := send_temp_peers_server(conn, addr, privkey, temp_peers, peer.AES_key)

	if recvd_error != nil {
		return lib.ErrorBye
	}

	//TODO: check if recvd data is temp_peers
	if recvd != "bye" {
		lib.Save_temp_peers(recvd, all_peers, peer.AES_key, lpeer)
		bye_err := Send_bye(conn, addr)
		if bye_err != nil {
			return lib.ErrorBye
		}
	}

	return nil
}

// Ping

func Server_ping(conn *net.UDPConn, addr *net.UDPAddr, lpeer lib.Lpeer) error {
	peerid := lpeer.Peerid
	_, write_err := conn.WriteToUDP([]byte(peerid), addr)
	if write_err != nil {
		return lib.ErrorWriteUDP
	}

	return nil
}
