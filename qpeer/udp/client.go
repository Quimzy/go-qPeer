package qpeer

import (
	"crypto/rsa"
	"encoding/json"
	"net"

	lib "github.com/quark-io/go-qPeer/qpeer"
)

// Setup

func greet_setup(conn *net.UDPConn, addr *net.UDPAddr, peerid string) (lib.Init, error) {
	msg, err := json.Marshal(lib.Setup(peerid))
	if err != nil {
		return lib.Init{}, err
	}
	_, write_err := conn.WriteToUDP(msg, addr)
	if write_err != nil {
		return lib.Init{}, err
	}

	buffer := make([]byte, 2048)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		return lib.Init{}, err
	}

	var init lib.Init
	json.Unmarshal(buffer[:n], &init)

	return init, nil

}

func send_key(conn *net.UDPConn, addr *net.UDPAddr, AES_key string, pubkey *rsa.PublicKey) (string, error) {
	enc_AES_key := lib.Penc_AES(AES_key, pubkey)

	_, write_err := conn.WriteToUDP([]byte(enc_AES_key), addr)
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

func send_peerinfo(conn *net.UDPConn, addr *net.UDPAddr, lpeer lib.Lpeer, pubkey_pem string, AES_key string) (string, error) {
	var lpeerinfo lib.Peerinfo
	lpeerinfo.Protocol = lpeer.Protocol
	lpeerinfo.Endpoints = lpeer.Endpoints
	lpeerinfo.RSA_Pubkey = pubkey_pem

	kenc_lpeerinfo := lib.Kenc_peerinfo(lpeerinfo, AES_key)

	_, write_err := conn.WriteToUDP([]byte(kenc_lpeerinfo), addr)
	if write_err != nil {
		return "", write_err
	}

	buffer := make([]byte, 1024)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		return "", read_err
	}

	return string(buffer[:n]), nil
}

func Send_bye(conn *net.UDPConn, addr *net.UDPAddr) error {
	_, write_err := conn.WriteToUDP([]byte("bye"), addr)
	if write_err != nil {
		return write_err
	}

	return nil
}

func Client_setup(conn *net.UDPConn, addr *net.UDPAddr, all_peers lib.All_peers, lpeer lib.Lpeer, pubkey_pem string) error {
	pubkey := lib.RSA_ImportPubkey(pubkey_pem)

	init, greet_err := greet_setup(conn, addr, lpeer.Peerid)
	if greet_err != nil {
		return lib.ErrorGreet
	}

	if init.Peerid != lib.Sha1_encrypt(init.Pubkey_pem) {
		return lib.ErrorPeerid
	}

	server_pubkey := lib.RSA_ImportPubkey(init.Pubkey_pem)

	AES_key := lib.AES_keygen()

	kenc_peerinfo, peerinfo_err := send_key(conn, addr, AES_key, server_pubkey)
	if peerinfo_err != nil {
		return lib.ErrorKpeerinfo
	}

	peerinfo := lib.Dkenc_peerinfo(kenc_peerinfo, AES_key)

	if init.Peerid != lpeer.Peerid {
		all_peers = lib.Save_peer(init.Peerid, peerinfo, AES_key, pubkey, all_peers)
		lib.Write_peers(all_peers)
	} else {
		return lib.ErrorSamePeerid
	}

	bye, bye_err := send_peerinfo(conn, addr, lpeer, pubkey_pem, AES_key)
	if bye_err != nil || bye != "bye" {
		return lib.ErrorBye
	}

	bye_err = Send_bye(conn, addr)
	if bye_err != nil {
		return lib.ErrorBye
	}

	return nil
}

// Exchange Peers

func greet_exchange_peers(conn *net.UDPConn, addr *net.UDPAddr, peerid string) (string, error) {
	msg, json_err := json.Marshal(lib.Exchange_peers(peerid))
	if json_err != nil {
		return "", json_err
	}
	_, write_err := conn.WriteToUDP(msg, addr)
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

func send_dkenc_verify(conn *net.UDPConn, addr *net.UDPAddr, dkenc_verify string) (string, error) {
	_, write_err := conn.WriteToUDP([]byte(dkenc_verify), addr)
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

func send_temp_peers(conn *net.UDPConn, addr *net.UDPAddr, privkey *rsa.PrivateKey, peers []lib.Peer, AES_key string) (string, error) {
	enc_temp_peers := lib.Share_temp_peers(lib.Return_temp_peers(privkey, peers), AES_key)

	_, write_err := conn.WriteToUDP([]byte(enc_temp_peers), addr)
	if write_err != nil {
		return "", write_err
	}

	buffer := make([]byte, 1024)

	n, read_err := conn.Read(buffer)
	if read_err != nil {
		return "", read_err
	}

	return string(buffer[:n]), nil
}

func Client_exchange_peers(conn *net.UDPConn, addr *net.UDPAddr, all_peers lib.All_peers, lpeer lib.Lpeer, privkey *rsa.PrivateKey, AES_key string) error {

	kenc_verify, verify_err := greet_exchange_peers(conn, addr, lpeer.Peerid)
	if verify_err != nil {
		return lib.ErrorVerify
	}
	dkenc_verify := lib.Dkenc_verify(kenc_verify, AES_key)

	enc_temp_peers, temp_peers_error := send_dkenc_verify(conn, addr, dkenc_verify)
	if temp_peers_error != nil {
		return lib.ErrorRcvTempPeers
	}
	lib.Save_temp_peers(enc_temp_peers, privkey, all_peers, AES_key, lpeer)

	if len(all_peers.Peers) >= 5 {
		bye, bye_err := send_temp_peers(conn, addr, privkey, all_peers.Peers, AES_key)
		if bye_err != nil || bye != "bye" {
			return lib.ErrorBye
		}
	} else {
		bye_err2 := Send_bye(conn, addr)
		if bye_err2 != nil {
			return lib.ErrorBye
		}
	}

	return nil
}

// Ping

func Client_ping(conn *net.UDPConn, addr *net.UDPAddr, all_peers lib.All_peers, peerid string, privkey *rsa.PrivateKey) {
	peer := lib.Decrypt_peer(peerid, privkey, all_peers.Peers)
	var peerinfo lib.Peerinfo
	json.Unmarshal([]byte(peer.Peerinfo), &peerinfo)

	_, write_err := conn.WriteToUDP([]byte("ping"), addr)

	buffer := make([]byte, 1024)
	n, read_err := conn.Read(buffer)

	recvd_peerid := string(buffer[:n])

	if write_err != nil || read_err != nil || recvd_peerid != peerid {
		lib.Remove_peer(peerid, all_peers)
	}
}

// Getback

func Client_getback(conn *net.UDPConn, addr *net.UDPAddr, all_peers lib.All_peers, peerid string, privkey *rsa.PrivateKey) {
	peer := lib.Decrypt_peer(peerid, privkey, all_peers.Offline_peers)
	var peerinfo lib.Peerinfo
	json.Unmarshal([]byte(peer.Peerinfo), &peerinfo)

	_, write_err := conn.WriteToUDP([]byte("ping"), addr)

	buffer := make([]byte, 1024)
	n, read_err := conn.Read(buffer)

	recvd_peerid := string(buffer[:n])

	if write_err != nil || read_err != nil || recvd_peerid != peerid {
		lib.Remove_peer(peerid, all_peers)
	}
}
