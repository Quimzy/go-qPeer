package lib

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	random "math/rand"
	"net"
	"os"
	"time"

	"github.com/quark-io/Endpoint/stun"
)

type RSA_Keys struct {
	RSA_Privkey string `json:"privkey"`
	RSA_Pubkey  string `json:"pubkey"`
}

type Lpeer struct {
	Peerid    string         `json:"peerid"`
	Protocol  string         `json:"protocol"`
	Endpoints stun.Endpoints `json:"endpoints"`
}

type All_peers struct {
	Peers         []Peer `json:"peers"`
	Offline_peers []Peer `json:"offline_peers"`
}

type Peer struct {
	Peerid   string `json:"peerid"`
	Peerinfo string `json:"peerinfo"`
	AES_key  string `json:"key"`
}

type Peerinfo struct {
	Protocol   string
	Endpoints  stun.Endpoints
	RSA_Pubkey string
}

// Basic functions

func Sha1_encrypt(msg string) string {
	h := sha1.New()
	h.Write([]byte(msg))
	return string(fmt.Sprintf("%x", h.Sum(nil)))
}

func Md5_encrypt(msg string) string {
	return string(fmt.Sprintf("%x", md5.Sum([]byte(msg))))
}

func RandomString(length int) string {
	random.Seed(time.Now().UnixNano())
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	s := make([]byte, 0, length)
	for i := 0; i < length; i++ {
		s = append(s, alphabet[random.Intn(len(alphabet))])
	}
	return string(s)
}

func Index(peers []Peer, peer Peer) int {
	for i, n_peer := range peers {
		if n_peer == peer {
			return i
		}
	}
	return -1
}

func Check_peer(peerid string, peers []Peer) bool {
	for _, n_peer := range peers {
		if n_peer.Peerid == peerid {
			return true
		}
	}

	return false
}

func Check_temp_peers(peerid string, temp_peers []Lpeer) bool {
	for _, n_peer := range temp_peers {
		if n_peer.Peerid == peerid {
			return true
		}
	}

	return false
}

func Find_peer(peerid string, peers []Peer) (string, error) {
	for _, n_peer := range peers {
		if n_peer.Peerid == peerid {
			jsonified_peer, err := json.Marshal(n_peer)
			if err != nil {
				return "", err
			}
			return string(jsonified_peer), nil
		}
	}

	return "", ErrorPeerNotFound
}

func Find_temp_peer(peerid string, temp_peers []Lpeer) (string, error) {
	for _, n_peer := range temp_peers {
		if n_peer.Peerid == peerid {
			jsonified_peer, err := json.Marshal(n_peer)
			if err != nil {
				return "", err
			}
			return string(jsonified_peer), nil
		}
	}

	return "", ErrorPeerNotFound
}

// Peer setup

func RSA_keygen() (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubkey := &privkey.PublicKey

	return privkey, pubkey
}

func RSA_ExportPrivkey(privkey *rsa.PrivateKey) string {
	privkey_bytes := x509.MarshalPKCS1PrivateKey(privkey)
	RSA_Privkey := string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privkey_bytes,
		},
	))

	return RSA_Privkey
}

func RSA_ExportPubkey(pubkey *rsa.PublicKey) (string, error) {
	pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	RSA_Pubkey := string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkey_bytes,
		},
	))

	return RSA_Pubkey, nil
}

func RSA_ExportKeys(privkey *rsa.PrivateKey, pubkey *rsa.PublicKey) (RSA_Keys, error) {
	var keys RSA_Keys
	keys.RSA_Privkey = RSA_ExportPrivkey(privkey)
	var rsa_err error
	keys.RSA_Pubkey, rsa_err = RSA_ExportPubkey(pubkey)

	if rsa_err != nil {
		return RSA_Keys{}, rsa_err
	}

	return keys, nil
}

func RSA_ImportPrivkey(privkey_pem string) *rsa.PrivateKey {
	dec_privkey, _ := pem.Decode([]byte(privkey_pem))
	privkey, _ := x509.ParsePKCS1PrivateKey(dec_privkey.Bytes)

	return privkey

}

func RSA_ImportPubkey(pubkey_pem string) (*rsa.PublicKey, error) {
	dec_pubkey, _ := pem.Decode([]byte(pubkey_pem))
	pubkey, err := x509.ParsePKIXPublicKey(dec_pubkey.Bytes)
	if err != nil {
		return nil, err
	}
	return pubkey.(*rsa.PublicKey), err
}

func RSA_ImportKeys(privkey_pem string, pubkey_pem string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	pubkey, err := RSA_ImportPubkey(pubkey_pem)
	if err != nil {
		return nil, nil, err
	}

	return RSA_ImportPrivkey(privkey_pem), pubkey, nil
}

func RSA_Writekeys(keys RSA_Keys) error {
	log.Println("Saving RSA_keys to keys.json")
	jsonified_keys, err := json.MarshalIndent(keys, "", " ")
	if err != nil {
		return err
	}
	_ = ioutil.WriteFile("keys.json", jsonified_keys, 0664)

	return nil
}

func RSA_Readkeys() (RSA_Keys, error) {
	log.Println("Retrieving RSA_keys from keys.json")
	reader, err := ioutil.ReadFile("keys.json")
	if err != nil {
		return RSA_Keys{}, err
	}

	var keys RSA_Keys
	json.Unmarshal([]byte(reader), &keys)

	return keys, nil
}

func Set_RSA_Keys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	if _, err := os.Stat("keys.json"); err == nil {
		keys, rsa_reading_err := RSA_Readkeys()
		if rsa_reading_err != nil {
			return nil, nil, rsa_reading_err
		}

		privkey, pubkey, rsa_importing_err := RSA_ImportKeys(keys.RSA_Privkey, keys.RSA_Pubkey)
		return privkey, pubkey, rsa_importing_err

	} else {
		var keys RSA_Keys
		log.Println("Generating RSA_keys")
		privkey, pubkey := RSA_keygen()

		var rsa_exporting_err error
		keys, rsa_exporting_err = RSA_ExportKeys(privkey, pubkey)
		if rsa_exporting_err != nil {
			return nil, nil, rsa_exporting_err
		}

		write_err := RSA_Writekeys(keys)
		if write_err != nil {
			return nil, nil, write_err
		}
		return privkey, pubkey, nil
	}

}

func Read_lpeer() (Lpeer, error) {
	log.Println("Retrieving lpeer from lpeer.json")
	reader, read_err := ioutil.ReadFile("lpeer.json")
	if read_err != nil {
		return Lpeer{}, read_err
	}
	var lpeer Lpeer
	json.Unmarshal([]byte(reader), &lpeer)

	return lpeer, nil
}

func Write_lpeer(lpeer Lpeer) error {
	log.Println("Saving lpeer to lpeer.json")
	jsonified_lpeer, err := json.Marshal(lpeer)
	if err != nil {
		return err
	}
	_ = ioutil.WriteFile("lpeer.json", jsonified_lpeer, 0664)
	return nil
}

func Set_lpeer(pubkey_pem, bootstrap_AES_key, signal_ip, signal_port string) (*net.UDPConn, Lpeer, error) {
	//Setting Proto & Endpoints
	conn, protocol, endpoints := SetProto(bootstrap_AES_key, signal_ip, signal_port)

	var lpeer Lpeer
	if _, err := os.Stat("lpeer.json"); err == nil {
		var lpeer_err error

		lpeer, lpeer_err = Read_lpeer()
		if lpeer_err != nil {
			return nil, Lpeer{}, lpeer_err
		}

		if lpeer.Peerid != Sha1_encrypt(pubkey_pem) { //peerid is always linked with RSA public key
			lpeer.Peerid = Sha1_encrypt(pubkey_pem)
		}

		if lpeer.Protocol != protocol && lpeer.Endpoints != endpoints { //if public ip has changed
			lpeer.Protocol = protocol
			lpeer.Endpoints = endpoints
		}

		saved_lpeer, read_err := Read_lpeer()
		if read_err != nil {
			return nil, Lpeer{}, read_err
		}

		if lpeer != saved_lpeer { //if lpeer has changed
			write_err := Write_lpeer(lpeer)
			if write_err != nil {
				return nil, Lpeer{}, read_err
			}
		}

	} else {
		log.Println("Generating lpeer")

		//Generating Peerid
		lpeer.Peerid = Sha1_encrypt(pubkey_pem)

		//Setting the rest of the variables
		lpeer.Protocol = protocol
		lpeer.Endpoints = endpoints

		write_err := Write_lpeer(lpeer)
		if write_err != nil {
			return nil, Lpeer{}, write_err
		}
	}

	log.Println("Your peerid is:", lpeer.Peerid)
	return conn, lpeer, nil
}

// Encryption Functions

func RSA_encrypt(msg string, pubkey *rsa.PublicKey) (string, error) {
	enc_msg, err := rsa.EncryptOAEP(
		sha1.New(),
		rand.Reader,
		pubkey,
		[]byte(msg),
		nil)

	if err != nil {
		return "", err
	}

	return string(enc_msg), nil
}

func RSA_decrypt(enc_msg string, privkey *rsa.PrivateKey) (string, error) {
	msg, err := privkey.Decrypt(nil, []byte(enc_msg), &rsa.OAEPOptions{Hash: crypto.SHA1})
	if err != nil {
		return "", err
	}
	return string(msg), err
}

func AES_keygen() string {
	key := Md5_encrypt(RandomString(32))
	return key
}

func AES_encrypt(msg string, key string) (string, error) {
	c, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())

	enc_msg := gcm.Seal(nonce, nonce, []byte(msg), nil)
	return string(enc_msg), err
}

func AES_decrypt(enc_msg string, key string) (string, error) {
	c, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(enc_msg) < nonceSize {
		return "", err
	}

	nonce, enc_msg := enc_msg[:nonceSize], enc_msg[nonceSize:]

	msg, err := gcm.Open(nil, []byte(nonce), []byte(enc_msg), nil)
	if err != nil {
		return "", err
	}

	return string(msg), nil
}

func Penc_AES(AES_key string, pubkey *rsa.PublicKey) (string, error) { // Public Key encryption for AES_key
	penc_AES, rsa_err := RSA_encrypt(AES_key, pubkey)
	if rsa_err != nil {
		return "", rsa_err
	}
	enc_AES_key := base64.StdEncoding.EncodeToString([]byte(penc_AES))

	return enc_AES_key, rsa_err
}

func Dpenc_AES(enc_AES_key string, privkey *rsa.PrivateKey) (string, error) {
	b64dec_AES_key, err := base64.StdEncoding.DecodeString(enc_AES_key)
	if err != nil {
		return "", err
	}

	AES_key, rsa_err := RSA_decrypt(string(b64dec_AES_key), privkey)
	if rsa_err != nil {
		return "", rsa_err
	}

	return AES_key, nil
}

func Kenc_peerinfo(peerinfo Peerinfo, AES_key string) (string, error) { //Key Encryption (AES)
	jsonified_peerinfo, err := json.Marshal(peerinfo) //From struct to a string
	if err != nil {
		return "", err
	}

	kenc_peerinfo, aes_err := AES_encrypt(string(jsonified_peerinfo), AES_key) //Encrypting peerinfo with Key
	if aes_err != nil {
		return "", aes_err
	}

	return base64.StdEncoding.EncodeToString([]byte(kenc_peerinfo)), nil
}

func Dkenc_peerinfo(kenc_peerinfo string, AES_key string) (Peerinfo, error) { // Decrypt Key Encryption (AES)
	b64dec_peerinfo, _ := base64.StdEncoding.DecodeString(kenc_peerinfo)    //Decoding base64
	kdec_peerinfo, aes_err := AES_decrypt(string(b64dec_peerinfo), AES_key) //Decrypting peerinfo with Key
	if aes_err != nil {
		return Peerinfo{}, aes_err
	}

	var peerinfo Peerinfo
	json.Unmarshal([]byte(kdec_peerinfo), &peerinfo)

	return peerinfo, nil
}

func Kenc_verify(msg string, key string) (string, error) {
	kenc_verify, aes_err := AES_encrypt(msg, key)
	if aes_err != nil {
		return "", aes_err
	}

	b64kenc_verify := base64.StdEncoding.EncodeToString([]byte(kenc_verify))

	return b64kenc_verify, nil
}

func Dkenc_verify(enc_msg string, key string) (string, error) {
	b64dec_verify, _ := base64.StdEncoding.DecodeString(enc_msg)
	kdec_verify, aes_err := AES_decrypt(string(b64dec_verify), key)
	if aes_err != nil {
		return "", aes_err
	}

	return kdec_verify, nil
}

func Kenc_lpeer(lpeer Lpeer, AES_key string) (string, error) {
	jsonified_lpeer, err := json.Marshal([]Lpeer{lpeer})
	if err != nil {
		return "", err
	}

	kenc_lpeer, aes_err := AES_encrypt(string(jsonified_lpeer), AES_key) //Encrypting lpeer with Key
	if aes_err != nil {
		return "", aes_err
	}

	return base64.StdEncoding.EncodeToString([]byte(kenc_lpeer)), nil
}

// MsgTypes

type Firstmsg struct {
	Msgtype string `json:"msgtype"`
	Peerid  string `json:"peerid"`
}

type Init struct {
	Peerid     string `json:"peerid"`
	Pubkey_pem string `json:"pubkey"`
}

func Setup(peerid string) Firstmsg {
	qpeer_msg := Firstmsg{"setup", peerid}

	return qpeer_msg
}

func Exchange_peers(peerid string) Firstmsg {
	exchange_peers_msg := Firstmsg{"exchange_peers", peerid}

	return exchange_peers_msg
}

func Init_enc(peerid string, pubkey_pem string) Init {
	init_msg := Init{peerid, pubkey_pem}

	return init_msg
}

// Saving peer

func Save_peer(peerid string, peerinfo Peerinfo, AES_key string, pubkey *rsa.PublicKey, all_peers All_peers) (All_peers, error) {
	jsonified_kenc_peerinfo, _ := json.Marshal(peerinfo)
	kenc_peerinfo, aes_err := AES_encrypt(string(jsonified_kenc_peerinfo), AES_key)
	if aes_err != nil {
		return All_peers{}, aes_err
	}

	penc_key, rsa_err := RSA_encrypt(AES_key, pubkey)
	if rsa_err != nil {
		return All_peers{}, aes_err
	}

	peer := Peer{peerid, base64.StdEncoding.EncodeToString([]byte(kenc_peerinfo)), base64.StdEncoding.EncodeToString([]byte(penc_key))}

	if !Check_peer(peerid, all_peers.Peers) && !Check_peer(peerid, all_peers.Offline_peers) {
		all_peers.Peers = append(all_peers.Peers, peer)
	}

	return all_peers, nil

}

func Write_peers(all_peers All_peers) error {
	jsonified_peers, err := json.MarshalIndent(all_peers, "", " ")
	if err != nil {
		return err
	}

	_ = ioutil.WriteFile("peers.json", jsonified_peers, 0664)
	return nil
}

func Read_peers() (All_peers, error) {
	reader, err := ioutil.ReadFile("peers.json")
	if err != nil {
		return All_peers{}, err
	}

	var peers All_peers
	json.Unmarshal([]byte(reader), &peers)

	return peers, nil
}

func Decrypt_peer(peerid string, privkey *rsa.PrivateKey, peers []Peer) (Peer, error) {
	var peer Peer

	if jsonized_peer, err := Find_peer(peerid, peers); err == nil { //if peerid found
		json.Unmarshal([]byte(jsonized_peer), &peer)
	} else {
		return Peer{}, err
	}

	var aes_err error

	peer.AES_key, aes_err = Dpenc_AES(peer.AES_key, privkey)
	if aes_err != nil {
		return Peer{}, aes_err
	}

	peerinfo, peerinfo_err := Dkenc_peerinfo(peer.Peerinfo, peer.AES_key)
	if peerinfo_err != nil {
		return Peer{}, peerinfo_err
	}

	jsonified_peerinfo, err := json.Marshal(peerinfo)
	if err != nil {
		return Peer{}, err
	}
	peer.Peerinfo = string(jsonified_peerinfo)

	return peer, nil
}

func Return_temp_peer(peerid string, privkey *rsa.PrivateKey, peers []Peer) (Lpeer, error) {
	peer, peer_err := Decrypt_peer(peerid, privkey, peers)
	if peer_err != nil {
		return Lpeer{}, peer_err
	}

	var peerinfo Peerinfo
	json.Unmarshal([]byte(peer.Peerinfo), &peerinfo)

	temp_peer := Lpeer{peer.Peerid, peerinfo.Protocol, peerinfo.Endpoints}

	return temp_peer, nil
}

// Remove peer if its offline (or Get it back if it becomes online)

func Remove_peer(peerid string, all_peers All_peers) error {
	if Check_peer(peerid, all_peers.Peers) && !Check_peer(peerid, all_peers.Offline_peers) {
		var del_peer Peer

		if jsonized_peer, err := Find_peer(peerid, all_peers.Peers); err == nil { //if peerid found
			var peer Peer
			json.Unmarshal([]byte(jsonized_peer), &peer)
		} else {
			return err
		}

		all_peers.Peers[Index(all_peers.Peers, del_peer)] = all_peers.Peers[len(all_peers.Peers)-1] //Remove peer from peers
		all_peers.Peers = all_peers.Peers[:len(all_peers.Peers)-1]
		all_peers.Offline_peers = append(all_peers.Offline_peers, del_peer) //Add peer to offline_peer

		write_err := Write_peers(all_peers)
		if write_err != nil {
			return write_err
		}
	}

	return nil
}

func Getback_peer(peerid string, all_peers All_peers) error {
	if !Check_peer(peerid, all_peers.Peers) && Check_peer(peerid, all_peers.Offline_peers) {
		var del_peer Peer
		if jsonized_peer, err := Find_peer(peerid, all_peers.Peers); err == nil { //if peerid found
			var peer Peer
			json.Unmarshal([]byte(jsonized_peer), &peer)
		} else {
			return err
		}

		all_peers.Offline_peers[Index(all_peers.Offline_peers, del_peer)] = all_peers.Offline_peers[len(all_peers.Offline_peers)-1] //Remove peer from offline_peer
		all_peers.Offline_peers = all_peers.Offline_peers[:len(all_peers.Offline_peers)-1]
		all_peers.Peers = append(all_peers.Offline_peers, del_peer) //Add peer to peers

		write_err := Write_peers(all_peers)
		if write_err != nil {
			return write_err
		}
	}

	return nil
}

// Exchange temp_peers

func Return_temp_peers(privkey *rsa.PrivateKey, peers []Peer) ([]Lpeer, error) {
	var temp_peers []Lpeer

	if len(peers) <= 5 {
		for _, peer := range peers {
			temp_peer, temp_peer_err := Return_temp_peer(peer.Peerid, privkey, peers)
			if temp_peer_err != nil {
				return []Lpeer{}, temp_peer_err
			}

			temp_peers = append(temp_peers, temp_peer)
		}
	} else {
		for i := 1; i <= 5; i++ {
			random.Seed(time.Now().UnixNano())
			peer := peers[random.Intn(len(peers))]
			switch Check_temp_peers(peer.Peerid, temp_peers) {
			case false:
				temp_peer, temp_peer_err := Return_temp_peer(peer.Peerid, privkey, peers)
				if temp_peer_err != nil {
					return []Lpeer{}, temp_peer_err
				}

				temp_peers = append(temp_peers, temp_peer)
			}
		}
	}

	return temp_peers, nil
}

func Return_temp_peers_bootstrap(privkey *rsa.PrivateKey, all_temp_peers []Lpeer) []Lpeer { //Share from temp_peers file
	var temp_peers []Lpeer

	if len(all_temp_peers) <= 5 {
		temp_peers = append(temp_peers, all_temp_peers...)

	} else {
		for i := 1; i <= 5; i++ {
			random.Seed(time.Now().UnixNano())
			temp_peer := all_temp_peers[random.Intn(len(all_temp_peers))]
			switch Check_temp_peers(temp_peer.Peerid, temp_peers) {
			case false:
				temp_peers = append(temp_peers, temp_peer)
			}
		}
	}

	return temp_peers
}

func Write_temp_peers(temp_peers []Lpeer) error {
	jsonified_temp_peers, err := json.Marshal(temp_peers)
	if err != nil {
		return err
	}

	_ = ioutil.WriteFile("temp_peers", jsonified_temp_peers, 0664)
	return nil
}

func Read_temp_peers() ([]Lpeer, error) {
	reader, err := ioutil.ReadFile("temp_peers")
	if err != nil {
		return []Lpeer{}, err
	}

	var temp_peers []Lpeer
	json.Unmarshal([]byte(reader), &temp_peers)

	return temp_peers, nil
}

func Share_temp_peers(temp_peers []Lpeer, AES_key string) (string, error) {
	jsonified_temp_peers, _ := json.Marshal(temp_peers)
	kenc_temp_peers, aes_err := AES_encrypt(string(jsonified_temp_peers), AES_key)
	if aes_err != nil {
		return "", aes_err
	}
	enc_temp_peers := base64.StdEncoding.EncodeToString([]byte(kenc_temp_peers))

	return enc_temp_peers, nil
}

func Save_temp_peers(enc_temp_peers string, privkey *rsa.PrivateKey, all_peers All_peers, AES_key string, lpeer Lpeer) error {
	var recvd_temp_peers []Lpeer

	b64dec_enc_temp_peers, _ := base64.StdEncoding.DecodeString(enc_temp_peers)

	kdec_temp_peers, aes_err := AES_decrypt(string(b64dec_enc_temp_peers), AES_key)
	if aes_err != nil {
		return aes_err
	}

	json.Unmarshal([]byte(kdec_temp_peers), &recvd_temp_peers)

	var temp_peers []Lpeer
	if _, err := os.Stat("temp_peers"); err == nil {
		var temp_peers_err error

		temp_peers, temp_peers_err = Read_temp_peers()
		if temp_peers_err != nil {
			return temp_peers_err
		}
	}

	for _, temp_peer := range recvd_temp_peers {
		if temp_peer.Peerid != lpeer.Peerid {
			if !Check_peer(temp_peer.Peerid, all_peers.Peers) && !Check_peer(temp_peer.Peerid, all_peers.Offline_peers) && !Check_temp_peers(temp_peer.Peerid, temp_peers) {
				temp_peers = append(temp_peers, temp_peer)
			}
		}
	}

	write_err := Write_temp_peers(temp_peers)
	if write_err != nil {
		return write_err
	}

	return nil
}
