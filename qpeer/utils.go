
package qpeer

import ("encoding/json"
	"io/ioutil"
	"time"
	"log"
	"fmt"
	"os"
	random "math/rand"
	"net/http"
    "crypto"
	"crypto/sha1"
	"crypto/md5"
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
    "encoding/pem"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"strings"
)

type RSA_Keys struct 
{
	RSA_Privkey string `json:"privkey"`
	RSA_Pubkey string `json:"pubkey"`
}

type Lpeer struct
{
	Peerid string `json:"peerid"`
	Role int `json:"role"`
	Peerip string `json:"peerip"`
	Port string `json:"port"`
}

type All_peers struct
	{
	Peers []Peer `json:"peers"`
	Offline_peers []Peer `json:"offline_peers"`
}

type Peer struct
{
	Peerid string `json:"peerid"`
	Peerinfo string `json:"peerinfo"`
	AES_key string `json:"key"`
	Stauts int `json:"status"`
}

type Peerinfo struct
{
	Role int 
	Peerip string 
	Port string 
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

func Index(peers []Peer, peer Peer) int{
    for i, n_peer := range peers {
        if n_peer == peer {
            return i
        }
    }
    return -1
}

func Check_peer(peerid string, peers []Peer) bool {
	for _, n_peer := range peers{
		switch strings.Compare(n_peer.Peerid, peerid){
		case 0:
			return true
			break
		default:
		}
	}

	return false
}

func Check_temp_peers(peerid string, temp_peers []Lpeer) bool {
	for _, n_peer := range temp_peers{
		switch strings.Compare(n_peer.Peerid, peerid){
		case 0:
			return true
			break
		default:
		}
	}

	return false
}

func Find_peer(peerid string, peers []Peer) string{
	for _, n_peer := range peers{
		switch strings.Compare(n_peer.Peerid, peerid){
		case 0:
			jsonified_peer, err := json.Marshal(n_peer)
			if err != nil {
				log.Fatal(err)
			}
			return string(jsonified_peer)
			break
		default:
		}
	}
	return ""

}

func Find_temp_peer(peerid string, temp_peers []Lpeer) string{
	for _, n_peer := range temp_peers{
		switch strings.Compare(n_peer.Peerid, peerid){
		case 0:
			jsonified_peer, err := json.Marshal(n_peer)
			if err != nil {
				log.Fatal(err)
			}
			return string(jsonified_peer)
			break
		default:
		}
	}
	return ""

}

// Peer setup

func Getmyip() string {
	req, err := http.Get("https://api.ipify.org")
	if err != nil {
		log.Fatal(err)
	}
	ip, _ := ioutil.ReadAll(req.Body)
	return string(ip)
}

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

func RSA_ExportPubkey(pubkey *rsa.PublicKey) string {
	pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	    if err != nil {
	            log.Fatal(err)
	    }
	RSA_Pubkey := string(pem.EncodeToMemory(
	        &pem.Block{
	                Type:  "RSA PUBLIC KEY",
	                Bytes: pubkey_bytes,
	        },
	))

	return RSA_Pubkey
}

func RSA_ExportKeys(privkey *rsa.PrivateKey, pubkey *rsa.PublicKey) RSA_Keys {
	var keys RSA_Keys
	keys.RSA_Privkey = RSA_ExportPrivkey(privkey)
	keys.RSA_Pubkey = RSA_ExportPubkey(pubkey)

	return keys
}

func RSA_ImportPrivkey(privkey_pem string) *rsa.PrivateKey {
	dec_privkey, _ := pem.Decode([]byte(privkey_pem))
	privkey, _ := x509.ParsePKCS1PrivateKey(dec_privkey.Bytes)

	return privkey
	
}

func RSA_ImportPubkey(pubkey_pem string) *rsa.PublicKey {
	dec_pubkey, _ := pem.Decode([]byte(pubkey_pem))
	pubkey, err := x509.ParsePKIXPublicKey(dec_pubkey.Bytes)
	if err != nil {
		log.Fatal(err)
	}
    return pubkey.(*rsa.PublicKey)
}

func RSA_ImportKeys(privkey_pem string, pubkey_pem string) (*rsa.PrivateKey, *rsa.PublicKey) {
	return RSA_ImportPrivkey(privkey_pem), RSA_ImportPubkey(pubkey_pem)
}

func RSA_Writekeys(keys RSA_Keys) {
	jsonified_keys, err := json.MarshalIndent(keys, "", " ")
	if err != nil {
		log.Fatal(err)
	}
	_ = ioutil.WriteFile("keys.json", jsonified_keys, 0664)
}

func RSA_Readkeys() RSA_Keys {
	reader, err := ioutil.ReadFile("keys.json")
	if err != nil {
		log.Fatal(err)
	}
	var keys RSA_Keys
	json.Unmarshal([]byte(reader), &keys)

	return keys
}

func Set_RSA_Keys() (*rsa.PrivateKey, *rsa.PublicKey) {
	if _, err := os.Stat("keys.json"); err == nil{
		var keys RSA_Keys
		keys = RSA_Readkeys()
		return RSA_ImportKeys(keys.RSA_Privkey, keys.RSA_Pubkey)
	} else {
		var keys RSA_Keys
		privkey, pubkey := RSA_keygen()
		keys = RSA_ExportKeys(privkey, pubkey)
		RSA_Writekeys(keys)
		return privkey, pubkey
	}

}

func Read_lpeer() Lpeer {
	reader, err := ioutil.ReadFile("lpeer.json")
	if err != nil {
		log.Fatal(err)
	}
	var lpeer Lpeer
	json.Unmarshal([]byte(reader), &lpeer)
	return lpeer
}

func Write_lpeer(lpeer Lpeer) {
	jsonified_lpeer, err := json.Marshal(lpeer)
	if err != nil {
		log.Fatal(err)
	}
	_  = ioutil.WriteFile("lpeer.json", jsonified_lpeer, 0664)
}

func Set_lpeer(pubkey_pem string) Lpeer {
	if _, err := os.Stat("lpeer.json"); err == nil{
		var lpeer Lpeer
		lpeer = Read_lpeer()
		if lpeer.Peerip != Getmyip() { //If public ip has changed
			lpeer.Peerip = Getmyip()
			Write_lpeer(lpeer)
		}
		return lpeer
	} else{
		var lpeer Lpeer

		//Generating Peerid
		
		lpeer.Peerid = Sha1_encrypt(pubkey_pem)

		//Setting the rest of the variables
		lpeer.Role = 0
		lpeer.Peerip = Getmyip()
		lpeer.Port = "1691"

		Write_lpeer(lpeer)
		return lpeer
	}
}

// Encryption Functions

func RSA_encrypt(msg string, pubkey *rsa.PublicKey) string {
	enc_msg, err := rsa.EncryptOAEP(
		sha1.New(),
		rand.Reader,
		pubkey,
		[]byte(msg),
		nil)
	if err != nil {
		log.Fatal(err)
	}

	return string(enc_msg)
}

func RSA_decrypt(enc_msg string, privkey *rsa.PrivateKey) string {
	msg, err := privkey.Decrypt(nil, []byte(enc_msg), &rsa.OAEPOptions{Hash: crypto.SHA1})
	if err != nil {
		log.Fatal(err)
	}
	return string(msg)
}

func AES_keygen() string {
	key := Md5_encrypt(RandomString(32))
	return key
}

func AES_encrypt(msg string, key string) string {
	c, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal(err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Fatal(err)
	}

	nonce := make([]byte, gcm.NonceSize())

	enc_msg := gcm.Seal(nonce, nonce, []byte(msg), nil)
	return string(enc_msg)
}

func AES_decrypt(enc_msg string, key string) string {
	c, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal(err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Fatal(err)
	}

	nonceSize := gcm.NonceSize()
	if len(enc_msg) < nonceSize {
		log.Fatal(err)
	}

	nonce, enc_msg := enc_msg[:nonceSize], enc_msg[nonceSize:]
	
	msg, err := gcm.Open(nil, []byte(nonce), []byte(enc_msg), nil)
    if err != nil {
        log.Fatal(err)
    }

	return string(msg)
}

func Penc_AES(AES_key string, pubkey *rsa.PublicKey) string { // Public Key encryption for AES_key
	enc_AES_key := base64.StdEncoding.EncodeToString([]byte(RSA_encrypt(AES_key, pubkey)))

	return enc_AES_key
}

func Dpenc_AES(enc_AES_key string, privkey *rsa.PrivateKey) string {
	b64dec_AES_key, err := base64.StdEncoding.DecodeString(enc_AES_key)
	if err != nil {
		log.Fatal(err)
	}
	AES_key := RSA_decrypt(string(b64dec_AES_key), privkey)

	return AES_key
}

func Kenc_peerinfo(peerinfo Peerinfo, AES_key string) string { //Key Encryption (AES)
	jsonified_peerinfo, err := json.Marshal(peerinfo) //From struct to a string
	if err != nil {
		log.Fatal(err)
	}
	kenc_peerinfo := AES_encrypt(string(jsonified_peerinfo), AES_key) //Encrypting peerinfo with Key

	return base64.StdEncoding.EncodeToString([]byte(kenc_peerinfo))
}

func Dkenc_peerinfo(kenc_peerinfo string, AES_key string) Peerinfo { // Decrypt Key Encryption (AES)
	b64dec_peerinfo, _ := base64.StdEncoding.DecodeString(kenc_peerinfo) //Decoding base64
	kdec_peerinfo := AES_decrypt(string(b64dec_peerinfo), AES_key) //Decrypting peerinfo with Key
	
	var peerinfo Peerinfo
	json.Unmarshal([]byte(kdec_peerinfo), &peerinfo)

	return peerinfo
}

func Kenc_verify(msg string, key string) string {
	kenc_verify := base64.StdEncoding.EncodeToString([]byte(AES_encrypt(msg, key)))
	return kenc_verify
}

func Dkenc_verify(enc_msg string, key string) string{
	b64dec_verify, _ := base64.StdEncoding.DecodeString(enc_msg)
	return AES_decrypt(string(b64dec_verify), key)
}

func Kenc_lpeer(lpeer Lpeer, AES_key string) string {
	jsonified_lpeer, err := json.Marshal(lpeer) 
	if err != nil {
		log.Fatal(err)
	}
	kenc_lpeer := AES_encrypt(string(jsonified_lpeer), AES_key) //Encrypting lpeer with Key

	return base64.StdEncoding.EncodeToString([]byte(kenc_lpeer))
}

func Dkenc_lpeer(kenc_lpeer string, AES_key string) Lpeer {
	b64dec_lpeer, _ := base64.StdEncoding.DecodeString(kenc_lpeer) 
	kdec_lpeer := AES_decrypt(string(b64dec_lpeer), AES_key) //Decrypting lpeer with Key
	
	var lpeer Lpeer
	json.Unmarshal([]byte(kdec_lpeer), &lpeer)

	return lpeer
}

// MsgTypes

type Qpeer struct 
{
	Msgtype string `json:"msgtype"`
	Peerid string `json:"peerid"`
}

type Init struct
{
	Peerid string `json:"peerid"`
	Pubkey_pem string `json:"pubkey"`
}

func Setup(peerid string) Qpeer {
	qpeer_msg := Qpeer{"setup", peerid}

	return qpeer_msg
} 

func Exchange_peers(peerid string) Qpeer {
	exchange_peers_msg := Qpeer{"exchange_peers", peerid}

	return exchange_peers_msg
}

func Init_enc(peerid string, pubkey_pem string) Init {
	init_msg := Init{peerid, pubkey_pem}

	return init_msg
}

// Generating peerinfo

func peerinfo(role int, peerip string, port string, pubkey_pem string) Peerinfo {
	peerinfo := Peerinfo{role, peerip, port, pubkey_pem}

	return peerinfo
}

// Saving peer

func Save_peer(peerid string, peerinfo Peerinfo, AES_key string, pubkey *rsa.PublicKey, all_peers All_peers) All_peers {
	jsonified_kenc_peerinfo, _ := json.Marshal(peerinfo)
	kenc_peerinfo := AES_encrypt(string(jsonified_kenc_peerinfo), AES_key)
	penc_key := RSA_encrypt(AES_key, pubkey)
	var peer Peer
	peer = Peer{peerid, base64.StdEncoding.EncodeToString([]byte(kenc_peerinfo)), base64.StdEncoding.EncodeToString([]byte(penc_key)), 1}
	
	all_peers.Peers = append(all_peers.Peers, peer)
	return all_peers
	
}

func Write_peers(all_peers All_peers) {
	jsonified_peers, err := json.MarshalIndent(all_peers, "", " ")
	if err != nil{
		log.Fatal(err)
	}

	_  = ioutil.WriteFile("peers.json", jsonified_peers, 0664)	
}

func Read_peers() All_peers {
	reader, err := ioutil.ReadFile("peers.json")
	if err != nil {
		log.Fatal(err)
	}

	var peers All_peers
	json.Unmarshal([]byte(reader), &peers)

	return peers
}

func Decrypt_peer(peerid string, privkey *rsa.PrivateKey, peers []Peer) Peer {
	var peer Peer

	if len(Find_peer(peerid, peers)) > 0{
		json.Unmarshal([]byte(Find_peer(peerid, peers)), &peer)
	}

	peer.AES_key = Dpenc_AES(peer.AES_key, privkey)
	jsonified_peerinfo, err := json.Marshal(Dkenc_peerinfo(peer.Peerinfo, peer.AES_key))
	if err != nil{
		log.Fatal(err)
	}
	peer.Peerinfo = string(jsonified_peerinfo)

	return peer

}

func Return_temp_peer(peerid string, privkey *rsa.PrivateKey, peers []Peer) Lpeer {
	peer := Decrypt_peer(peerid, privkey, peers)
	
	var peerinfo Peerinfo
	json.Unmarshal([]byte(peer.Peerinfo), &peerinfo)
	
	temp_peer := Lpeer{peer.Peerid, peerinfo.Role, peerinfo.Peerip, peerinfo.Port}

	return temp_peer
}

// Remove peer if its offline (or Get it back if it becomes online)

func Remove_peer(peerid string, all_peers All_peers) All_peers{
	if (Check_peer(peerid, all_peers.Peers) == true && Check_peer(peerid, all_peers.Offline_peers) == false){
		var del_peer Peer
		json.Unmarshal([]byte(Find_peer(peerid, all_peers.Peers)), &del_peer)
		
		all_peers.Peers[Index(all_peers.Peers, del_peer)] = all_peers.Peers[len(all_peers.Peers)-1] //Remove peer from peers
		all_peers.Offline_peers = append(all_peers.Offline_peers, del_peer) //Add peer to offline_peer

		Write_peers(all_peers)
		return all_peers
	}

	return all_peers
}

func Getback_peer(peerid string, all_peers All_peers) All_peers{
	if (Check_peer(peerid, all_peers.Peers) == false && Check_peer(peerid, all_peers.Offline_peers) == true){
		var del_peer Peer
		json.Unmarshal([]byte(Find_peer(peerid, all_peers.Peers)), &del_peer)
		all_peers.Offline_peers[Index(all_peers.Offline_peers, del_peer)] = all_peers.Offline_peers[len(all_peers.Offline_peers)-1]  //Remove peer from offline_peer
		all_peers.Peers = append(all_peers.Offline_peers, del_peer) //Add peer to peers

		Write_peers(all_peers)
		return all_peers
	}

	return all_peers
}

// Exchange temp_peers

func Return_temp_peers(privkey *rsa.PrivateKey, peers []Peer) []Lpeer{
	var temp_peers []Lpeer
	
	if len(peers) <= 5{
		for _, peer := range peers {
			temp_peer := Return_temp_peer(peer.Peerid, privkey, peers)
			temp_peers = append(temp_peers, temp_peer)
		}
	}else{
		for i := 1; i<=5; i++ {
			random.Seed(time.Now().UnixNano())
			peer := peers[random.Intn(len(peers))]
			switch Check_temp_peers(peer.Peerid, temp_peers){
			case false:
				temp_peer := Return_temp_peer(peer.Peerid, privkey, peers)
				temp_peers = append(temp_peers, temp_peer)
			}
		}
	}

	return temp_peers
}

func Share_temp_peers(temp_peers []Lpeer, AES_key string) string {
	jsonified_temp_peers, _ := json.Marshal(temp_peers)
	enc_temp_peers := base64.StdEncoding.EncodeToString([]byte(AES_encrypt(string(jsonified_temp_peers), AES_key)))

	return enc_temp_peers
}

func Save_temp_peers(enc_temp_peers string, privkey *rsa.PrivateKey, all_peers All_peers, AES_key string, lpeer Lpeer) []Lpeer {
	var temp_peers []Lpeer
	
	b64dec_enc_temp_peers, _ := base64.StdEncoding.DecodeString(enc_temp_peers)
	json.Unmarshal([]byte(AES_decrypt(string(b64dec_enc_temp_peers), AES_key)), &temp_peers)
	for _, temp_peer := range temp_peers{
		if temp_peer != lpeer{
			if Check_peer(temp_peer.Peerid, all_peers.Peers) == false || Check_peer(temp_peer.Peerid, all_peers.Offline_peers){
				temp_peers = append(temp_peers, temp_peer)		
			}
		}
	}

	return temp_peers
}
