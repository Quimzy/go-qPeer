
package main

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
)

type RSA_Keys struct {
	RSA_Privkey string `json:"privkey"`
	RSA_Pubkey string `json:"pubkey"`
}

type Lpeer struct
{
	Peerid string `json:"peerid"`
	Role int `json:"role"`
	Peerip string `json:"peerip"`
	Port int `json:"port"`
}

type Peers struct
{
	Peers []Peer `json:"peers"`
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
	Port int 
	RSA_Pubkey string
}

// Basic functions

func sha1_encrypt(msg string) string {
	h := sha1.New()
	h.Write([]byte(msg))
	return string(fmt.Sprintf("%x", h.Sum(nil)))
}

func md5_encrypt(msg string) string {
    return string(fmt.Sprintf("%x", md5.Sum([]byte(msg))))
}

func randomString(length int) string {
	random.Seed(time.Now().UnixNano())
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	s := make([]byte, 0, length)
	for i := 0; i < length; i++ {
		s = append(s, alphabet[random.Intn(len(alphabet))])
	}
	return string(s)
}

// Peer setup

func getmyip() string {
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

func set_RSA_Keys() (*rsa.PrivateKey, *rsa.PublicKey) {
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

func read_lpeer() Lpeer {
	reader, err := ioutil.ReadFile("lpeer.json")
	if err != nil {
		log.Fatal(err)
	}
	var lpeer Lpeer
	json.Unmarshal([]byte(reader), &lpeer)
	return lpeer
}

func write_lpeer(lpeer Lpeer) {
	jsonified_lpeer, err := json.Marshal(lpeer)
	if err != nil {
		log.Fatal(err)
	}
	_  = ioutil.WriteFile("lpeer.json", jsonified_lpeer, 0664)
}

func set_lpeer(pubkey_pem string) Lpeer {
	if _, err := os.Stat("lpeer.json"); err == nil{
		var lpeer Lpeer
		lpeer = read_lpeer()
		if lpeer.Peerip != getmyip() { //If public ip has changed
			lpeer.Peerip = getmyip()
			write_lpeer(lpeer)
		}
		return lpeer
	} else{
		var lpeer Lpeer

		//Generating Peerid
		
		lpeer.Peerid = sha1_encrypt(pubkey_pem)

		//Setting the rest of the variables
		lpeer.Role = 0
		lpeer.Peerip = getmyip()
		lpeer.Port = 1691

		write_lpeer(lpeer)
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
	key := md5_encrypt(randomString(32))
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

func penc_AES(AES_key string, pubkey *rsa.PublicKey) string { // Public Key encryption for AES_key
	enc_AES_key := base64.StdEncoding.EncodeToString([]byte(RSA_encrypt(AES_key, pubkey)))

	return enc_AES_key
}

func dpenc_AES(enc_AES_key string, privkey *rsa.PrivateKey) string {
	b64dec_AES_key, err := base64.StdEncoding.DecodeString(enc_AES_key)
	if err != nil {
		log.Fatal(err)
	}
	AES_key := RSA_decrypt(string(b64dec_AES_key), privkey)

	return AES_key
}

// MsgTypes

type Qpeer struct 
{
	msgtype string `json:"msgtype"`
	peerid string `json:"peerid"`
}

type Init struct
{
	peerid string `json:"peerid"`
	pubkey_pem string `json:"pubkey"`
}

func qpeer(peerid string) Qpeer {
	qpeer_msg := Qpeer{"qpeer", peerid}

	return qpeer_msg
} 

func exchange_peers(peerid string) Qpeer {
	exchange_peers_msg := Qpeer{"exchange_peers", peerid}

	return exchange_peers_msg
}

func init_enc(peerid string, pubkey_pem string) Init {
	init_msg := Init{peerid, pubkey_pem}

	return init_msg
}

// Exchanging peerinfo

func peerinfo(role int, peerip string, port int, pubkey_pem string) Peerinfo {
	peerinfo := Peerinfo{role, peerip, port, pubkey_pem}

	return peerinfo
}
func kenc_peerinfo(peerinfo Peerinfo, AES_key string) string { //Key Encryption (AES)
	jsonified_peerinfo, err := json.Marshal(peerinfo) //From struct to a string
	if err != nil {
		log.Fatal(err)
	}
	kenc_peerinfo := AES_encrypt(string(jsonified_peerinfo), AES_key) //Encrypting peerinfo with Key

	return base64.StdEncoding.EncodeToString([]byte(kenc_peerinfo))
}

func dkenc_peerinfo(kenc_peerinfo string, AES_key string) Peerinfo { // Decrypt Key Encryption (AES)
	b64dec_peerinfo, _ := base64.StdEncoding.DecodeString(kenc_peerinfo) //Decoding base64
	kdec_peerinfo := AES_decrypt(string(b64dec_peerinfo), AES_key) //Decrypting peerinfo with Key
	
	var peerinfo Peerinfo
	json.Unmarshal([]byte(kdec_peerinfo), &peerinfo)

	return peerinfo
}

// Saving peer

func save_peer(peerid string, peerinfo Peerinfo, AES_key string, pubkey *rsa.PublicKey) Peer {
	jsonified_kenc_peerinfo, _ := json.Marshal(peerinfo)
	kenc_peerinfo := AES_encrypt(string(jsonified_kenc_peerinfo), AES_key)
	penc_key := RSA_encrypt(AES_key, pubkey)
	var peer Peer
	peer = Peer{peerid, base64.StdEncoding.EncodeToString([]byte(kenc_peerinfo)), penc_key, 1}

	write_peer(peer)
	return peer
}

func write_peer(peer Peer) {
	
	jsonified_peer, err := json.Marshal(peer)
	if err != nil {
		log.Fatal(err)
	}
	_  = ioutil.WriteFile("peers.json", jsonified_peer, 0664)

}

