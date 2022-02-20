
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
	Peerinfo []Peerinfo `json:"peerinfo"`
	AES_key string `json:"key"`
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

func RSA_ExportKeys(privkey *rsa.PrivateKey, pubkey *rsa.PublicKey) RSA_Keys {
	var keys RSA_Keys

	privkey_bytes := x509.MarshalPKCS1PrivateKey(privkey)
    keys.RSA_Privkey = string(pem.EncodeToMemory(
            &pem.Block{
                    Type:  "RSA PRIVATE KEY",
                    Bytes: privkey_bytes,
            },
    ))

    pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
    if err != nil {
            log.Fatal(err)
    }
    keys.RSA_Pubkey = string(pem.EncodeToMemory(
            &pem.Block{
                    Type:  "RSA PUBLIC KEY",
                    Bytes: pubkey_bytes,
            },
    ))

    return keys
}

func RSA_ImportKeys(privkey_pem string, pubkey_pem string) (*rsa.PrivateKey, *rsa.PublicKey) {
	dec_privkey, _ := pem.Decode([]byte(privkey_pem))
	privkey, _ := x509.ParsePKCS1PrivateKey(dec_privkey.Bytes)

	dec_pubkey, _ := pem.Decode([]byte(pubkey_pem))
	pubkey, err := x509.ParsePKIXPublicKey(dec_pubkey.Bytes)
	if err != nil {
		log.Fatal(err)
	}
    return privkey, pubkey.(*rsa.PublicKey)
}

func RSA_Writekeys(keys RSA_Keys) {
	jsonized_keys, err := json.MarshalIndent(keys, "", " ")
	if err != nil {
		log.Fatal(err)
	}
	_ = ioutil.WriteFile("keys.json", jsonized_keys, 0664)
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
	jsonized_lpeer, err := json.Marshal(lpeer)
	if err != nil {
		log.Fatal(err)
	}
	_  = ioutil.WriteFile("lpeer.json", jsonized_lpeer, 0664)
}

func set_lpeer(pubkey_pem string) Lpeer {
	if _, err := os.Stat("lpeer.json"); err == nil{
		var lpeer Lpeer
		lpeer = read_lpeer()
		if lpeer.Peerip != getmyip() { //If public ip has changed
			lpeer.Peerip = getmyip()
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


