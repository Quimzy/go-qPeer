
package main

import ("encoding/json"
	"io/ioutil"
	"log"
	"fmt"
	"net/http"
	"crypto/sha1"
	"crypto/rsa"
	"crypto/rand"
	"os"
	"crypto/x509"
    "encoding/pem"

)

type RSA_Keys struct {
	RSA_Privkey string
	RSA_Pubkey string
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
	AES_iv int `json:"iv"`
	AES_key string `json:"key"`
}

type Peerinfo struct
{
	Role int 
	Peerip string 
	Port int 
	RSA_Pubkey string
}

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

func RSA_ExportKey(privkey *rsa.PrivateKey, pubkey *rsa.PublicKey) RSA_Keys {
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

func read_lpeer() Lpeer {
	reader, err := ioutil.ReadFile("lpeer.json")
	if err != nil {
		log.Fatal(err)
	}
	var lpeer Lpeer
	json.Unmarshal([]byte(reader), &lpeer)
	return lpeer
}

func set_lpeer(pubkey_pem string) Lpeer {
	if _, err := os.Stat("lpeer.json"); err == nil{
		var lpeer Lpeer
		lpeer = read_lpeer()
		if lpeer.Peerip != getmyip() {
			lpeer.Peerip = getmyip()
		}
		return lpeer
	} else{
		var lpeer Lpeer

		h := sha1.New()
		h.Write([]byte(pubkey_pem))
		lpeer.Peerid = string(fmt.Sprintf("%x", h.Sum(nil)))

		lpeer.Role = 0
		lpeer.Peerip = getmyip()
		lpeer.Port = 1691
		write_lpeer(lpeer)
		return lpeer
	}
}

func write_lpeer(lpeer Lpeer) {
	jsonized_lpeer, err := json.Marshal(lpeer)
	if err != nil {
		log.Fatal(err)
	}
	_  = ioutil.WriteFile("lpeer.json", jsonized_lpeer, 0664)
}

