
package main

import ("encoding/json"
	"io/ioutil"
	"log"
	"net/http"
)

type RSA_keys struct {
	RSA_Pubkey string
	RSA_Privkey string
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


func read_lpeer() Lpeer {
	reader, err := ioutil.ReadFile("lpeer.json")
	if err != nil {
		log.Fatal(err)
	}
	var lpeer Lpeer
	json.Unmarshal([]byte(reader), &lpeer)
	return lpeer
}

func getmyip() string {
	req, err := http.Get("https://api.ipify.org")
	if err != nil {
		log.Fatal(err)
	}
	ip, _ := ioutil.ReadAll(req.Body)
	return string(ip)
}

