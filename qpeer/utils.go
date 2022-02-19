
package main

import ("encoding/json"
	"fmt"
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
