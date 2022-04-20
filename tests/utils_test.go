
package qpeer_testing

import ("testing"
	"fmt"
	qpeer "github.com/quirkio/go-qPeer/qpeer"
)

const (peerip = "localhost"
	port = "1691"
	AES_key = "4342ba80a22071aab0e031922e0671d0"
)

func TestSha1(t *testing.T){
	msg := "quirk"
	hash_msg_wanted := "f47c844721fa50459f2d6558d1904a688bc13ee2"
	hash_msg_recvd := qpeer.Sha1_encrypt(msg)

	if hash_msg_recvd != hash_msg_wanted{
		t.Errorf("Sha1 error. Wanted: %s, Recvd: %s", hash_msg_wanted, hash_msg_recvd )
	}
}

func TestMd5(t *testing.T){
	msg := "quirk"
	hash_msg_wanted := "4342ba80a22071aab0e031922e0671d0"
	hash_msg_recvd := qpeer.Md5_encrypt(msg)

	if hash_msg_recvd != hash_msg_wanted{
		t.Errorf("Md5 error. Wanted: %s, Recvd: %s", hash_msg_wanted, hash_msg_recvd )
	}
}

func TestIndex(t *testing.T){

}

func TestRSA_keygen(t *testing.T){
	privkey, pubkey := qpeer.RSA_keygen()
	if fmt.Sprintf("%T", privkey) != "*rsa.PrivateKey" && fmt.Sprintf("%T", pubkey) != "*rsa.PublicKey"{
		t.Errorf("RSA error. The keys generated are not the correct type")
	}
}

func TestRSA_Readkeys(t *testing.T){
	keys := qpeer.RSA_Readkeys()
	if fmt.Sprintf("%T", keys) != "qpeer.RSA_Keys"{
		t.Errorf("RSA error. The keys stored are not the correct type")
	}
}