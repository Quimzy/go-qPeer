
package qpeer_testing

import ("testing"
	qpeer "github.com/Quirk-io/go-qPeer/qpeer"
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

/*func TestIndex(t *testing.T){
}*/

