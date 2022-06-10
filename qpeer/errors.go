package lib

import "errors"

var ErrorGreet = errors.New("qpeer: can't greet peer")

var ErrorPeerid = errors.New("qpeer: peer's peerid doesn't match peer's public key")

var ErrorKpeerinfo = errors.New("qpeer: can't get AES encrypted peerinfo")

var ErrorSamePeerid = errors.New("qpeer: peer has the same peerid as lpeer")

var ErrorBye = errors.New("qpeer: peer did not send bye back")
