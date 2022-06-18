package lib

import "errors"

// RSA errors
var ErrorRSA = errors.New("qpeer: can't encrypt/decrypt rsa")

var ErrorRSAPubKey = errors.New("qpeer: rsa public key is wrong")

var ErrorRSAPrivKey = errors.New("qpeer: rsa private key is wrong")

var ErrorReadRSA = errors.New("qpeer: can't read from file")

var ErrorWriteRSA = errors.New("qpeer: can't write to file")

var ErrorImportRSA = errors.New("qpeer: can't import rsa keys")

var ErrorExportRSA = errors.New("qpeer: can't export rsa keys")

//AES errors
var ErrorAES = errors.New("qpeer: can't encrypt/decrypt aes")

var ErrorAESKey = errors.New("qpeer: aes key is wrong")

//JSON errors
var ErrorJSON = errors.New("qpeer: can't marshal/unmarshal json")

//Lpeer errors
var ErrorReadLpeer = errors.New("qpeer: can't read peers from lpeer.json")

var ErrorWriteLpeer = errors.New("qpeer: can't write lpeer to lpeer.json")

//Peers errors
var ErrorPeerNotFound = errors.New("qpeer: peer not found in db")

var ErrorReadPeers = errors.New("qpeer: can't read peers from db")

var ErrorWritePeers = errors.New("qpeer: can't write peers to db")

//Temp_peers errors
var ErrorTempPeerNotFound = errors.New("qpeer: temp_peers not found in db")

var ErrorReadTempPeers = errors.New("qpeer: can't read temp_peers from db")

var ErrorWriteTempPeers = errors.New("qpeer: can't write temp_peers in db")

var ErrorRcvTempPeers = errors.New("qpeer: didn't receive temp peers")

//These errors are not organized

var ErrorGreet = errors.New("qpeer: can't greet peer")

var ErrorPeerid = errors.New("qpeer: peer's peerid doesn't match peer's public key")

var ErrorKencpeerinfo = errors.New("qpeer: can't get AES encrypted peerinfo")

var ErrorKdecpeerinfo = errors.New("qpeer: can't decrypted AES encrypted peerinfo")

var ErrorSamePeerid = errors.New("qpeer: peer has the same peerid as lpeer")

var ErrorBye = errors.New("qpeer: peer did not send bye back")

var ErrorVerify = errors.New("qpeer: problem with AES_key verification")

var ErrorPenckey = errors.New("qpeer: can't read/use RSA encrypted AES key")
