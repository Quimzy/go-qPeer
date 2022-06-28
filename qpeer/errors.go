package lib

import "errors"

//RSA errors
var ErrorRSA = errors.New("qpeer: can't encrypt/decrypt rsa") //handled

var ErrorRSAPubKey = errors.New("qpeer: rsa public key is wrong")

var ErrorRSAPrivKey = errors.New("qpeer: rsa private key is wrong") //handled

var ErrorReadRSA = errors.New("qpeer: can't read from file") //handled

var ErrorWriteRSA = errors.New("qpeer: can't write to file") //handled

var ErrorImportRSA = errors.New("qpeer: can't import rsa keys") //handled

var ErrorExportRSA = errors.New("qpeer: can't export rsa keys") //handled

//AES errors
var ErrorAES = errors.New("qpeer: can't encrypt/decrypt aes") //handled

var ErrorAESKey = errors.New("qpeer: aes key is wrong")

//JSON errors
var ErrorJSON = errors.New("qpeer: can't marshal/unmarshal json") //handled

//Lpeer errors
var ErrorReadLpeer = errors.New("qpeer: can't read peers from lpeer.json") //handled

var ErrorWriteLpeer = errors.New("qpeer: can't write lpeer to lpeer.json") //handled

//Peers errors
var ErrorPeerNotFound = errors.New("qpeer: peer not found in db")

var ErrorReadPeers = errors.New("qpeer: can't read peers from db") //handled

var ErrorWritePeers = errors.New("qpeer: can't write peers to db") //handled

//Temp_peers errors
//var ErrorTempPeerNotFound = errors.New("qpeer: temp_peers not found in db") not needed?

var ErrorReadTempPeers = errors.New("qpeer: can't read temp_peers from db") //handled

var ErrorWriteTempPeers = errors.New("qpeer: can't write temp_peers in db") //handled

var ErrorRcvTempPeers = errors.New("qpeer: didn't receive temp peers")

//UDP errors
var ErrorWriteUDP = errors.New("qpeer: can't send packet")

var ErrorReadUDP = errors.New("qpeer: can't read packet")

//TCP errors
var ErrorWriteTCP = errors.New("qpeer: can't send packet")

var ErrorReadTCP = errors.New("qpeer: can't read packet")

//Verification errors
var ErrorPeerid = errors.New("qpeer: peer's peerid doesn't match peer's public key")

var ErrorSamePeerid = errors.New("qpeer: peer has the same peerid as lpeer")

var ErrorVerify = errors.New("qpeer: problem with AES_key verification")

//These errors are not organized

var ErrorGreet = errors.New("qpeer: can't greet peer")

var ErrorKencpeerinfo = errors.New("qpeer: can't get AES encrypted peerinfo")

var ErrorKdecpeerinfo = errors.New("qpeer: can't decrypted AES encrypted peerinfo")

var ErrorBye = errors.New("qpeer: peer did not send bye back")

var ErrorPenckey = errors.New("qpeer: can't read/use RSA encrypted AES key")
