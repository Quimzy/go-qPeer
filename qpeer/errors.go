package lib

import (
	"errors"
	"log"
	"os"
)

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
var ErrorTempPeerNotFound = errors.New("qpeer: temp_peers not found in db")

var ErrorReadTempPeers = errors.New("qpeer: can't read temp_peers from db") //handled

var ErrorWriteTempPeers = errors.New("qpeer: can't write temp_peers in db") //handled

var ErrorRcvTempPeers = errors.New("qpeer: didn't receive temp peers") //handled

//UDP errors
var ErrorWriteUDP = errors.New("qpeer: can't send packet") //handled

var ErrorReadUDP = errors.New("qpeer: can't read packet") //handled

//TCP errors
var ErrorWriteTCP = errors.New("qpeer: can't send packet") //handled

var ErrorReadTCP = errors.New("qpeer: can't read packet") //handled

//Verification errors
var ErrorPeerid = errors.New("qpeer: peer's peerid doesn't match peer's public key") //handled

var ErrorSamePeerid = errors.New("qpeer: peer has the same peerid as lpeer") //handled

var ErrorVerify = errors.New("qpeer: problem with AES_key verification") //handled

//These errors are not organized

var ErrorGreet = errors.New("qpeer: can't greet peer") //handled

var ErrorBye = errors.New("qpeer: peer did not send bye back") //handled

var ErrorKencpeerinfo = errors.New("qpeer: can't get AES encrypted peerinfo")

var ErrorKdecpeerinfo = errors.New("qpeer: can't decrypt AES encrypted peerinfo")

var ErrorPenckey = errors.New("qpeer: can't read/use RSA encrypted AES key")

// ErrorHandling

func openLogFile(path string) (*os.File, error) {
	logFile, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	return logFile, nil
}

func ErrorHandling(err error, peerid string, all_peers All_peers, temp_peers []Lpeer) {
	errorFile, logfile_err := openLogFile("errors.log")
	if logfile_err != nil {
		log.Println("An error occured.. qPeer won't be able to log errors")
		return
	}

	customLog := log.New(errorFile, "[ERROR] ", log.LstdFlags|log.Lshortfile)

	for {
		if err != nil {
			if errors.Is(err, ErrorJSON) || errors.Is(err, ErrorRSA) || errors.Is(err, ErrorAES) {
				customLog.Println(err)
				return
			} //normal errors logged to file

			if errors.Is(err, ErrorReadLpeer) || errors.Is(err, ErrorWriteLpeer) || errors.Is(err, ErrorReadPeers) || errors.Is(err, ErrorWritePeers) || errors.Is(err, ErrorReadTempPeers) || errors.Is(err, ErrorWriteTempPeers) || errors.Is(err, ErrorReadRSA) || errors.Is(err, ErrorWriteRSA) || errors.Is(err, ErrorRSAPrivKey) || errors.Is(err, ErrorImportRSA) || errors.Is(err, ErrorExportRSA) || errors.Is(err, ErrorRSAPubKey) {
				customLog.Fatalln(err)
			} //critical error logged to file

			if errors.Is(err, ErrorPeerid) || errors.Is(err, ErrorSamePeerid) || errors.Is(err, ErrorVerify) || errors.Is(err, ErrorGreet) || errors.Is(err, ErrorBye) || errors.Is(err, ErrorRcvTempPeers) || errors.Is(err, ErrorWriteTCP) || errors.Is(err, ErrorReadTCP) || errors.Is(err, ErrorWriteUDP) || errors.Is(err, ErrorReadUDP) {
				if Check_peer(peerid, all_peers.Peers) {
					err = Remove_peer(peerid, all_peers)
				} else if Check_temp_peers(peerid, temp_peers) {
					err = Remove_temp_peer(peerid, temp_peers)
				}
			} //connection & verification delete peer from db
		}
	}
}
