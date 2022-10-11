package lib

import (
	"errors"
	"log"
	"os"
)

//RSA errors
var ErrorRSA = errors.New("qpeer: can't encrypt/decrypt rsa") //handled

var ErrorRSAPubKey = errors.New("qpeer: rsa public key is wrong") //handled

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
var ErrorPeerNotFound = errors.New("qpeer: peer not found in db") //handled

var ErrorReadPeers = errors.New("qpeer: can't read peers from db") //handled

var ErrorWritePeers = errors.New("qpeer: can't write peers to db") //handled

//Temp_peers errors
var ErrorTempPeerNotFound = errors.New("qpeer: temp_peer not found in db") //handled

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

var ErrorKencpeerinfo = errors.New("qpeer: can't get AES encrypted peerinfo") //should be handled in connection (quit connection)

var ErrorKdecpeerinfo = errors.New("qpeer: can't decrypt AES encrypted peerinfo") //should be handled in connection (quit connection)

var ErrorPenckey = errors.New("qpeer: can't read/use RSA encrypted AES key") //should be handled in connection (quit connection)

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
		switch err{
		case ErrorJSON || ErrorRSA || ErrorAES || ErrorTempPeerNotFound || ErrorPeerNotFound: //normal log printed to file
			customLog.Println(err)
			return

		case ErrorReadLpeer || ErrorWriteLpeer || ErrorReadPeers || ErrorWritePeers || ErrorReadTempPeers || ErrorWriteTempPeers || ErrorReadRSA || ErrorWriteRSA || ErrorRSAPrivKey || ErrorImportRSA || ErrorExportRSA || ErrorRSAPubKey: //critical error logged to file
			customLog.Fatalln(err)	

		case ErrorPeerid || ErrorSamePeerid || ErrorVerify || ErrorGreet || ErrorBye || ErrorRcvTempPeers || ErrorWriteTCP || ErrorReadTCP || ErrorWriteUDP || ErrorReadUDP: //connection & verification delete peer from db
			if Check_peer(peerid, all_peers.Peers) {
				err = Remove_peer(peerid, all_peers)
			} else if Check_temp_peers(peerid, temp_peers) {
				err = Remove_temp_peer(peerid, temp_peers)
			}

			return
		
		case nil:
			return
		}
			
	}
}

