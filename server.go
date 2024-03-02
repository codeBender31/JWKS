package main

//Import all necessary libraries and useful repos
import(
	"encoding/json" //To encode and decode JSON objects
	"encoding/base64" //To encode into base64 format
	"crypto/rsa" //To use for cryptography needed for RSA functionality
	"crypto/rand" //To be able to assign random numbers
	"math/big" //For calculations with large ints regarding RSA
	"net/http" //To set up HTTP connection
	"time"//Needed to be able to time out JWTS kid's
	"log" //To check the logs in the console
	"github.com/golang-jwt/jwt/v4" //Use repo from github to handle JWTs
	//Reference https://github.com/golang-jwt/jwt
)

//Define struct to hold keys
type keyPair struct{
	publicKey *rsa.PublicKey
	privateKey *rsa.PrivateKey //Two variables to hold rsa key pointers
	kid 		string
	expiryTime	time.Time	
}

//Create a container to hold keyPairs
var keyPairs []keyPair

//Method to define key pair
func generateKeys(kid string, numberOfBits int, expiryTime time.Time) keyPair{
	//Generate the private key
	newPrivateKey, err := rsa.GenerateKey(rand.Reader, numberOfBits)
	if err != nil{
		log.Fatalf("Failure: %v", err)//Show me the error that is generated if it does not work
	}
	//Extract public key from the generation command
	 newPublicKey := &newPrivateKey.PublicKey

	return keyPair{ //return a keyPair object
		publicKey: newPublicKey,
		privateKey: newPrivateKey,
		kid : kid,
		expiryTime: expiryTime,
	}
}
