package main

//Import all necessary libraries and useful repos
import (
	"crypto/rand"     //To be able to assign random numbers
	"crypto/rsa"      //To use for cryptography needed for RSA functionality
	"encoding/base64" //To encode into base64 format
	"encoding/json"   //To encode and decode JSON objects
	"fmt"             // Tp format the responses
	"log"             //To check the logs in the console
	"math/big"        //For calculations with large ints regarding RSA
	"net/http"        //To set up HTTP connection
	"time"            //Needed to be able to time out JWTS kid's

	"github.com/golang-jwt/jwt/v4" //Use repo from github to handle JWTs
	//Reference https://github.com/golang-jwt/jwt

	"database/sql" //Import the sqlite database library

	_ "github.com/mattn/go-sqlite3" //Import the driver
)

// Define struct to hold keys
type keyPair struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey //Two variables to hold rsa key pointers
	kid        string
	expiryTime time.Time
}

// // Defining the database globally
const (
	dataBaseFile = "totally_not_my_privateKeys.db"
	createTable  = `CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	)`
)

// Create a container to hold keyPairs
var keyPairs []keyPair

// Method to define key pair
func generateKeys(kid string, numberOfBits int, expiryTime time.Time) keyPair {
	//Generate the private key
	newPrivateKey, err := rsa.GenerateKey(rand.Reader, numberOfBits)
	if err != nil {
		log.Fatalf("Failure: %v", err) //Show me the error that is generated if it does not work
	}
	//Extract public key from the generation command
	newPublicKey := &newPrivateKey.PublicKey

	return keyPair{ //return a keyPair object
		publicKey:  newPublicKey,
		privateKey: newPrivateKey,
		kid:        kid,
		expiryTime: expiryTime,
	}
}

// Create a method to handle the publicKey
func handlePublicKey(write http.ResponseWriter, read *http.Request) {
	//Define structure for JWKS
	JWKS := struct {
		Keys []map[string]interface{} `json:"keys"`
	}{}
	//Loop through keyPairs
	for _, i := range keyPairs {
		//If the current key is not expired compared to current time
		if i.expiryTime.After(time.Now()) {
			//If pair is current then encode it using base 64
			n := base64.RawURLEncoding.EncodeToString(i.publicKey.N.Bytes())
			e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(i.publicKey.E)).Bytes())

			//Build the current JWT with current key pair
			jwk := map[string]interface{}{
				//Follow conventional format
				"kid": i.kid,
				"alg": "RS256",
				"kty": "RSA",
				"use": "sig",
				"n":   n,
				"e":   e,
			}
			//Add the encoded jwk into the JWKS
			JWKS.Keys = append(JWKS.Keys, jwk)
		}
	}
	//Set the content to JSON
	write.Header().Set("Content-Type", "application/json")
	//If an error is encountered
	if err := json.NewEncoder(write).Encode(JWKS); err != nil {
		//Handle error and state the source of problem
		http.Error(write, "Failure in JWKS", http.StatusInternalServerError)
		//return back from method
		return
	}
}

// Create a method to handle the POST request to the endpoint
// As well as generating JWTS
func authorizationHandler(write http.ResponseWriter, read *http.Request) {
	//Check if the request is a POST request
	if read.Method != http.MethodPost {
		//Let user know it was not allowed
		http.Error(write, "Not allowed", http.StatusMethodNotAllowed)
		//Return back from method
		return
	}
	//Declare variables
	var token string
	var err error
	//Check for expired params
	expired := read.URL.Query().Get("expired") == "true"

	//If length of keypairs container is greater than 0 meaning not empty
	if len(keyPairs) > 0 {
		JWTclaims := jwt.MapClaims{
			"iss": "exampleIssuer",                      //Issuer tag
			"sub": "exampleSubject",                     //Subject tag
			"iat": time.Now().Unix(),                    //Issuing time
			"exp": time.Now().Add(time.Hour * 1).Unix(), // Expiration tag
		}

		//If expired is a parameter set it to past JWT
		if expired {
			JWTclaims["exp"] = time.Now().Add(-time.Hour).Unix()
		} else {
			JWTclaims["exp"] = time.Now().Add(time.Hour * 1).Unix()
		}

		//Create a new JWToken
		JWToken := jwt.NewWithClaims(jwt.SigningMethodRS256, JWTclaims)
		//Specify first key's kid
		JWToken.Header["kid"] = keyPairs[0].kid

		//Turn it into string and sign it
		token, err = JWToken.SignedString(keyPairs[0].privateKey)
		//If error is encountered, log that it was unable to be signed
		if err != nil {
			http.Error(write, "Failed to be signed", http.StatusInternalServerError)
			//Return after logging in error
			return
		}

		//Set the content
		write.Header().Set("Content-Type", "application/json")
		//Format the response
		formattedResponse := fmt.Sprintf(`{"token":"%s"}`, token)
		write.Write([]byte(formattedResponse))
		// write.Write([]byte(`{"token":"` + token + `"}`)) //Deliver signed JWT
	} else {
		http.Error(write, "No keys left for signing", http.StatusInternalServerError)
	}
}

// Create Main function to test all the methods
func main() {
	//Declare new variables
	database, err := sql.Open("sqlite3", dataBaseFile)

	//Check for errors
	if err != nil {
		log.Fatal(err)
	}

	//Create the table
	_, err = database.Exec(createTable)
	//If error is encountered
	if err != nil {
		//Output the error and format string
		log.Fatalf("Error creating the database table: %s", err)
	}

	defer database.Close()
	kid := "uniqueExample"
	expiry := time.Now().Add(24 * time.Hour)
	keyPair := generateKeys(kid, 2048, expiry)

	keyPairs = append(keyPairs, keyPair)

	http.HandleFunc("/.well-known/jwks.json", handlePublicKey)
	http.HandleFunc("/auth", authorizationHandler)

	//Let me know if the server start
	log.Println("Server started at http://localhost:8080")
	//Start the server
	log.Fatal(http.ListenAndServe(":8080", nil))
}
