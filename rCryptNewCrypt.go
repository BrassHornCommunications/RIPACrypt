package main

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"github.com/btcsuite/go-socks/socks"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
	"io/ioutil"
	"net/http"
)

// NewCryptAPIResponse describes the JSON that the API will return to us
type NewCryptAPIResponse struct {
	StatusCode int    `json:"status_code"`
	Success    bool   `json:"success"`
	Message    string `json:"status_message"`
	Version    int64  `json:"version"`

	CryptPayload Crypt `json:"crypt"`
}

// Crypt describes the structure of a crypt and the JSON layout embedded within
// the API response NewCryptAPIResponse
type Crypt struct {
	UserID          uint64 `json:"-"`
	CryptID         string `json:"crypt_id"`
	CipherText      string `json:"ciphertext"`
	CreateTimeStamp int64  `json:"crypt_timestamp"`
	Description     string `json:"crypt_description"`
	IsDestroyed     bool   `json:"is_crypt_destroyed"`
	LastCheckIn     int64  `json:"last_checkin"`
	CheckInDuration int64  `json:"check_in_duration"`
	MissCount       int64  `json:"miss_count"`
}

// ClientCryptRequest describes the JSON payload that needs to tbe send to the
// API to generate a new Crypt
type ClientCryptRequest struct {
	UserID          uint64 `json:"user_id"`
	CryptContent    string `json:"crypt_content"`
	Challenge       string `json:"challenge"`
	ChallengeID     uint64 `json:"challenge_id"`
	Description     string `json:"description"`
	CheckInDuration int64  `json:"checkin_duration"`
	MissCount       int64  `json:"miss_count"`
}

// NewCrypt takes a series of arguments (most notably the secret to store) and
// then encrypts the secret (if not already encrypted), substitutes sensible
// defaults for missing values and then sends an API request to get a challenge
// nonce, decrypts it and then submits the entire payload to the /1/crypt/new/
// endpoint to create a new crypt
func NewCrypt(dataToStore string, Description string, CheckInDuration int64, MissCount int64, IsEncrypted bool, conf CoreConf) (NewCryptAPIResponse, error) {

	var client http.Client
	var encryptedData string

	if conf.UseTor == true {
		proxy := &socks.Proxy{TORSOCKS, "", "", true}
		tr := &http.Transport{
			Dial: proxy.Dial,
		}
		client = http.Client{Transport: tr}
	} else {
		client = http.Client{}
	}

	if IsEncrypted == false {
		var encryptErr error
		encryptedData, encryptErr = EncryptData(dataToStore, conf.PublicKey)

		if encryptErr != nil {
			return NewCryptAPIResponse{}, encryptErr
		}
	} else {
		encryptedData = dataToStore
	}

	challengeAPIResponse, challengeErr := GetChallenge(conf.UserID, conf.Fingerprint, conf.UseTor)

	decryptedChallenge, decryptErr := DecryptChallenge(challengeAPIResponse.Challenge, conf.PrivateKey)

	if decryptErr != nil {
		return NewCryptAPIResponse{}, challengeErr
	}

	jsonBuf, jsonErr := json.Marshal(ClientCryptRequest{UserID: conf.UserID,
		Description:     Description,
		CryptContent:    encryptedData,
		Challenge:       decryptedChallenge,
		ChallengeID:     challengeAPIResponse.ChallengeID,
		CheckInDuration: CheckInDuration,
		MissCount:       MissCount,
	})

	if jsonErr != nil {
		return NewCryptAPIResponse{}, jsonErr
	}

	req, httpReqErr := http.NewRequest("POST", RIPACRYPTURL+"crypt/new/", bytes.NewBuffer(jsonBuf))

	if httpReqErr != nil {
		return NewCryptAPIResponse{}, httpReqErr
	}

	req.Header.Set("X-CLIENT-VER", CLIENTVERSION)
	req.Header.Set("Content-Type", "application/json")

	resp, httpErr := client.Do(req)
	if httpErr != nil {
		return NewCryptAPIResponse{}, httpErr
	}

	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	var apiResponse NewCryptAPIResponse
	jsonResponseParseErr := json.Unmarshal(body, &apiResponse)

	if jsonResponseParseErr != nil {
		return NewCryptAPIResponse{}, jsonResponseParseErr
	}
	return apiResponse, nil
}

// EncryptData simply takes a plaintext string and a public key armoured
// string and returns an armoured, encrypted version of the plaintext.
// This is the 'end-to-end' nature of RIPACrypt - our servers never see a
// users private key so can never decrypt their data.
func EncryptData(clearText, publicKey string) (string, error) {
	keyBuffer := bytes.NewBufferString(publicKey)
	entityList, err := openpgp.ReadArmoredKeyRing(keyBuffer)
	if err == nil {
		buf := new(bytes.Buffer)
		packetConf := packet.Config{DefaultHash: crypto.SHA256}
		w, err := openpgp.Encrypt(buf, entityList, nil, nil, &packetConf)
		if err != nil {
			return "", err
		}
		_, err = w.Write([]byte(clearText))
		if err != nil {
			return "", err
		}
		err = w.Close()
		if err != nil {
			return "", err
		}

		// Encode to base64
		bytes, err := ioutil.ReadAll(buf)
		if err != nil {
			return "", err
		}
		encStr := base64.StdEncoding.EncodeToString(bytes)

		return encStr, nil
	}
	return "", err

}
