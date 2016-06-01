package main

import (
	"bytes"
	"encoding/json"
	"github.com/btcsuite/go-socks/socks"
	"io/ioutil"
	"net/http"
)

// ClientCheckinRequest describes the JSON payload sent to the server to
// "check in" with a crypt
type ClientCheckinRequest struct {
	UserID      uint64 `json:"user_id"`
	Challenge   string `json:"challenge"`
	ChallengeID uint64 `json:"challenge_id"`
}

// Checkin takes a cryptID and various config options, requests a challenge nonce
// decrypts it then sends a HTTP POST to the /1/crypt/CRYPTID/ endpoint to reset
// the deadline for a crypt
func Checkin(conf CoreConf, cryptID string) (NewCryptAPIResponse, error) {
	var client http.Client

	if conf.UseTor == true {
		proxy := &socks.Proxy{TORSOCKS, "", "", true}
		tr := &http.Transport{
			Dial: proxy.Dial,
		}
		client = http.Client{Transport: tr}
	} else {
		client = http.Client{}
	}

	challengeAPIResponse, challengeErr := GetChallenge(conf.UserID, conf.Fingerprint, conf.UseTor)

	decryptedChallenge, decryptErr := DecryptChallenge(challengeAPIResponse.Challenge, conf.PrivateKey)

	if decryptErr != nil {
		return NewCryptAPIResponse{}, challengeErr
	}

	jsonBuf, jsonErr := json.Marshal(ClientCheckinRequest{UserID: conf.UserID,
		Challenge:   decryptedChallenge,
		ChallengeID: challengeAPIResponse.ChallengeID,
	})

	if jsonErr != nil {
		return NewCryptAPIResponse{}, jsonErr
	}

	req, httpReqErr := http.NewRequest("POST", RIPACRYPTURL+"crypt/"+cryptID+"/", bytes.NewBuffer(jsonBuf))
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
