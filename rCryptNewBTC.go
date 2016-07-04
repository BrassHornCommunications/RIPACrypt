package main

import (
	"bytes"
	"encoding/json"
	"github.com/btcsuite/go-socks/socks"
	"io/ioutil"
	"net/http"
)

// ClientBTCRequest describes the JSON payload required for requesting a new bitcoin address
type ClientBTCRequest struct {
	UserID      uint64 `json:"user_id"`
	Challenge   string `json:"challenge"`
	ChallengeID uint64 `json:"challenge_id"`
}

// GetBTC will generate a new bitcoin address for your account (server side)
// this should be done after every transaction to ensure your anonymity
//
// WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
//
// Previous addresses are not retained so if you have sent some BTC ensure your
// account balance is updated before changing the address!
//
// WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
func GetBTC(conf CoreConf) (APIRegisterResponse, error) {
	var client http.Client
	var URL string

	if conf.UseTor == true {
		URL = HSURL
		proxy := &socks.Proxy{TORSOCKS, "", "", true}
		tr := &http.Transport{
			Dial: proxy.Dial,
		}
		client = http.Client{Transport: tr}
	} else {
		URL = RIPACRYPTURL
		client = http.Client{}
	}

	challengeAPIResponse, challengeErr := GetChallenge(conf.UserID, conf.Fingerprint, conf.UseTor)

	decryptedChallenge, decryptErr := DecryptChallenge(challengeAPIResponse.Challenge, conf.PrivateKey)

	if decryptErr != nil {
		return APIRegisterResponse{}, challengeErr
	}

	jsonBuf, jsonErr := json.Marshal(ClientBTCRequest{UserID: conf.UserID,
		Challenge:   decryptedChallenge,
		ChallengeID: challengeAPIResponse.ChallengeID,
	})

	if jsonErr != nil {
		return APIRegisterResponse{}, jsonErr
	}

	req, httpReqErr := http.NewRequest("POST", URL+"newbtc/", bytes.NewBuffer(jsonBuf))

	if httpReqErr != nil {
		return APIRegisterResponse{}, httpReqErr
	}

	req.Header.Set("X-CLIENT-VER", CLIENTVERSION)
	req.Header.Set("Content-Type", "application/json")

	resp, httpErr := client.Do(req)

	if httpErr != nil {
		return APIRegisterResponse{}, httpErr
	}

	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	var apiResponse APIRegisterResponse
	jsonResponseParseErr := json.Unmarshal(body, &apiResponse)

	if jsonResponseParseErr != nil {
		return APIRegisterResponse{}, jsonResponseParseErr
	}
	return apiResponse, nil
}
