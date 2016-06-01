package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/btcsuite/go-socks/socks"
	"golang.org/x/crypto/openpgp"
	"io/ioutil"
	"net/http"
)

type ClientChallengeRequest struct {
	UserID      uint64 `json:"user_id"`
	Fingerprint string `json:"fingerprint"`
}
type ChallengeAPIResponse struct {
	Challenge   string `json:"challenge"`
	ChallengeID uint64 `json:"challenge_id"`
	UserID      uint64 `json:"user_id"`
	StatusCode  int    `json:"status_code"`
	Success     bool   `json:"success"`
	Message     string `json:"status_message"`
	Version     int64  `json:"version"`
}

// GetChallenge will fetch a challenge nonce from the server
func GetChallenge(UserID uint64, Fingerprint string, UseTor bool) (ChallengeAPIResponse, error) {

	var client http.Client

	if UseTor == true {
		proxy := &socks.Proxy{TORSOCKS, "", "", true}
		tr := &http.Transport{
			Dial: proxy.Dial,
		}
		client = http.Client{Transport: tr}
	} else {
		client = http.Client{}
	}

	jsonBuf, jsonErr := json.Marshal(ClientChallengeRequest{UserID: UserID, Fingerprint: Fingerprint})

	if jsonErr != nil {
		return ChallengeAPIResponse{}, jsonErr
	}
	req, httpReqErr := http.NewRequest("POST", RIPACRYPTURL+"challenge/", bytes.NewBuffer(jsonBuf))
	if httpReqErr != nil {
		return ChallengeAPIResponse{}, httpReqErr
	}
	req.Header.Set("X-CLIENT-VER", CLIENTVERSION)
	req.Header.Set("Content-Type", "application/json")

	resp, httpErr := client.Do(req)
	if httpErr != nil {
		return ChallengeAPIResponse{}, httpErr
	}

	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	var apiResponse ChallengeAPIResponse
	jsonResponseParseErr := json.Unmarshal(body, &apiResponse)
	if jsonResponseParseErr != nil {
		return ChallengeAPIResponse{}, jsonResponseParseErr
	} else {
		return apiResponse, nil
	}

	return ChallengeAPIResponse{}, nil
}

// DecryptChallenge will take an encrypted challenge nonce and a private key
// then decrypt the challenge and return the plaintext
func DecryptChallenge(challenge, privatekey string) (string, error) {

	keyBuffer := bytes.NewBufferString(privatekey)
	entityList, err := openpgp.ReadArmoredKeyRing(keyBuffer)
	dec, err := base64.StdEncoding.DecodeString(challenge)
	md, err := openpgp.ReadMessage(bytes.NewBuffer(dec), entityList, nil, nil)
	if err != nil {
		return "", err
	}
	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}
	decStr := string(bytes)

	return decStr, nil
}
