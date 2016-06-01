package main

import (
	"bytes"
	"encoding/json"
	"github.com/btcsuite/go-socks/socks"
	"golang.org/x/crypto/openpgp"
	"io/ioutil"
	"math/rand"
	"net/http"
)

//ClientRegisterRequest describes the JSON payload used to register a new
// account
type ClientRegisterRequest struct {
	PublicKey string `json:"public_key"`
}

// APIRegisterResponse describes the JSON reply from the API detailing the new
// user account e.g. their userid and Bitcoin address
type APIRegisterResponse struct {
	StatusCode int    `json:"status_code"`
	Success    bool   `json:"success"`
	Message    string `json:"status_message"`
	Version    int64  `json:"version"`

	BTCAddr string `json:"btc_addr"`
	UserID  uint64 `json:"user_id"`
}

// RIPACryptRegister takes a PublicKey string and submits it to the RIPACrypt
// API to register a new account. Each account receives a unique bitcoin
// address that can be used to expand storage space, for donations or
// notifcation credits (future plans).
func RIPACryptRegister(PublicKey string, useTor bool) (APIRegisterResponse, error) {

	var client http.Client

	if useTor == true {
		proxy := &socks.Proxy{TORSOCKS, "", "", true}
		tr := &http.Transport{
			Dial: proxy.Dial,
		}
		client = http.Client{Transport: tr}
	} else {
		client = http.Client{}
	}

	//request := ClientRequest{PublicKey: PublicKey}
	//jsonBuf, jsonErr := json.Marshal(request)
	jsonBuf, jsonErr := json.Marshal(ClientRegisterRequest{PublicKey: PublicKey})

	//fmt.Println(string(jsonBuf))

	if jsonErr != nil {
		return APIRegisterResponse{}, jsonErr
	}

	req, httpReqErr := http.NewRequest("POST", RIPACRYPTURL+"register/", bytes.NewBuffer(jsonBuf))

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
	} else {
		return apiResponse, nil
	}
}

// VerifyGPGPublicKey simply takes an armoured  GPG key and attemts to parse it
// if successful we return the partial fingerprint
func VerifyGPGPublicKey(PublicKey string) (string, error) {

	keyBuffer := bytes.NewBufferString(PublicKey)
	entityList, armorErr := openpgp.ReadArmoredKeyRing(keyBuffer)

	if armorErr != nil {
		return "", armorErr
	} else {
		return entityList[0].PrimaryKey.KeyIdString(), nil
	}
}

// RandStringRunes is used to generate pseudo random email addresses for the
// GPG public / private keys.
func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
