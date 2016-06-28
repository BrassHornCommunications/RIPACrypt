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

// GetCrypt takes a cryptID and various config options the retrieves the crypt
func GetCrypt(conf CoreConf, cryptID string) (NewCryptAPIResponse, error) {
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

	/*challengeAPIResponse, challengeErr := GetChallenge(conf.UserID, conf.Fingerprint, conf.UseTor)

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
	}*/

	req, httpReqErr := http.NewRequest("GET", RIPACRYPTURL+"crypt/"+cryptID+"/", nil)
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

func DecryptCrypt(crypt, privatekey string) (string, error) {

	keyBuffer := bytes.NewBufferString(privatekey)
	entityList, err := openpgp.ReadArmoredKeyRing(keyBuffer)
	dec, err := base64.StdEncoding.DecodeString(crypt)
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
