package challenges

import (
	. "acme/client/signing"
	. "acme/client/type"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	base = "/builds/COURSE-NETSEC-ACME-AS-2019/aziani-acme-project-netsec-fall-19/src/"
)

func ResponseToChallenge(client *Client, url string, challengeType string, domain string) {
	requestBody := JwsEncodeJSON("", *client.Key, url, client.Kid, client.ReplayNonce)
	resp, err := client.Client.Post(url, "application/jose+json", bytes.NewBuffer(requestBody))
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()
	client.ReplayNonce = resp.Header.Get("Replay-Nonce")
	body, err := ioutil.ReadAll(resp.Body)
	log.Info(string(body))
	_ = json.Unmarshal(body, client.Challenges[challengeType])

	switch challengeType {
	case "http-01":
		createHttp01ChallengeFile(client, client.Challenges[challengeType].Token)
	case "dns-01":
		createDns01ChallengeFile(client, client.Challenges[challengeType].Token, domain)
	}

	//indicate to the server to start validating
	payload := struct{}{}
	requestBody = JwsEncodeJSON(payload, *client.Key, url, client.Kid, client.ReplayNonce)
	resp, err = client.Client.Post(url, "application/jose+json", bytes.NewBuffer(requestBody))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	client.ReplayNonce = resp.Header.Get("Replay-Nonce")

	log.Info("CLIENT - Response to start validating")
	log.Info(string(body))
}

func IsAuthorizationValid(client *Client, url string, challengeType string) bool {
	requestBody := JwsEncodeJSON("", *client.Key, url, client.Kid, client.ReplayNonce)
	resp, err := client.Client.Post(url, "application/jose+json", bytes.NewBuffer(requestBody))

	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()
	client.ReplayNonce = resp.Header.Get("Replay-Nonce")
	body, err := ioutil.ReadAll(resp.Body)
	_ = json.Unmarshal(body, client.Challenges[challengeType])

	log.Info("CLIENT - Polling result")
	log.Info(string(body))
	if client.Challenges[challengeType].Status == "invalid" {
		log.Fatal(err)
	}
	return client.Challenges[challengeType].Status == "valid"
}

func createDns01ChallengeFile(client *Client, token string, domain string) {
	hashedKeyAuthz := sha256.Sum256([]byte(token + "." + JWKThumbprint(client.Key.PublicKey)))
	fileContent := base64.RawURLEncoding.EncodeToString(hashedKeyAuthz[:])
	var fileName string
	if strings.Contains(domain, "*") {
		domain = domain[1:]
		fileName = base + "w_acme-challenge" + domain
	} else {
		fileName = base + "_acme-challenge." + domain
	}
	err := ioutil.WriteFile(fileName, []byte(fileContent), 0777)
	if err != nil {
		log.Fatal("Unable to write file %v", err)
	}
}

func createHttp01ChallengeFile(client *Client, token string) {
	log.Info("Create HTTP01 file")
	fileContent := token + "." + JWKThumbprint(client.Key.PublicKey)
	d1 := []byte(fileContent)
	err := ioutil.WriteFile(base+token, d1, 0777)
	if err != nil {
		log.Fatal("Unable to write file %v", err)
	}

}
