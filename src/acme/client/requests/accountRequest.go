package requests

import (
	. "acme/client/signing"
	. "acme/client/type"
	"bytes"
	"crypto/ecdsa"
	"io/ioutil"

	log "github.com/sirupsen/logrus"
)

type AccountRequestBody struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func RequestAccount(client *Client) {
	requestBody := makeAccountRequestBody(client.Dir.NewAccount, client.ReplayNonce, client.Key)
	log.Info("CLIENT - Send account request to ACME server")
	log.Info(string(requestBody))

	resp, err := client.Client.Post(client.Dir.NewAccount, "application/jose+json", bytes.NewBuffer(requestBody))

	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	client.Kid = resp.Header.Get("Location")
	client.ReplayNonce = resp.Header.Get("Replay-Nonce")
	if err != nil {
		log.Fatal(err)
	}
	log.Info("CLIENT - Server response: ")
	log.Info(string(body))
}

func makeAccountRequestBody(url string, replayNonce string, key *ecdsa.PrivateKey) []byte {
	var contacts [0]string
	payload := AccountRequestPayload{TermsOfServiceAgreed: true, Contact: contacts[:]}
	res := JwsEncodeJSON(payload, *key, url, "", replayNonce)
	return res
}
