package requests

import (
	. "acme/client/signing"
	. "acme/client/type"
	"bytes"
	"encoding/json"
	"io/ioutil"

	log "github.com/sirupsen/logrus"
)

func RequestAuthorization(client *Client, i int) {
	log.Info("CLIENT - Send authorization request to the ACME server")
	requestBody := JwsEncodeJSON("", *client.Key, client.AuthorizationsURL[i], client.Kid, client.ReplayNonce)
	resp, err := client.Client.Post(client.AuthorizationsURL[i], "application/jose+json", bytes.NewBuffer(requestBody))
	if err != nil {
		log.Fatal(err)
	}
	client.ReplayNonce = resp.Header.Get("Replay-Nonce")
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	var challenges struct {
		Challenges []Challenge `json:"challenges"`
	}

	_ = json.Unmarshal(body, &challenges)

	client.Challenges = make(map[string]*Challenge)
	for i := 0; i < len(challenges.Challenges); i++ {
		if challenges.Challenges[i].Type == "dns-01" {
			client.Challenges["dns-01"] = &challenges.Challenges[i]
		}
		if challenges.Challenges[i].Type == "http-01" {
			client.Challenges["http-01"] = &challenges.Challenges[i]
		}
	}

	log.Info("CLIENT - Challenges: ")
	log.Info(string(body))
}
