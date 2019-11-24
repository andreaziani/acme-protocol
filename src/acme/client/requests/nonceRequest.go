package requests

import (
	. "acme/client/type"

	log "github.com/sirupsen/logrus"
)

func RequestNonce(client *Client) {
	log.Info("CLIENT - Nonce request")
	res, err := client.Client.Head(client.Dir.NewNonce)
	if err != nil {
		log.Fatal(err)
	}

	nonce := res.Header.Get("Replay-Nonce")
	if nonce == "" {
		log.Fatal("Empty nonce")
	}
	if err != nil {
		log.Fatal(err)
	}
	client.ReplayNonce = nonce
}
