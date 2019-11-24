package requests

import (
	. "acme/client/type"
	"encoding/json"
	"io/ioutil"

	log "github.com/sirupsen/logrus"
)

func RequestDir(client *Client) {
	log.Info("CLIENT - Dir request")
	resp, err := client.Client.Get(client.BaseUrl)
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	var dir Directory
	_ = json.Unmarshal(body, &dir)
	client.Dir = dir
	log.Info(client.Dir)
}
