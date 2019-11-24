package requests

import (
	. "acme/client/signing"
	. "acme/client/type"
	"bytes"
	"io/ioutil"

	log "github.com/sirupsen/logrus"
)

func DownloadCertificate(client *Client, url string) {
	log.Info("CLIENT - DOWNLOADING CERTIFICATE")
	requestBody := JwsEncodeJSON("", *client.Key, url, client.Kid, client.ReplayNonce)
	resp, err := client.Client.Post(url, "application/jose+json", bytes.NewBuffer(requestBody))

	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()
	client.ReplayNonce = resp.Header.Get("Replay-Nonce")
	body, err := ioutil.ReadAll(resp.Body)
	//log.Info(string(body))

	err = ioutil.WriteFile("/builds/COURSE-NETSEC-ACME-AS-2019/aziani-acme-project-netsec-fall-19/src/certificate.pem", body, 0644)
	if err != nil {
		log.Fatal("Unable to write file %v", err)
	}

}
