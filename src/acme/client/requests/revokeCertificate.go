package requests

import (
	. "acme/client/signing"
	. "acme/client/type"
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"

	log "github.com/sirupsen/logrus"
)

func SendRevokeCertificateRequest(client *Client) {
	log.Info("CLIENT - SEND REVOKE CERT REQUEST")
	dat, err := ioutil.ReadFile("/builds/COURSE-NETSEC-ACME-AS-2019/aziani-acme-project-netsec-fall-19/src/certificate.pem")
	block, _ := pem.Decode(dat)
	var payload RevokeCertPayload
	cert, _ := x509.ParseCertificate(block.Bytes)
	payload.Certificate = base64.RawURLEncoding.EncodeToString(cert.Raw)
	requestBody := JwsEncodeJSON(payload, *client.Key, client.Dir.RevokeCert, client.Kid, client.ReplayNonce)
	resp, err := client.Client.Post(client.Dir.RevokeCert, "application/jose+json", bytes.NewBuffer(requestBody))

	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()

	client.ReplayNonce = resp.Header.Get("Replay-Nonce")
	body, err := ioutil.ReadAll(resp.Body)
	if string(body) == "" {
		log.Info("Certificate revoked")
	}

}
