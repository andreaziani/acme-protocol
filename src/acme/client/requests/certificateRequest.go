package requests

import (
	. "acme/client/signing"
	. "acme/client/type"
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"time"

	log "github.com/sirupsen/logrus"
)

func RequestCertificate(client *Client) {
	log.Info("CLIENT - Send certificate request to the ACME server")
	requestBody := makeCertificateRequestBody(client)
	resp, err := client.Client.Post(client.Dir.NewOrder, "application/jose+json", bytes.NewBuffer(requestBody))
	if err != nil {
		log.Fatal(err)
	}

	client.ReplayNonce = resp.Header.Get("Replay-Nonce")
	//log.Info(client.ReplayNonce)
	var aut struct {
		Authorizations []string `json:"authorizations"`
		Finalize       string   `json:"finalize"`
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	log.Info(string(body))
	_ = json.Unmarshal(body, &aut)

	client.FinalizeURL = aut.Finalize
	client.AuthorizationsURL = aut.Authorizations
}

func makeCertificateRequestBody(client *Client) []byte {
	var identifiers []Identifier

	for i := 0; i < len(client.Domain); i++ {
		identifiers = append(identifiers, Identifier{Type: "dns", Value: client.Domain[i]})
	}
	notBefore := time.Now().Format(time.RFC3339)
	notAfter := time.Now().AddDate(10, 0, 0).Format(time.RFC3339)
	payload := CertificateRequestPayload{Identifiers: identifiers[:], NotBefore: notBefore, NotAfter: notAfter}
	res := JwsEncodeJSON(payload, *client.Key, client.Dir.NewOrder, client.Kid, client.ReplayNonce)
	return res
}

func SendCertificateRequestWithCSR(client *Client, challengeType string) {
	log.Info("CLIENT - Get certificate")

	finaliseCsr := struct {
		Csr string `json:"csr"`
	}{
		Csr: base64.RawURLEncoding.EncodeToString(makeCSR(client)),
	}

	requestBody := JwsEncodeJSON(finaliseCsr, *client.Key, client.FinalizeURL, client.Kid, client.ReplayNonce)
	resp, err := client.Client.Post(client.FinalizeURL, "application/jose+json", bytes.NewBuffer(requestBody))
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()
	client.ReplayNonce = resp.Header.Get("Replay-Nonce")
	client.OrderUrl = resp.Header.Get("Location")
	body, err := ioutil.ReadAll(resp.Body)
	log.Info(string(body))
	_ = json.Unmarshal(body, client.Challenges[challengeType])

}

func makeCSR(client *Client) []byte {
	tpl := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          client.Key.Public(),
		Subject:            pkix.Name{CommonName: client.Domain[0]}, //TODO: modify this shit
		DNSNames:           client.Domain,
	}
	csrDer, _ := x509.CreateCertificateRequest(rand.Reader, tpl, client.Key)
	csr, _ := x509.ParseCertificateRequest(csrDer)
	return csr.Raw
}

func IsCertificateRequestWithCSRValid(client *Client) bool {
	requestBody := JwsEncodeJSON("", *client.Key, client.OrderUrl, client.Kid, client.ReplayNonce)
	resp, err := client.Client.Post(client.OrderUrl, "application/jose+json", bytes.NewBuffer(requestBody))

	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()
	client.ReplayNonce = resp.Header.Get("Replay-Nonce")
	body, err := ioutil.ReadAll(resp.Body)
	type Resp struct {
		Status      string `json:"status"`
		Expires     string `json:"expires"`
		Certificate string `json:"certificate"`
	}
	var bodyResp Resp
	_ = json.Unmarshal(body, &bodyResp)

	if bodyResp.Status == "valid" {
		client.Certificate = bodyResp.Certificate
	}
	log.Info("CLIENT - Polling result")
	log.Info(string(body))
	return bodyResp.Status == "valid" || bodyResp.Status == "invalid"
}
