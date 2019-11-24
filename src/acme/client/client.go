package client

import (
	. "acme/client/challenges"
	. "acme/client/requests"
	"acme/client/signing"
	. "acme/client/type"
	"acme/httpsserver"
	. "acme/utils"
	"time"

	"github.com/sirupsen/logrus"
)

func StartClient(challengeType string, revoke bool, baseUrl string, domains []string) {
	configuredClient := ConfigureCA()
	client := Client{Client: configuredClient, Key: signing.GenerateKeyPair(), BaseUrl: baseUrl, Domain: domains}
	RequestDir(&client)
	RequestNonce(&client)
	RequestAccount(&client)
	RequestCertificate(&client)
	for i := 0; i < len(client.AuthorizationsURL); i++ { //for all authorizations url
		logrus.Info("Authorization " + string(i))
		RequestAuthorization(&client, i)
		ResponseToChallenge(&client, client.Challenges[challengeType].Url, challengeType, client.Domain[i])
		time.Sleep(4 * time.Second)
		for !IsAuthorizationValid(&client, client.Challenges[challengeType].Url, challengeType) {
			time.Sleep(2 * time.Second)
		}
	}

	SendCertificateRequestWithCSR(&client, challengeType)
	time.Sleep(3 * time.Second)
	for !IsCertificateRequestWithCSRValid(&client) {
		time.Sleep(2 * time.Second)
	}
	DownloadCertificate(&client, client.Certificate)
	if revoke {
		SendRevokeCertificateRequest(&client)
	}
	go httpsserver.StartHttpsServer()
}
