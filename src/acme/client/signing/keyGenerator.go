package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"

	log "github.com/sirupsen/logrus"
)

func GenerateKeyPair() *ecdsa.PrivateKey {
	log.Info("Generate key pair")
	clientPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	pemPrivateFile, err := os.Create("/builds/COURSE-NETSEC-ACME-AS-2019/aziani-acme-project-netsec-fall-19/src/private_key.pem")
	if err != nil {
		log.Fatal(err)
	}

	bytes, _ := x509.MarshalECPrivateKey(clientPrivateKey)
	var pemPrivateBlock = &pem.Block{
		Type:  "ECDSA PRIVATE KEY",
		Bytes: bytes,
	}

	err = pem.Encode(pemPrivateFile, pemPrivateBlock)
	if err != nil {
		log.Fatal(err)
	}
	_ = pemPrivateFile.Close()
	return clientPrivateKey
}
