package _type

import (
	"crypto/ecdsa"
	"net/http"
)

type Client struct {
	Client            *http.Client
	ReplayNonce       string
	Key               *ecdsa.PrivateKey
	BaseUrl           string
	Dir               Directory
	Kid               string
	AuthorizationsURL []string
	Challenges        map[string]*Challenge
	FinalizeURL       string
	Domain            []string
	OrderUrl          string
	Certificate       string
}

type AccountRequestPayload struct {
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
	Contact              []string `json:"contact"`
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type CertificateRequestPayload struct {
	Identifiers []Identifier `json:"identifiers"`
	NotBefore   string       `json:"notBefore"`
	NotAfter    string       `json:"notAfter"`
}

type Directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
}

type Challenge struct {
	Type      string `json:"type"`
	Url       string `json:"url"`
	Token     string `json:"token"`
	Status    string `json:"status"`
	Validated string `json:"validated"`
}

type RevokeCertPayload struct {
	Certificate string `json:"certificate"`
}
