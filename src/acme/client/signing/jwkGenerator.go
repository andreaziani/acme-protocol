package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
)

func JwsEncodeJSON(payload interface{}, key ecdsa.PrivateKey, requestURL, keyID, nonce string) []byte {
	jwk := jwkEncode(key.PublicKey)
	alg, sha := "ES256", crypto.SHA256

	var phead string
	if keyID != "" {
		phead = fmt.Sprintf(`{"alg":%q,"kid":%q,"nonce":%q,"url":%q}`, alg, keyID, nonce, requestURL)
	} else {
		phead = fmt.Sprintf(`{"alg":%q,"jwk":%s,"nonce":%q,"url":%q}`, alg, jwk, nonce, requestURL)
	}
	phead = base64.RawURLEncoding.EncodeToString([]byte(phead))

	var p string
	pString, ok := payload.(string)
	if !ok || pString != "" {
		cs, err := json.Marshal(payload)
		if err != nil {
			log.Fatal(err)
		}
		p = base64.RawURLEncoding.EncodeToString(cs)
	}

	hash := sha.New()
	hash.Write([]byte(phead + "." + p))
	sig := jwsSign(key, sha, hash.Sum(nil))

	enc := struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}{
		Protected: phead,
		Payload:   p,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}
	jsonData, err := json.Marshal(&enc)
	if err != nil {
		log.Fatal(err)
	}
	return jsonData
}

func jwkEncode(pubKey ecdsa.PublicKey) string {
	p := pubKey.Curve.Params()
	n := p.BitSize / 8
	if p.BitSize % 8 != 0 {
		n++
	}
	x := pubKey.X.Bytes()
	if n > len(x) {
		x = append(make([]byte, n-len(x)), x...)
	}
	y := pubKey.Y.Bytes()
	if n > len(y) {
		y = append(make([]byte, n-len(y)), y...)
	}

	return fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`,
		p.Name,
		base64.RawURLEncoding.EncodeToString(x),
		base64.RawURLEncoding.EncodeToString(y),
	)
}

func jwsSign(key ecdsa.PrivateKey, hash crypto.Hash, d []byte) []byte {
	r, s, err := ecdsa.Sign(rand.Reader, &key, d)
	if err != nil {
		log.Fatal(err)
	}
	rb, sb := r.Bytes(), s.Bytes()
	size := key.Params().BitSize / 8
	if size%8 > 0 {
		size++
	}
	sig := make([]byte, size*2)
	copy(sig[size-len(rb):], rb)
	copy(sig[size*2-len(sb):], sb)
	return sig
}

// JWKThumbprint creates a JWK thumbprint out of pub
func JWKThumbprint(pub ecdsa.PublicKey) string {
	jwk := jwkEncode(pub)
	b := sha256.Sum256([]byte(jwk))
	return base64.RawURLEncoding.EncodeToString(b[:])
}
