package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type JWKSet struct {
	Keys []*JWK `json:"keys"`
}

type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type IDTokenHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type IDTokenBody struct {
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Iss string `json:"iss"`
}

type GenerateResult struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"`
}

type VerifyResult struct {
	Valid       bool
	ErrorDetail string
	Header      *IDTokenHeader
	Body        *IDTokenBody
}

const TokenExpiresIn = 900

func GenerateIDToken(ctx context.Context, keyResourceID, sub, aud, iss string) (*GenerateResult, error) {
	kid, err := KeyResourceIDToKid(keyResourceID)
	if err != nil {
		return nil, err
	}

	header := IDTokenHeader{
		Typ: "JWT",
		Alg: "RS256",
		Kid: kid,
	}
	headerJson, _ := json.Marshal(header)

	body := IDTokenBody{
		Iat: time.Now().Unix(),
		Exp: time.Now().Unix() + TokenExpiresIn,
		Sub: sub,
		Aud: aud,
		Iss: iss,
	}
	bodyJson, _ := json.Marshal(body)

	headerAndBody := fmt.Sprintf("%s.%s", base64.RawURLEncoding.EncodeToString(headerJson), base64.RawURLEncoding.EncodeToString(bodyJson))

	signature, err := Sign(ctx, keyResourceID, []byte(headerAndBody))
	if err != nil {
		return nil, err
	}

	token := fmt.Sprintf("%s.%s", headerAndBody, base64.RawURLEncoding.EncodeToString(signature))
	return &GenerateResult{
		Token:     token,
		ExpiresIn: TokenExpiresIn,
	}, nil
}

func VerifyToken(idToken string, jwkSet JWKSet) (*VerifyResult, error) {
	genInvalidVerifyResult := func(errMsg string) *VerifyResult {
		return &VerifyResult{
			Valid:       false,
			ErrorDetail: errMsg,
			Header:      nil,
			Body:        nil,
		}
	}

	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return genInvalidVerifyResult("not JWT string"), nil
	}

	rawHeader := parts[0]
	rawBody := parts[1]
	rawSignature := parts[2]

	// parse
	headerJson, err := base64.RawURLEncoding.DecodeString(rawHeader)
	if err != nil {
		return genInvalidVerifyResult(err.Error()), nil
	}
	bodyJson, err := base64.RawURLEncoding.DecodeString(rawBody)
	if err != nil {
		return genInvalidVerifyResult(err.Error()), nil
	}
	signature, err := base64.RawURLEncoding.DecodeString(rawSignature)
	if err != nil {
		return genInvalidVerifyResult(err.Error()), nil
	}

	var header IDTokenHeader
	if err = json.Unmarshal(headerJson, &header); err != nil {
		return genInvalidVerifyResult(err.Error()), nil
	}
	var body IDTokenBody
	if err = json.Unmarshal(bodyJson, &body); err != nil {
		return genInvalidVerifyResult(err.Error()), nil
	}

	// Find jwk.
	kid := header.Kid
	var jwk *JWK
	for _, k := range jwkSet.Keys {
		if k.Kid == kid {
			jwk = k
			break
		}
	}
	if jwk == nil {
		return genInvalidVerifyResult("no jwk found"), nil
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return genInvalidVerifyResult(err.Error()), nil
	}
	if len(eBytes) < 8 {
		padding := make([]byte, 8-len(eBytes))
		eBytes = append(padding, eBytes...)
	}
	exponent := binary.BigEndian.Uint64(eBytes)

	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	modulus := big.NewInt(0)
	modulus = modulus.SetBytes(nBytes)

	publicKey := &rsa.PublicKey{
		N: modulus,
		E: int(exponent),
	}

	headerAndBody := fmt.Sprintf("%s.%s", rawHeader, rawBody)
	digest := sha256.Sum256([]byte(headerAndBody))
	digestSlice := digest[:]

	// Verify signature.
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digestSlice, signature); err != nil {
		return genInvalidVerifyResult("invalid signature"), nil
	}

	// Verify body.
	if body.Exp <= time.Now().Unix() {
		return genInvalidVerifyResult("expired token"), nil
	}

	return &VerifyResult{
		Valid:       true,
		ErrorDetail: "",
		Header:      &header,
		Body:        &body,
	}, nil
}

func PublicKeyToJwk(publicKey *kmspb.PublicKey, keyResourceId string) (*JWK, error) {
	if alg := publicKey.GetAlgorithm(); alg != kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256 {
		return nil, errors.New(fmt.Sprintf("Unsupported algorithm: %d", alg))
	}

	pubkeyPem := publicKey.GetPem()
	block, _ := pem.Decode([]byte(pubkeyPem))
	if block == nil {
		return nil, errors.New("invalid public key: " + pubkeyPem)
	}

	keyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, _ := keyInterface.(*rsa.PublicKey)

	kid, err := KeyResourceIDToKid(keyResourceId)
	if err != nil {
		return nil, err
	}

	return &JWK{
		Kid: kid,
		Kty: "RSA",
		Alg: "RS256",
		Use: "sig",
		N:   encodeBase64urlUint(key.N),
		E:   encodeBase64urlUint(key.E),
	}, nil
}

// see. https://tools.ietf.org/html/rfc7518#section-2
func encodeBase64urlUint(data interface{}) string {
	var byteArray []byte

	switch v := data.(type) {
	case int:
		d := data.(int)
		byteArray = make([]byte, 8)
		binary.BigEndian.PutUint64(byteArray, uint64(d))
	case *big.Int:
		d := data.(*big.Int)
		byteArray = d.Bytes()
	default:
		panic(fmt.Sprintf("unexpected type: %T", v))
	}

	i := 0
	for ; i < len(byteArray); i++ {
		if byteArray[i] != 0 {
			break
		}
	}

	return base64.RawURLEncoding.EncodeToString(byteArray[i:])
}
