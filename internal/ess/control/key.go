package control

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
)

// Alg names used in the protected header (A.2).
const (
	AlgES256 = "ES256"
	AlgEdDSA = "EdDSA"
)

// AlgAllowlist is the fixed allowlist (A.4 1단계).
var AlgAllowlist = map[string]bool{AlgES256: true, AlgEdDSA: true}

// ParsePublicKeyPEM accepts SPKI "PUBLIC KEY" PEM (P-256 or Ed25519).
func ParsePublicKeyPEM(b []byte) (crypto.PublicKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("PEM 블록을 찾지 못했습니다")
	}
	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("공개키 파싱 실패: %w", err)
	}
	return checkPub(pub)
}

func checkPub(pub any) (crypto.PublicKey, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("P-256 이외 곡선은 허용되지 않습니다")
		}
		return k, nil
	case ed25519.PublicKey:
		return k, nil
	default:
		return nil, fmt.Errorf("지원하지 않는 공개키 타입: %T", pub)
	}
}

// ParsePrivateKeyPEM accepts SEC1 "EC PRIVATE KEY" or PKCS#8 "PRIVATE KEY".
func ParsePrivateKeyPEM(b []byte) (crypto.Signer, string, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, "", fmt.Errorf("PEM 블록을 찾지 못했습니다")
	}
	if blk.Type == "EC PRIVATE KEY" {
		k, err := x509.ParseECPrivateKey(blk.Bytes)
		if err != nil {
			return nil, "", err
		}
		if k.Curve != elliptic.P256() {
			return nil, "", fmt.Errorf("P-256 이외 곡선은 허용되지 않습니다")
		}
		return k, AlgES256, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("개인키 파싱 실패: %w", err)
	}
	switch kk := k.(type) {
	case *ecdsa.PrivateKey:
		if kk.Curve != elliptic.P256() {
			return nil, "", fmt.Errorf("P-256 이외 곡선은 허용되지 않습니다")
		}
		return kk, AlgES256, nil
	case ed25519.PrivateKey:
		return kk, AlgEdDSA, nil
	}
	return nil, "", fmt.Errorf("지원하지 않는 개인키 타입: %T", k)
}

// Keyring maps kid → public key (fail-closed lookup, A.4 2단계).
type Keyring map[string]crypto.PublicKey

// LoadKeystore reads the golden-vector keystore.json format:
// {"keys":[{"kid":..., "alg":..., "jwk":{kty,crv,x,y}}]}
func LoadKeystore(path string) (Keyring, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseKeystore(b)
}

// ParseKeystore parses keystore JSON bytes.
func ParseKeystore(b []byte) (Keyring, error) {
	var ks struct {
		Keys []struct {
			Kid string            `json:"kid"`
			JWK map[string]string `json:"jwk"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(b, &ks); err != nil {
		return nil, fmt.Errorf("keystore 파싱 실패: %w", err)
	}
	ring := Keyring{}
	for _, k := range ks.Keys {
		pub, err := PubFromJWK(k.JWK)
		if err != nil {
			return nil, fmt.Errorf("kid=%s: %w", k.Kid, err)
		}
		ring[k.Kid] = pub
	}
	return ring, nil
}

// PubFromJWK converts an EC P-256 or OKP Ed25519 JWK into a public key.
func PubFromJWK(j map[string]string) (crypto.PublicKey, error) {
	dec := base64.RawURLEncoding.DecodeString
	switch j["kty"] {
	case "EC":
		if j["crv"] != "P-256" {
			return nil, fmt.Errorf("crv=%s 미지원", j["crv"])
		}
		x, err := dec(j["x"])
		if err != nil {
			return nil, err
		}
		y, err := dec(j["y"])
		if err != nil {
			return nil, err
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, fmt.Errorf("곡선 위의 점이 아닙니다")
		}
		return pub, nil
	case "OKP":
		if j["crv"] != "Ed25519" {
			return nil, fmt.Errorf("crv=%s 미지원", j["crv"])
		}
		x, err := dec(j["x"])
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("Ed25519 x 값이 올바르지 않습니다")
		}
		return ed25519.PublicKey(x), nil
	}
	return nil, fmt.Errorf("kty=%s 미지원", j["kty"])
}

// JWKFromPub renders a public key as a JWK map.
func JWKFromPub(pub crypto.PublicKey) (map[string]string, string, error) {
	enc := base64.RawURLEncoding.EncodeToString
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		x := make([]byte, 32)
		y := make([]byte, 32)
		k.X.FillBytes(x)
		k.Y.FillBytes(y)
		return map[string]string{"kty": "EC", "crv": "P-256", "x": enc(x), "y": enc(y)}, AlgES256, nil
	case ed25519.PublicKey:
		return map[string]string{"kty": "OKP", "crv": "Ed25519", "x": enc(k)}, AlgEdDSA, nil
	}
	return nil, "", fmt.Errorf("지원하지 않는 공개키 타입: %T", pub)
}

// GenerateKey creates a fresh key pair as PEM (PKCS#8 private, SPKI public).
// es256 private keys are written as SEC1 for parity with the golden vectors.
func GenerateKey(alg string) (privPEM, pubPEM []byte, err error) {
	var priv crypto.Signer
	var privDER []byte
	var privType string
	switch alg {
	case "", "es256", "ES256":
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return nil, nil, e
		}
		priv = k
		privDER, err = x509.MarshalECPrivateKey(k)
		privType = "EC PRIVATE KEY"
	case "ed25519", "EdDSA", "eddsa":
		_, k, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return nil, nil, e
		}
		priv = k
		privDER, err = x509.MarshalPKCS8PrivateKey(k)
		privType = "PRIVATE KEY"
	default:
		return nil, nil, fmt.Errorf("지원하지 않는 알고리즘: %s (es256|ed25519)", alg)
	}
	if err != nil {
		return nil, nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: privType, Bytes: privDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), nil
}
