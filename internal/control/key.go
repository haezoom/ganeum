package control

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

// KeyAlg names the supported key/signature algorithms.
type KeyAlg string

const (
	AlgES256   KeyAlg = "es256"   // ECDSA P-256 (부록 A 기본)
	AlgEd25519 KeyAlg = "ed25519" // Ed25519 (부록 A 옵션)
)

// JOSEAlg maps a KeyAlg to its JWS `alg` value.
func (a KeyAlg) JOSEAlg() (jose.SignatureAlgorithm, error) {
	switch a {
	case AlgES256:
		return jose.ES256, nil
	case AlgEd25519:
		return jose.EdDSA, nil
	default:
		return "", fmt.Errorf("지원하지 않는 알고리즘: %q (es256|ed25519)", a)
	}
}

// GenerateKey creates a fresh keypair for alg and returns PKCS#8 (private) and
// PKIX (public) PEM blocks.
func GenerateKey(alg KeyAlg) (privPEM, pubPEM []byte, err error) {
	var priv crypto.Signer
	var pub crypto.PublicKey
	switch alg {
	case AlgES256:
		k, gerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if gerr != nil {
			return nil, nil, fmt.Errorf("ES256 키 생성 실패: %w", gerr)
		}
		priv, pub = k, &k.PublicKey
	case AlgEd25519:
		pubk, privk, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			return nil, nil, fmt.Errorf("Ed25519 키 생성 실패: %w", gerr)
		}
		priv, pub = privk, pubk
	default:
		return nil, nil, fmt.Errorf("지원하지 않는 알고리즘: %q", alg)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("개인키 인코딩 실패: %w", err)
	}
	privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	pder, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("공개키 인코딩 실패: %w", err)
	}
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pder})
	return privPEM, pubPEM, nil
}

// ParsePrivateKeyPEM decodes a PKCS#8 PEM private key and reports the matching
// JWS algorithm (ES256 for P-256, EdDSA for Ed25519).
func ParsePrivateKeyPEM(data []byte) (crypto.Signer, jose.SignatureAlgorithm, error) {
	blk, _ := pem.Decode(data)
	if blk == nil {
		return nil, "", fmt.Errorf("PEM 블록을 찾을 수 없습니다")
	}
	key, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("PKCS#8 개인키 파싱 실패: %w", err)
	}
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, "", fmt.Errorf("ECDSA 곡선이 P-256 이 아닙니다 (ES256 전용)")
		}
		return k, jose.ES256, nil
	case ed25519.PrivateKey:
		return k, jose.EdDSA, nil
	default:
		return nil, "", fmt.Errorf("지원하지 않는 개인키 타입 %T (P-256 또는 Ed25519)", key)
	}
}

// ParsePublicKeyPEM decodes a PKIX PEM public key (P-256 or Ed25519).
func ParsePublicKeyPEM(data []byte) (crypto.PublicKey, error) {
	blk, _ := pem.Decode(data)
	if blk == nil {
		return nil, fmt.Errorf("PEM 블록을 찾을 수 없습니다")
	}
	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("PKIX 공개키 파싱 실패: %w", err)
	}
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("ECDSA 곡선이 P-256 이 아닙니다")
		}
		return k, nil
	case ed25519.PublicKey:
		return k, nil
	default:
		return nil, fmt.Errorf("지원하지 않는 공개키 타입 %T", pub)
	}
}
