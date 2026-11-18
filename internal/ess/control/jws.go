package control

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/haezoom/ganeum/internal/ess/jcs"
)

var b64 = base64.RawURLEncoding

// ParsedJWS is a detached compact JWS split into its parts (RFC 7515 App. F).
type ParsedJWS struct {
	ProtectedB64 string
	Header       map[string]any
	Sig          []byte
}

// ParseDetached splits "<protected>..<signature>".
func ParseDetached(s string) (*ParsedJWS, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("compact 직렬화 3부가 아닙니다(세그먼트 %d개)", len(parts))
	}
	if parts[1] != "" {
		return nil, fmt.Errorf("detached 형식이 아닙니다(가운데 payload 세그먼트가 비어 있어야 함)")
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("protected header base64url 디코딩 실패(패딩 '=' 금지): %v", err)
	}
	var h map[string]any
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, fmt.Errorf("protected header JSON 파싱 실패: %v", err)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("signature base64url 디코딩 실패: %v", err)
	}
	return &ParsedJWS{ProtectedB64: parts[0], Header: h, Sig: sig}, nil
}

// SigningInput = ASCII(BASE64URL(protected) + "." + BASE64URL(canonical)).
func SigningInput(protectedB64 string, canonical []byte) []byte {
	return []byte(protectedB64 + "." + b64.EncodeToString(canonical))
}

// ProtectedB64 builds BASE64URL(JCS({"alg":..,"kid":..})).
func ProtectedB64(alg, kid string) (string, error) {
	c, err := jcs.Marshal(map[string]any{"alg": alg, "kid": kid})
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(c), nil
}

// rawSign produces the JWS signature bytes (ES256 = raw R‖S 64 bytes).
func rawSign(priv crypto.Signer, alg string, input []byte) ([]byte, error) {
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		if alg != AlgES256 {
			return nil, fmt.Errorf("ECDSA 키로 alg=%s 서명 불가", alg)
		}
		h := sha256.Sum256(input)
		r, s, err := ecdsa.Sign(rand.Reader, k, h[:])
		if err != nil {
			return nil, err
		}
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		return out, nil
	case ed25519.PrivateKey:
		if alg != AlgEdDSA {
			return nil, fmt.Errorf("Ed25519 키로 alg=%s 서명 불가", alg)
		}
		return ed25519.Sign(k, input), nil
	}
	return nil, fmt.Errorf("지원하지 않는 개인키 타입: %T", priv)
}

// rawVerify checks a JWS signature; ES256 expects raw R‖S (not DER).
func rawVerify(pub crypto.PublicKey, alg string, input, sig []byte) (bool, string) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if alg != AlgES256 {
			return false, fmt.Sprintf("키 타입(ECDSA P-256)과 alg=%s 가 맞지 않습니다", alg)
		}
		if len(sig) != 64 {
			hint := ""
			if len(sig) >= 68 && len(sig) <= 72 && sig[0] == 0x30 {
				hint = " — DER(ASN.1) 인코딩으로 보입니다. JWS ES256 은 raw R‖S 64바이트입니다(A.2)"
			}
			return false, fmt.Sprintf("ES256 서명 길이 %d바이트(기대 64)%s", len(sig), hint)
		}
		h := sha256.Sum256(input)
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if ecdsa.Verify(k, h[:], r, s) {
			return true, ""
		}
		return false, "canonical 바이트 또는 서명이 일치하지 않습니다"
	case ed25519.PublicKey:
		if alg != AlgEdDSA {
			return false, fmt.Sprintf("키 타입(Ed25519)과 alg=%s 가 맞지 않습니다", alg)
		}
		if ed25519.Verify(k, input, sig) {
			return true, ""
		}
		return false, "canonical 바이트 또는 서명이 일치하지 않습니다"
	}
	return false, fmt.Sprintf("지원하지 않는 공개키 타입: %T", pub)
}
