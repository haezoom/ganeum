package control

import (
	"crypto"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

// Sign produces a detached JWS over the canonical 5-field body (부록 A.2/A.5).
// The returned string is the compact detached form "protectedHeader..signature"
// with protected header {"alg":<alg>,"kid":keyID}; the payload (canonical bytes)
// is not embedded, matching the detached profile.
func Sign(priv crypto.Signer, alg jose.SignatureAlgorithm, keyID string, body SignBody) (string, error) {
	if keyID == "" {
		return "", fmt.Errorf("key_id(kid) 가 비어 있습니다")
	}
	canon, err := body.Canonical()
	if err != nil {
		return "", err
	}
	opts := (&jose.SignerOptions{}).WithHeader("kid", keyID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: priv}, opts)
	if err != nil {
		return "", fmt.Errorf("서명기 생성 실패: %w", err)
	}
	obj, err := signer.Sign(canon)
	if err != nil {
		return "", fmt.Errorf("서명 실패: %w", err)
	}
	detached, err := obj.DetachedCompactSerialize()
	if err != nil {
		return "", fmt.Errorf("detached 직렬화 실패: %w", err)
	}
	return detached, nil
}

// SignCommand signs a parsed command message in place: it derives the 5-field
// body (injecting the default TTL if omitted), signs it, and writes the
// resulting detached JWS into payload.signature and keyID into payload.key_id.
// It returns the canonical bytes used (for golden-vector capture).
func SignCommand(msg map[string]any, priv crypto.Signer, alg jose.SignatureAlgorithm, keyID string) (canonical []byte, err error) {
	body, _, err := BodyFromCommand(msg)
	if err != nil {
		return nil, err
	}
	canon, err := body.Canonical()
	if err != nil {
		return nil, err
	}
	sig, err := Sign(priv, alg, keyID, body)
	if err != nil {
		return nil, err
	}
	payload, ok := msg["payload"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("payload 객체가 없습니다")
	}
	payload["key_id"] = keyID
	payload["signature"] = sig
	return canon, nil
}
