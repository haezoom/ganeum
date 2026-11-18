package control

import (
	"crypto"
	"encoding/json"
	"fmt"
)

// SignResult carries the artefacts a 발행측 implementer wants to compare.
type SignResult struct {
	Signature      string         `json:"signature"`
	SigningBody    map[string]any `json:"signing_body"`
	Canonical      string         `json:"canonical"`
	CanonicalSHA   string         `json:"canonical_sha256"`
	ProtectedB64   string         `json:"jws_protected_b64u"`
	SigningInput   string         `json:"jws_signing_input"`
	SignatureB64   string         `json:"jws_signature_b64u"`
	TTLInjected    bool           `json:"ttl_injected"`
	Type2Present   []string       `json:"type2_present"`
	IgnoredPayload []string       `json:"ignored_fields,omitempty"`
}

// SignCommand fills payload.key_id and payload.signature in place (참조 서명기).
// ttl_sec is NOT written into the message when absent: the signer injects 120
// only into the signing body, exactly like the verifier (A.3 유형 ①).
func SignCommand(msg map[string]any, priv crypto.Signer, alg, kid string) (*SignResult, error) {
	if !AlgAllowlist[alg] {
		return nil, fmt.Errorf("허용되지 않은 alg: %s", alg)
	}
	payload, ok := msg["payload"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("payload 객체가 없습니다")
	}
	payload["key_id"] = kid
	sb, err := BuildSigningBody(msg)
	if err != nil {
		return nil, err
	}
	canon, sum, err := sb.Canonical()
	if err != nil {
		return nil, err
	}
	prot, err := ProtectedB64(alg, kid)
	if err != nil {
		return nil, err
	}
	input := SigningInput(prot, canon)
	sig, err := rawSign(priv, alg, input)
	if err != nil {
		return nil, err
	}
	sigB64 := b64.EncodeToString(sig)
	payload["signature"] = prot + ".." + sigB64
	return &SignResult{
		Signature: payload["signature"].(string), SigningBody: sb.Body,
		Canonical: string(canon), CanonicalSHA: sum, ProtectedB64: prot,
		SigningInput: string(input), SignatureB64: sigB64,
		TTLInjected: sb.TTLInjected, Type2Present: sb.Type2Used, IgnoredPayload: sb.Ignored,
	}, nil
}

// Explain returns signing artefacts without a key (canonical 디버깅용).
func Explain(msg map[string]any) (*SignResult, error) {
	sb, err := BuildSigningBody(msg)
	if err != nil {
		return nil, err
	}
	canon, sum, err := sb.Canonical()
	if err != nil {
		return nil, err
	}
	r := &SignResult{SigningBody: sb.Body, Canonical: string(canon), CanonicalSHA: sum,
		TTLInjected: sb.TTLInjected, Type2Present: sb.Type2Used, IgnoredPayload: sb.Ignored}
	if p, ok := msg["payload"].(map[string]any); ok {
		if s, ok := p["signature"].(string); ok {
			r.Signature = s
			if j, err := ParseDetached(s); err == nil {
				r.ProtectedB64 = j.ProtectedB64
				r.SigningInput = string(SigningInput(j.ProtectedB64, canon))
				r.SignatureB64 = b64.EncodeToString(j.Sig)
			}
		}
	}
	return r, nil
}

// MarshalIndent is a helper for stable pretty output.
func MarshalIndent(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}
