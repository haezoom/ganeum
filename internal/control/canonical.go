// Package control implements the 해줌 제어 명령 서명 프로파일 (01 부록 A):
// the RFC 8785 (JCS) canonicalization of the 5-field signing body, ES256/EdDSA
// detached JWS signing (reference signer), and fail-closed verification.
package control

import (
	"encoding/json"
	"fmt"

	"github.com/gowebpki/jcs"
)

// DefaultTTLSec is the value both signer and verifier inject when a command
// omits ttl_sec, so the canonical bytes stay identical on both sides (부록 A.3).
const DefaultTTLSec int64 = 120

// SignBody is the exact set of fields covered by the signature (부록 A.3):
// {id, rtu_id, max_power_w, issued_at, ttl_sec}. All are integers or strings —
// no float normalization is ever required.
type SignBody struct {
	ID        string
	RTUID     string
	MaxPowerW int64
	IssuedAt  int64
	TTLSec    int64
}

// Canonical serializes the 5-field body with RFC 8785 (JCS): keys sorted,
// minimal whitespace, canonical integers. Both signer and verifier MUST produce
// byte-identical output for the signature to match.
func (b SignBody) Canonical() ([]byte, error) {
	// A map marshals with sorted keys and integer numbers render without a
	// decimal point; jcs.Transform then enforces full RFC 8785 canonical form.
	m := map[string]any{
		"id":          b.ID,
		"rtu_id":      b.RTUID,
		"max_power_w": b.MaxPowerW,
		"issued_at":   b.IssuedAt,
		"ttl_sec":     b.TTLSec,
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("서명 대상 직렬화 실패: %w", err)
	}
	canon, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("JCS(RFC 8785) 정규화 실패: %w", err)
	}
	return canon, nil
}

// BodyFromCommand extracts the 5 signing fields from a parsed command message.
// header id/rtu_id live at the top level; max_power_w/issued_at/ttl_sec live in
// payload. ttlInjected reports whether the default TTL was applied (ttl_sec
// omitted). The JSON must be decoded with json.Number for integer fidelity.
func BodyFromCommand(msg map[string]any) (body SignBody, ttlInjected bool, err error) {
	id, ok := msg["id"].(string)
	if !ok || id == "" {
		return SignBody{}, false, fmt.Errorf("id(헤더) 가 없거나 문자열이 아닙니다")
	}
	rtu, ok := msg["rtu_id"].(string)
	if !ok || rtu == "" {
		return SignBody{}, false, fmt.Errorf("rtu_id(헤더) 가 없거나 문자열이 아닙니다")
	}
	payload, ok := msg["payload"].(map[string]any)
	if !ok {
		return SignBody{}, false, fmt.Errorf("payload 객체가 없습니다")
	}

	mp, err := intField(payload, "max_power_w")
	if err != nil {
		return SignBody{}, false, err
	}
	ia, err := intField(payload, "issued_at")
	if err != nil {
		return SignBody{}, false, err
	}

	body = SignBody{ID: id, RTUID: rtu, MaxPowerW: mp, IssuedAt: ia, TTLSec: DefaultTTLSec}
	if raw, exists := payload["ttl_sec"]; exists {
		n, ok := raw.(json.Number)
		if !ok {
			return SignBody{}, false, fmt.Errorf("ttl_sec 가 정수가 아닙니다")
		}
		v, cerr := n.Int64()
		if cerr != nil {
			return SignBody{}, false, fmt.Errorf("ttl_sec 정수 변환 실패: %w", cerr)
		}
		body.TTLSec = v
	} else {
		ttlInjected = true
	}
	return body, ttlInjected, nil
}

func intField(m map[string]any, key string) (int64, error) {
	raw, exists := m[key]
	if !exists {
		return 0, fmt.Errorf("%s 필드가 없습니다", key)
	}
	n, ok := raw.(json.Number)
	if !ok {
		return 0, fmt.Errorf("%s 가 정수가 아닙니다", key)
	}
	v, err := n.Int64()
	if err != nil {
		return 0, fmt.Errorf("%s 정수 변환 실패: %w", key, err)
	}
	return v, nil
}
