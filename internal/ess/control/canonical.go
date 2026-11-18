// Package control implements the ESS 제어 명령 서명 프로파일 (01 부록 A):
// the mode-dependent signing-body rule (A.3), RFC 8785 canonicalization,
// detached compact JWS signing/verification (A.2) and the A.4 verification
// procedure including expiry/skew (step 6) and id de-duplication (step 7).
package control

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/haezoom/ganeum/internal/ess/jcs"
)

// DefaultTTLSec is injected by both signer and verifier when ttl_sec is
// omitted (A.3 유형 ①).
const DefaultTTLSec = 120

// Modes.
const (
	ModeImmediate = "IMMEDIATE"
	ModeSchedule  = "SCHEDULE"
)

// always lists the mode's always-included fields (A.3 "항상 포함").
var always = map[string][]string{
	ModeImmediate: {"id", "rtu_id", "mode", "issued_at", "direction", "power_w"},
	ModeSchedule:  {"id", "rtu_id", "mode", "issued_at", "tz_offset_min", "slots"},
}

// type2 lists the mode's "included only when present" fields (A.3 유형 ②).
var type2 = map[string][]string{
	ModeImmediate: {"soc_min_pct", "soc_max_pct", "hold_sec", "override_polarity_gap"},
	ModeSchedule:  {"soc_min_pct", "soc_max_pct", "date"},
}

var headerFields = map[string]bool{"id": true, "rtu_id": true}

// SigningBody is the outcome of the A.3 key-set rule.
type SigningBody struct {
	Mode        string         `json:"mode"`
	Body        map[string]any `json:"signing_body"`
	TTLInjected bool           `json:"ttl_injected"`
	Type2Used   []string       `json:"type2_present"`
	Ignored     []string       `json:"ignored_fields,omitempty"` // payload keys outside the signing set
}

// BuildSigningBody applies A.3 steps 1~5 to a decoded command message.
// The message must be decoded with json.Number (UseNumber) to keep integers exact.
func BuildSigningBody(msg map[string]any) (*SigningBody, error) {
	payload, ok := msg["payload"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("payload 객체가 없습니다")
	}
	mode, _ := payload["mode"].(string)
	fields, ok := always[mode]
	if !ok {
		return nil, fmt.Errorf("알 수 없는 mode: %q (IMMEDIATE|SCHEDULE)", mode)
	}
	sb := &SigningBody{Mode: mode, Body: map[string]any{}}

	// 1. 그 모드의 "항상 포함" 필드
	for _, k := range fields {
		var v any
		var present bool
		if headerFields[k] {
			v, present = msg[k]
			if !present {
				return nil, fmt.Errorf("헤더 필수 서명 필드 누락: %s", k)
			}
		} else {
			v, present = payload[k]
			if !present {
				return nil, fmt.Errorf("payload 필수 서명 필드 누락: %s (mode=%s)", k, mode)
			}
		}
		sb.Body[k] = v
	}
	// 2. ttl_sec — 없으면 120 주입(유형 ①)
	if v, ok := payload["ttl_sec"]; ok {
		sb.Body["ttl_sec"] = v
	} else {
		sb.Body["ttl_sec"] = DefaultTTLSec
		sb.TTLInjected = true
	}
	// 3. 유형 ② — 키가 존재할 때만(값이 false·0 이어도 포함)
	for _, k := range type2[mode] {
		if v, ok := payload[k]; ok {
			sb.Body[k] = v
			sb.Type2Used = append(sb.Type2Used, k)
		}
	}
	// 5. 다른 모드 필드는 화이트리스트 구조상 들어가지 않는다. 진단용으로 기록만 한다.
	inSet := map[string]bool{"ttl_sec": true, "key_id": true, "signature": true}
	for _, k := range fields {
		inSet[k] = true
	}
	for _, k := range type2[mode] {
		inSet[k] = true
	}
	for k := range payload {
		if !inSet[k] {
			sb.Ignored = append(sb.Ignored, k)
		}
	}
	return sb, nil
}

// Canonical returns RFC 8785 bytes and their SHA-256 hex.
func (s *SigningBody) Canonical() ([]byte, string, error) {
	c, err := jcs.Marshal(s.Body)
	if err != nil {
		return nil, "", err
	}
	h := sha256.Sum256(c)
	return c, hex.EncodeToString(h[:]), nil
}
