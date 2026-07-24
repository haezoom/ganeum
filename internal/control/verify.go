package control

import (
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	jose "github.com/go-jose/go-jose/v4"
)

// allowedAlgs is the fixed allowlist for the `alg` protected-header parameter
// (부록 A.4 step 1). Anything else — including "none" — is rejected.
var allowedAlgs = map[string]jose.SignatureAlgorithm{
	"ES256": jose.ES256,
	"EdDSA": jose.EdDSA,
}

// Failure reasons surfaced by verification (01 §3.3 / common failureReason).
const (
	ReasonPermissionDenied = "PERMISSION_DENIED"
	ReasonBadRequest       = "BAD_REQUEST"
)

// VerifyResult is the structured outcome of verify-command.
type VerifyResult struct {
	OK            bool   `json:"ok"`
	FailureReason string `json:"failure_reason,omitempty"` // PERMISSION_DENIED | BAD_REQUEST
	Step          string `json:"step"`                     // which check produced the outcome
	Detail        string `json:"detail"`
	Alg           string `json:"alg,omitempty"`
	KeyID         string `json:"key_id,omitempty"`
	TTLInjected   bool   `json:"ttl_injected"`
	CanonicalHex  string `json:"canonical_hex,omitempty"`
}

func fail(reason, step, detail string) VerifyResult {
	return VerifyResult{OK: false, FailureReason: reason, Step: step, Detail: detail}
}

// VerifyCommand runs the 부록 A.4 verification procedure against a parsed
// command message using a key_id -> public key ring (fail-closed: an unknown
// key_id is rejected). It enforces the alg allowlist, rejects alg:"none",
// requires the protected-header kid to equal payload.key_id, rebuilds the
// canonical 5-field body (injecting ttl_sec=120 if omitted), and verifies the
// detached ES256/EdDSA signature.
//
// Scope boundary: this only proves the 5-field body (id, rtu_id, max_power_w,
// issued_at, ttl_sec) is authentic and untampered. issued_at/ttl_sec are part
// of the canonical signed bytes but are never compared against wall-clock
// time here — VerifyCommand does not reject on staleness, and it enforces no
// replay/freshness (TTL expiry) guard. Safe-to-execute enforcement (replay
// rejection, expiry checks) is the responsibility of the production
// consumer/broker, not this verifier.
func VerifyCommand(msg map[string]any, ring map[string]crypto.PublicKey) VerifyResult {
	payload, ok := msg["payload"].(map[string]any)
	if !ok {
		return fail(ReasonBadRequest, "payload", "payload 객체가 없습니다")
	}
	sig, ok := payload["signature"].(string)
	if !ok || sig == "" {
		return fail(ReasonBadRequest, "signature", "signature 필드가 없거나 비어 있습니다")
	}
	keyID, ok := payload["key_id"].(string)
	if !ok || keyID == "" {
		return fail(ReasonBadRequest, "key_id", "key_id 필드가 없거나 비어 있습니다")
	}

	// --- Step 1: parse protected header, enforce alg allowlist / reject none.
	hdr, err := parseProtectedHeader(sig)
	if err != nil {
		return fail(ReasonBadRequest, "jws-format", err.Error())
	}
	res := VerifyResult{Alg: hdr.Alg, KeyID: keyID}
	joseAlg, allowed := allowedAlgs[hdr.Alg]
	if !allowed {
		r := fail(ReasonPermissionDenied, "alg-allowlist",
			fmt.Sprintf("alg=%q 는 허용 목록[ES256, EdDSA]에 없습니다(alg:none 및 목록 외 거부).", hdr.Alg))
		r.Alg, r.KeyID = hdr.Alg, keyID
		return r
	}

	// kid in the protected header must match payload.key_id (진위 일관성).
	if hdr.Kid != keyID {
		r := fail(ReasonPermissionDenied, "kid-mismatch",
			fmt.Sprintf("protected header kid=%q 가 payload key_id=%q 와 다릅니다.", hdr.Kid, keyID))
		r.Alg, r.KeyID = hdr.Alg, keyID
		return r
	}

	// --- Step 2: key_id lookup, fail-closed on unknown.
	pub, known := ring[keyID]
	if !known {
		r := fail(ReasonPermissionDenied, "unknown-key-id",
			fmt.Sprintf("미지의 key_id=%q 입니다(fail-closed 거부). 신뢰된 공개키가 없습니다.", keyID))
		r.Alg, r.KeyID = hdr.Alg, keyID
		return r
	}

	// --- Step 3: rebuild canonical 5-field body (부록 A.3).
	body, ttlInjected, err := BodyFromCommand(msg)
	if err != nil {
		r := fail(ReasonBadRequest, "canonical", err.Error())
		r.Alg, r.KeyID = hdr.Alg, keyID
		return r
	}
	canon, err := body.Canonical()
	if err != nil {
		r := fail(ReasonBadRequest, "canonical", err.Error())
		r.Alg, r.KeyID = hdr.Alg, keyID
		return r
	}
	res.TTLInjected = ttlInjected
	res.CanonicalHex = hex.EncodeToString(canon)

	// --- Step 4: verify detached signature (pin to the header's allowed alg).
	obj, err := jose.ParseDetached(sig, canon, []jose.SignatureAlgorithm{joseAlg})
	if err != nil {
		r := fail(ReasonPermissionDenied, "jws-parse", fmt.Sprintf("detached JWS 파싱 실패: %v", err))
		r.Alg, r.KeyID, r.CanonicalHex, r.TTLInjected = hdr.Alg, keyID, res.CanonicalHex, ttlInjected
		return r
	}
	if _, err := obj.Verify(pub); err != nil {
		r := fail(ReasonPermissionDenied, "signature",
			fmt.Sprintf("서명 검증 실패: %v (변조 또는 키 불일치).", err))
		r.Alg, r.KeyID, r.CanonicalHex, r.TTLInjected = hdr.Alg, keyID, res.CanonicalHex, ttlInjected
		return r
	}

	res.OK = true
	res.Step = "verified"
	res.Detail = "서명 검증 통과(alg 허용·key_id 신뢰·JCS 5필드·서명 유효)."
	return res
}

// protectedHeader is the minimal set of JOSE header fields we inspect.
type protectedHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// parseProtectedHeader decodes the first segment of a compact detached JWS
// ("protected..signature") and returns its alg/kid. It verifies the detached
// shape (empty payload segment).
func parseProtectedHeader(compact string) (protectedHeader, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return protectedHeader{}, fmt.Errorf("JWS compact 형식이 3개 세그먼트가 아닙니다(%d개).", len(parts))
	}
	if parts[1] != "" {
		return protectedHeader{}, fmt.Errorf("detached JWS 가 아닙니다(payload 세그먼트가 비어있지 않음).")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return protectedHeader{}, fmt.Errorf("protected header base64url 디코드 실패: %w", err)
	}
	var h protectedHeader
	if err := json.Unmarshal(raw, &h); err != nil {
		return protectedHeader{}, fmt.Errorf("protected header JSON 파싱 실패: %w", err)
	}
	if h.Alg == "" {
		return protectedHeader{}, fmt.Errorf("protected header 에 alg 가 없습니다.")
	}
	return h, nil
}
