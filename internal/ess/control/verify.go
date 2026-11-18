package control

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// Verification codes (aligned with verify_golden.py) and the standard
// failure_reason each maps to in an ACK (01 §6, 부록 A.4).
const (
	CodeOK               = "OK"
	CodeBadJWS           = "BAD_JWS"
	CodeAlgNotAllowed    = "ALG_NOT_ALLOWED"
	CodeKidMismatch      = "KID_MISMATCH"
	CodeUnknownKid       = "UNKNOWN_KID"
	CodeBadRequest       = "BAD_REQUEST"
	CodeSignatureInvalid = "SIGNATURE_INVALID"
	CodeExpired          = "EXPIRED"
	CodeFutureIssued     = "FUTURE_ISSUED_AT"
	CodeDuplicate        = "DUPLICATE_ID"
)

// FailureReasonFor maps a verification code to the ACK failure_reason.
func FailureReasonFor(code string) string {
	switch code {
	case CodeOK, CodeDuplicate:
		return ""
	case CodeBadRequest, CodeExpired, CodeFutureIssued:
		return "BAD_REQUEST"
	default:
		return "PERMISSION_DENIED"
	}
}

// VerifyOptions enables the wall-clock dependent steps (A.4 6·7).
type VerifyOptions struct {
	NowMs   int64     // 0 → step 6 skipped
	SkewSec int64     // future tolerance, default 60
	Dedup   *DedupSet // nil → step 7 skipped
}

// DedupSet is the A.4 7단계 id cache (apply-once).
type DedupSet struct {
	mu   sync.Mutex
	seen map[string]bool
}

// NewDedup returns an empty id cache.
func NewDedup() *DedupSet { return &DedupSet{seen: map[string]bool{}} }

func (d *DedupSet) check(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	k := strings.ToLower(id) // 수신 비교는 대소문자 무관(01 §2.4)
	if d.seen[k] {
		return false
	}
	d.seen[k] = true
	return true
}

// VerifyResult reports the outcome step by step.
type VerifyResult struct {
	OK            bool     `json:"ok"`
	Code          string   `json:"code"`
	FailureReason string   `json:"failure_reason,omitempty"`
	Step          string   `json:"step"`
	Detail        string   `json:"detail"`
	Alg           string   `json:"alg,omitempty"`
	KeyID         string   `json:"key_id,omitempty"`
	Mode          string   `json:"mode,omitempty"`
	TTLInjected   bool     `json:"ttl_injected"`
	Canonical     string   `json:"canonical,omitempty"`
	CanonicalSHA  string   `json:"canonical_sha256,omitempty"`
	Type2Present  []string `json:"type2_present,omitempty"`
	StepsRun      []string `json:"steps_run"`
	Notes         []string `json:"notes,omitempty"`
}

func fail(r *VerifyResult, code, step, detail string) *VerifyResult {
	r.OK = false
	r.Code = code
	r.FailureReason = FailureReasonFor(code)
	r.Step = step
	r.Detail = detail
	return r
}

// VerifyCommand runs 부록 A.4 against a decoded command message.
func VerifyCommand(msg map[string]any, ring Keyring, opt VerifyOptions) *VerifyResult {
	r := &VerifyResult{}
	payload, _ := msg["payload"].(map[string]any)
	if payload == nil {
		return fail(r, CodeBadRequest, "0", "payload 객체가 없습니다")
	}
	sigField, _ := payload["signature"].(string)
	if sigField == "" {
		return fail(r, CodeBadJWS, "0", "payload.signature 가 없거나 문자열이 아닙니다")
	}
	jws, err := ParseDetached(sigField)
	if err != nil {
		return fail(r, CodeBadJWS, "0", err.Error())
	}

	// 1. alg allowlist
	r.StepsRun = append(r.StepsRun, "1")
	alg, _ := jws.Header["alg"].(string)
	r.Alg = alg
	if !AlgAllowlist[alg] {
		return fail(r, CodeAlgNotAllowed, "1", fmt.Sprintf("alg=%q 는 허용 목록(ES256, EdDSA)에 없습니다(RFC 8725)", alg))
	}
	// 2-1. kid == key_id
	r.StepsRun = append(r.StepsRun, "2-1")
	kid, _ := jws.Header["kid"].(string)
	keyID, _ := payload["key_id"].(string)
	r.KeyID = keyID
	if kid != keyID {
		return fail(r, CodeKidMismatch, "2-1", fmt.Sprintf("protected.kid=%q ≠ payload.key_id=%q (키 혼동 방어)", kid, keyID))
	}
	// 2. key lookup (fail-closed)
	r.StepsRun = append(r.StepsRun, "2")
	pub, ok := ring[kid]
	if !ok {
		return fail(r, CodeUnknownKid, "2", fmt.Sprintf("kid=%q 가 신뢰 키 목록에 없습니다(fail-closed)", kid))
	}
	if strings.HasPrefix(kid, "haezoom-ctrl-test-") {
		r.Notes = append(r.Notes, "시험 전용 키(haezoom-ctrl-test-*)입니다. 운영 키스토어에 적재하지 마십시오(A.1).")
	}
	// 3. A.3 key-set rule → JCS
	r.StepsRun = append(r.StepsRun, "3")
	sb, err := BuildSigningBody(msg)
	if err != nil {
		return fail(r, CodeBadRequest, "3", err.Error())
	}
	r.Mode, r.TTLInjected, r.Type2Present = sb.Mode, sb.TTLInjected, sb.Type2Used
	canon, sum, err := sb.Canonical()
	if err != nil {
		return fail(r, CodeBadRequest, "3", err.Error())
	}
	r.Canonical, r.CanonicalSHA = string(canon), sum
	if len(sb.Ignored) > 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("서명 대상 밖 payload 필드(서명으로 보호되지 않음): %s", strings.Join(sb.Ignored, ", ")))
	}
	// 4·5. signature
	r.StepsRun = append(r.StepsRun, "4")
	if ok, why := rawVerify(pub, alg, SigningInput(jws.ProtectedB64, canon), jws.Sig); !ok {
		return fail(r, CodeSignatureInvalid, "4", why)
	}
	// 6. expiry / skew
	if opt.NowMs > 0 {
		r.StepsRun = append(r.StepsRun, "6")
		ia, err1 := toInt(sb.Body["issued_at"])
		ttl, err2 := toInt(sb.Body["ttl_sec"])
		if err1 != nil || err2 != nil {
			return fail(r, CodeBadRequest, "6", "issued_at·ttl_sec 를 정수로 읽을 수 없습니다")
		}
		skew := opt.SkewSec
		if skew <= 0 {
			skew = 60
		}
		if ia > opt.NowMs+skew*1000 {
			return fail(r, CodeFutureIssued, "6", fmt.Sprintf("issued_at=%d 가 현재(%d)+%ds 를 넘는 미래 시각입니다", ia, opt.NowMs, skew))
		}
		if opt.NowMs > ia+ttl*1000 {
			return fail(r, CodeExpired, "6", fmt.Sprintf("만료된 명령입니다: issued_at+ttl_sec=%d < now=%d (%.1fs 경과)", ia+ttl*1000, opt.NowMs, float64(opt.NowMs-ia-ttl*1000)/1000))
		}
	} else {
		r.Notes = append(r.Notes, "A.4 6단계(만료·스큐)는 --now 를 주면 수행합니다.")
	}
	// 7. dedup
	if opt.Dedup != nil {
		r.StepsRun = append(r.StepsRun, "7")
		id, _ := msg["id"].(string)
		if !opt.Dedup.check(id) {
			r.OK = true
			r.Code = CodeDuplicate
			r.Step = "7"
			r.Detail = fmt.Sprintf("id=%s 는 이미 수신한 명령입니다 — 재적용하지 않고 ACK 만 재송신해야 합니다(01 §2.4)", id)
			return r
		}
	}
	r.OK, r.Code, r.Step = true, CodeOK, "done"
	r.Detail = fmt.Sprintf("서명 검증 성공 (mode=%s, canonical sha256=%s)", sb.Mode, sum[:16]+"…")
	return r
}

func toInt(v any) (int64, error) {
	switch x := v.(type) {
	case json.Number:
		return x.Int64()
	case int:
		return int64(x), nil
	case int64:
		return x, nil
	case float64:
		return int64(x), nil
	}
	return 0, fmt.Errorf("not int: %T", v)
}
