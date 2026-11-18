// Package emulate is a reference EMS decision model: given a signed command
// plus the resource's info (and optionally its latest telemetry and state), it
// produces the ACK (…/command/response) a conforming EMS should publish and a
// trace of which rule decided it. It lets a partner compare its own EMS
// decisions with the standard — it does not talk to a broker.
package emulate

import (
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"github.com/haezoom/ganeum/internal/ess/control"
	"github.com/haezoom/ganeum/internal/ess/validate"
)

// State is the EMS-side state the standard's checks depend on.
type State struct {
	NowMs             int64           // 0 → expiry/skew not checked
	SkewSec           int64           // default 60
	LastPolarity      string          // CHARGE|DISCHARGE (last non-IDLE direction)
	LastPolarityAtMs  int64           // when the polarity last changed
	SeenIDs           map[string]bool // dedup cache (A.4 7단계)
	PowerLimitPartial bool            // accept and partially execute instead of rejecting (협의 필요)
}

// Step is one decision trace line.
type Step struct {
	Check  string `json:"check"`
	Result string `json:"result"` // pass|fail|skip|note
	Detail string `json:"detail"`
}

// Outcome is the emulated ACK plus trace.
type Outcome struct {
	Response map[string]any `json:"response"`
	Trace    []Step         `json:"trace"`
	Notes    []string       `json:"notes,omitempty"`
}

// Decide runs the reference decision.
func Decide(v *validate.Validator, raw []byte, ring control.Keyring, info *validate.Context, tele map[string]any, st State) (*Outcome, error) {
	o := &Outcome{}
	trace := func(c, r, f string, a ...any) { o.Trace = append(o.Trace, Step{c, r, fmt.Sprintf(f, a...)}) }

	msg, err := validate.Decode(raw)
	resp := map[string]any{"schema_version": "0.2", "id": NewUUID(), "type": "response"}
	reject := func(reason, check, f string, a ...any) *Outcome {
		resp["accepted"] = false
		resp["result"] = "FAILURE"
		resp["failure_reason"] = reason
		resp["received_at"] = receivedAt(st)
		trace(check, "fail", f+" → failure_reason="+reason, a...)
		o.Response = resp
		return o
	}
	if err != nil {
		resp["req_id"] = "00000000-0000-0000-0000-000000000000"
		resp["rtu_id"] = "UNKNOWN"
		return reject("BAD_REQUEST", "parse", "JSON 파싱 실패: %v", err), nil
	}
	id, _ := msg["id"].(string)
	rid, _ := msg["rtu_id"].(string)
	resp["req_id"] = id
	resp["rtu_id"] = rid
	p, _ := msg["payload"].(map[string]any)
	mode, _ := p["mode"].(string)

	// 0. schema (R-12 포함)
	sr := v.ValidateBytes("command", raw, validate.Options{Type: validate.TypeCommand})
	if !sr.OK {
		var errs []string
		for _, x := range sr.Violations {
			if x.Level == validate.LevelError {
				errs = append(errs, x.Path+" "+x.Rule)
			}
		}
		return reject("BAD_REQUEST", "schema+R-1/R-2/R-12", "%s", strings.Join(errs, "; ")), nil
	}
	trace("schema+R-1/R-2/R-12", "pass", "command 스키마·단일 메시지 규칙 통과")

	// 1~5. signature
	vr := control.VerifyCommand(msg, ring, control.VerifyOptions{})
	if !vr.OK {
		return reject("PERMISSION_DENIED", "A.4 1~5 서명", "[%s] %s", vr.Code, vr.Detail), nil
	}
	trace("A.4 1~5 서명", "pass", "%s", vr.Detail)

	// 6. expiry / skew
	if st.NowMs > 0 {
		vr6 := control.VerifyCommand(msg, ring, control.VerifyOptions{NowMs: st.NowMs, SkewSec: st.SkewSec})
		if !vr6.OK {
			return reject("BAD_REQUEST", "A.4 6 만료·스큐", "[%s] %s", vr6.Code, vr6.Detail), nil
		}
		trace("A.4 6 만료·스큐", "pass", "now=%d 기준 유효", st.NowMs)
	} else {
		trace("A.4 6 만료·스큐", "skip", "--now 미지정")
	}

	accept := func() *Outcome {
		resp["accepted"] = true
		resp["result"] = "IN_PROGRESS"
		resp["mode"] = mode
		if mode == "IMMEDIATE" {
			resp["direction"] = p["direction"]
			resp["power_w"] = p["power_w"]
		} else {
			sl, _ := p["slots"].([]any)
			resp["slots_count"] = len(sl)
		}
		resp["received_at"] = receivedAt(st)
		o.Response = resp
		return o
	}

	// 7. dedup
	if st.SeenIDs != nil {
		if st.SeenIDs[strings.ToLower(id)] {
			trace("A.4 7 dedup", "note", "이미 처리한 id — 재적용하지 않고 원 처리 결과의 ACK 를 재송신합니다(01 §2.4)")
			o.Notes = append(o.Notes, "중복 명령: 실제 EMS 는 원 ACK 의 accepted/failure_reason 을 그대로 재송신해야 합니다. 이 도구는 원 결과를 모르므로 수락 형태로 표시합니다.")
			return accept(), nil
		}
		trace("A.4 7 dedup", "pass", "신규 id")
	}

	// 운영 상태·자기신고 대조
	if info != nil && info.RTUID != "" && info.RTUID != rid {
		o.Notes = append(o.Notes, fmt.Sprintf("--info 의 rtu_id(%s)와 명령 rtu_id(%s)가 다릅니다. 같은 자원의 info 를 주십시오.", info.RTUID, rid))
	}
	if info != nil {
		if len(info.ControlModes) > 0 && !info.ControlModes[mode] {
			return reject("UNSUPPORTED_CONTROL", "control_modes", "mode=%s 는 info.control_modes 에 없음", mode), nil
		}
		trace("control_modes", "pass", "mode=%s 지원", mode)
	}
	if tele != nil {
		if e, _ := tele["payload"].(map[string]any); e != nil {
			if ems, _ := e["ems"].(map[string]any); ems != nil {
				if om, _ := ems["operation_mode"].(string); om == "LOCAL" || om == "MANUAL" {
					return reject("LOCAL_MODE", "ems.operation_mode", "현재 운전모드 %s — 상위 명령 미적용", om), nil
				}
			}
		}
	}
	if info != nil && mode == "SCHEDULE" && info.Resolution > 0 {
		sl, _ := p["slots"].([]any)
		for i, it := range sl {
			s, _ := it.(map[string]any)
			for _, k := range []string{"start_min", "end_min"} {
				if n, ok := toI(s[k]); ok && n%info.Resolution != 0 {
					return reject("BAD_REQUEST", "R-2 해상도", "slots[%d].%s=%d 가 %d분 배수 아님", i, k, n, info.Resolution), nil
				}
			}
		}
		trace("R-2 해상도", "pass", "모든 슬롯 경계가 %d분 배수", info.Resolution)
	}
	if info != nil && info.HasSocLimits {
		for _, k := range []string{"soc_min_pct", "soc_max_pct"} {
			if n, ok := toI(p[k]); ok && (n < info.SocMin || n > info.SocMax) {
				return reject("BAD_REQUEST", "R-6 SoC 범위", "%s=%d ∉ [%d,%d]", k, n, info.SocMin, info.SocMax), nil
			}
		}
		trace("R-6 SoC 범위", "pass", "info 등록 한계 [%d,%d] 이내", info.SocMin, info.SocMax)
	}

	if mode == "IMMEDIATE" {
		dir, _ := p["direction"].(string)
		pw, _ := toI(p["power_w"])
		// R-7 polarity gap
		ov, _ := p["override_polarity_gap"].(bool)
		if info != nil && info.HasPolarityGap && info.PolarityGap > 0 && dir != "IDLE" && st.LastPolarity != "" && dir != st.LastPolarity && st.LastPolarityAtMs > 0 && st.NowMs > 0 {
			elapsed := (st.NowMs - st.LastPolarityAtMs) / 1000
			if elapsed < info.PolarityGap {
				if ov {
					trace("R-7 극성 휴지", "note", "휴지 %ds 미경과(경과 %ds)지만 override_polarity_gap=true → 수행, result 에 readback 필수(R-8)", info.PolarityGap, elapsed)
				} else {
					return reject("BAD_REQUEST", "R-7 극성 휴지", "%s→%s 전환, 경과 %ds < min_polarity_gap_sec %ds", st.LastPolarity, dir, elapsed, info.PolarityGap), nil
				}
			} else {
				trace("R-7 극성 휴지", "pass", "경과 %ds ≥ %ds", elapsed, info.PolarityGap)
			}
		} else {
			trace("R-7 극성 휴지", "skip", "info.min_polarity_gap_sec·--last-polarity·--now 중 일부가 없거나 극성 전환이 아님")
		}
		// SoC / power limit against telemetry
		if tele != nil {
			tp, _ := tele["payload"].(map[string]any)
			bat, _ := tp["battery"].(map[string]any)
			soc, hasSoc := toI(bat["soc_pct"])
			smin, okMin := toI(p["soc_min_pct"])
			smax, okMax := toI(p["soc_max_pct"])
			if !okMin && info != nil && info.HasSocLimits {
				smin, okMin = info.SocMin, true
			}
			if !okMax && info != nil && info.HasSocLimits {
				smax, okMax = info.SocMax, true
			}
			if hasSoc && dir == "DISCHARGE" && okMin && soc <= smin {
				return reject("SOC_LIMIT", "SoC 한계", "SoC %d%% ≤ 하한 %d%% 에서 방전 명령", soc, smin), nil
			}
			if hasSoc && dir == "CHARGE" && okMax && soc >= smax {
				return reject("SOC_LIMIT", "SoC 한계", "SoC %d%% ≥ 상한 %d%% 에서 충전 명령", soc, smax), nil
			}
			limitKey := map[string]string{"CHARGE": "avail_charge_w", "DISCHARGE": "avail_discharge_w"}[dir]
			var limit int64 = -1
			src := ""
			if a, ok := toI(bat[limitKey]); ok {
				limit, src = a, limitKey
			}
			if info != nil && info.RatedSum > 0 && (limit < 0 || info.RatedSum < limit) {
				limit, src = info.RatedSum, "Σ info.pcs[].rated_power_w"
			}
			if limit >= 0 && dir != "IDLE" && pw > limit {
				if st.PowerLimitPartial {
					trace("가용 출력", "note", "power_w=%d > 상한 %d(%s) — 수락 후 부분 수행 모드: result=PARTIAL·failure_reason=POWER_LIMIT_EXCEEDED 예정", pw, limit, src)
					o.Notes = append(o.Notes, "가용 출력 초과 명령을 ACK 단계에서 거부할지 수락 후 부분 수행할지는 표준 v0.2 에서 [협의 필요] 입니다.")
				} else {
					o.Notes = append(o.Notes, "가용 출력 초과 명령을 ACK 단계에서 거부할지 수락 후 부분 수행할지는 표준 v0.2 에서 [협의 필요] 입니다(--power-limit-partial 로 다른 쪽 동작 확인).")
					return reject("POWER_LIMIT_EXCEEDED", "가용 출력", "power_w=%d > 상한 %d(%s)", pw, limit, src), nil
				}
			} else if limit >= 0 {
				trace("가용 출력", "pass", "power_w=%d ≤ 상한 %d(%s)", pw, limit, src)
			}
		} else {
			trace("SoC·가용 출력", "skip", "--telemetry 미지정")
		}
	}
	trace("결정", "pass", "수락 → accepted=true, result=IN_PROGRESS")
	return accept(), nil
}

func receivedAt(st State) int64 {
	if st.NowMs > 0 {
		return st.NowMs
	}
	return time.Now().UnixMilli()
}

func toI(v any) (int64, bool) {
	m := map[string]any{"x": v}
	return numOf(m)
}

func numOf(m map[string]any) (int64, bool) {
	switch x := m["x"].(type) {
	case interface{ Int64() (int64, error) }:
		i, err := x.Int64()
		return i, err == nil
	case int:
		return int64(x), true
	case int64:
		return x, true
	}
	return 0, false
}

// NewUUID returns a lowercase RFC 9562 v4 UUID.
func NewUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
