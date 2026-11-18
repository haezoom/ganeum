package validate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/haezoom/ganeum/internal/ess/schema"
)

// ---- topic (R-10, R-11 partial, 01 §3.2) ----------------------------------

func topicType(topic string) string {
	p := strings.Split(topic, "/")
	if len(p) < 4 {
		return ""
	}
	switch strings.Join(p[3:], "/") {
	case "telemetry":
		return TypeTelemetry
	case "info":
		return TypeInfo
	case "command":
		return TypeCommand
	case "command/response":
		return TypeResponse
	case "command/result":
		return TypeResult
	case "keys":
		return "keys"
	}
	return ""
}

func checkTopic(topic, typ string, msg map[string]any) []Violation {
	var vs []Violation
	p := strings.Split(topic, "/")
	if len(p) < 4 || p[0] != "v1" {
		return append(vs, ve("", "R-10/topic-format", "토픽 %q 가 v1/{vendor}/{rtu_id}/<telemetry|info|command|command/response|command/result> 형식이 아닙니다(01 §3.2).", topic))
	}
	for _, seg := range p {
		if strings.ContainsAny(seg, "+#") {
			vs = append(vs, ve("", "R-10/topic-wildcard", "토픽에 와일드카드(+, #)를 쓸 수 없습니다."))
		}
	}
	if !idStringRe.MatchString(p[1]) {
		vs = append(vs, ve("", "R-10/topic-vendor", "vendor 세그먼트 %q 가 허용 문자 [A-Za-z0-9_.:-] 범위를 벗어납니다.", p[1]))
	}
	want := topicType(topic)
	if want == "" {
		vs = append(vs, ve("", "R-10/topic-suffix", "토픽 끝 %q 는 표준 토픽이 아닙니다.", strings.Join(p[3:], "/")))
	} else if want != typ {
		vs = append(vs, ve("/type", "R-10", "type=%q 가 토픽 마지막 세그먼트(%s)와 다릅니다 — 해줌은 이 메시지를 폐기합니다(04 §0).", typ, want))
	}
	if rid, ok := str(msg, "rtu_id"); ok && rid != p[2] {
		vs = append(vs, ve("/rtu_id", "R-11", "헤더 rtu_id=%q ≠ 토픽 {rtu_id}=%q — 3자 일치 위반으로 폐기됩니다(01 §3.3).", rid, p[2]))
	}
	return vs
}

// ---- common header ----------------------------------------------------------

func lintCommon(msg map[string]any, typ string) []Violation {
	var vs []Violation
	if sv, ok := str(msg, "schema_version"); ok && sv != schema.StandardVersion {
		vs = append(vs, vw("/schema_version", "schema-version",
			"schema_version=%q 는 이 도구가 검증하는 ESS 표준 세트(%s)와 다릅니다. Draft 기간 MINOR 차이는 하위호환이 보장되지 않습니다(01 §8).", sv, schema.StandardVersion))
	}
	for _, k := range []string{"id", "req_id"} {
		if s, ok := str(msg, k); ok && uuidAnyRe.MatchString(s) && !uuidLowerRe.MatchString(s) {
			vs = append(vs, vw("/"+k, "uuid-lowercase", "%s 에 대문자가 있습니다. 생성은 소문자 8-4-4-4-12 표기여야 합니다(수신은 대소문자 무관, 01 §2.4).", k))
		}
	}
	if p := obj(msg, "payload"); p != nil {
		if s, ok := str(p, "req_id"); ok && uuidAnyRe.MatchString(s) && !uuidLowerRe.MatchString(s) {
			vs = append(vs, vw("/payload/req_id", "uuid-lowercase", "req_id 에 대문자가 있습니다. 대상 명령의 id 를 그대로(verbatim) 실어야 합니다(01 §2.4)."))
		}
	}
	// ms heuristic
	check := func(m map[string]any, base string, keys ...string) {
		for _, k := range keys {
			if n, ok := num(m, k); ok && n > 0 && n < msMinValid {
				vs = append(vs, ve(base+"/"+k, "epoch-ms", "%s=%d 는 자릿수로 보아 초 단위로 의심됩니다. 모든 시각은 UTC epoch 밀리초 정수입니다(01 §2.2).", k, n))
			}
		}
	}
	check(msg, "", "event_time", "ingest_time", "received_at")
	p := obj(msg, "payload")
	check(p, "/payload", "issued_at", "effective_at")
	et, ok1 := num(msg, "event_time")
	it, ok2 := num(msg, "ingest_time")
	if ok1 && ok2 && typ != TypeCommand && it < et {
		vs = append(vs, vw("/ingest_time", "time-order", "ingest_time(%d) 가 event_time(%d) 보다 이릅니다. 송신 생성 시각은 측정 시각 이후여야 합니다 — NTP 동기를 확인하십시오(01 §2.2).", it, et))
	}
	return vs
}

// ---- telemetry --------------------------------------------------------------

func lintTelemetry(msg map[string]any) []Violation {
	var vs []Violation
	p := obj(msg, "payload")
	ids := map[string]int{}
	for i, it := range arr(p, "pcs") {
		pc, _ := it.(map[string]any)
		base := fmt.Sprintf("/payload/pcs/%d", i)
		if id, ok := str(pc, "id"); ok {
			if j, dup := ids[id]; dup {
				vs = append(vs, ve(base+"/id", "pcs-id-unique", "pcs id %q 가 /payload/pcs/%d 와 중복됩니다.", id, j))
			}
			ids[id] = i
		}
		vs = append(vs, idlePower(pc, base, "direction", "power_w")...)
		st, _ := str(pc, "status")
		dir, _ := str(pc, "direction")
		pw, hasPw := num(pc, "power_w")
		if (st == "STOP" || st == "FAULT" || st == "IDLE") && hasPw && pw > 0 {
			vs = append(vs, vw(base+"/power_w", "status-power", "status=%s 인데 power_w=%d 입니다. 정지·대기 상태의 전력은 0 이어야 합니다.", st, pw))
		}
		if st == "RUN" && dir == "IDLE" && hasPw && pw == 0 {
			vs = append(vs, vi(base, "status-power", "status=RUN · direction=IDLE · power_w=0 입니다. 대기 중이면 status=IDLE 이 더 정확합니다."))
		}
		if r, ok := str(pc, "reason"); ok && r == "OTHER" && !has(pc, "reason_text") {
			vs = append(vs, vw(base, "reason-text", "reason=OTHER 이면 reason_text 를 함께 싣는 것을 권장합니다."))
		}
		if r, ok := str(pc, "reason"); ok && r == "" {
			vs = append(vs, ve(base+"/reason", "reason-empty", "reason 값이 없을 때는 빈 문자열을 보내지 말고 키를 생략하십시오."))
		}
	}
	b := obj(p, "battery")
	rt, ok1 := num(b, "rack_total")
	ro, ok2 := num(b, "rack_online")
	if ok1 && ok2 && ro > rt {
		vs = append(vs, ve("/payload/battery/rack_online", "R-3", "rack_online(%d) ≤ rack_total(%d) 이어야 합니다(04 §7.1 R-3).", ro, rt))
	}
	vmax, a := num(b, "cell_v_max_mv")
	vmin, c := num(b, "cell_v_min_mv")
	if a && c && vmin > vmax {
		vs = append(vs, ve("/payload/battery", "cell-range", "cell_v_min_mv(%d) 가 cell_v_max_mv(%d) 보다 큽니다.", vmin, vmax))
	}
	if a && (vmax < 1000 || vmax > 5000) {
		vs = append(vs, vw("/payload/battery/cell_v_max_mv", "unit-mv", "cell_v_max_mv=%d — 셀 전압은 mV 정수입니다(예: 3.32V → 3320). 단위를 확인하십시오.", vmax))
	}
	tmax, a := num(b, "cell_t_max_c")
	tmin, c := num(b, "cell_t_min_c")
	if a && c && tmin > tmax {
		vs = append(vs, ve("/payload/battery", "cell-range", "cell_t_min_c(%d) 가 cell_t_max_c(%d) 보다 큽니다.", tmin, tmax))
	}
	if has(b, "soc_permille") {
		vs = append(vs, vw("/payload/battery/soc_permille", "reserved", "soc_permille 은 예약 필드로 v0.2 에서는 사용하지 않습니다(04 §2)."))
	}
	if al := obj(b, "bms_alarm"); al != nil {
		if c, _ := str(al, "code"); c == "OTHER" && !has(al, "text") {
			vs = append(vs, vw("/payload/battery/bms_alarm", "bms-alarm-text", "bms_alarm.code=OTHER 이면 text 를 함께 싣는 것을 권장합니다(01 §6.1)."))
		}
	}
	if e := obj(p, "ems"); e != nil {
		if s := obj(e, "active_slot"); s != nil {
			vs = append(vs, slotChecks(s, "/payload/ems/active_slot", 5)...)
		}
	}
	if pv := obj(p, "pv"); pv != nil {
		if pw, ok := num(pv, "power_w"); ok && pw < 0 {
			vs = append(vs, vw("/payload/pv/power_w", "pv-negative", "pv.power_w=%d 가 음수입니다.", pw))
		}
	}
	return vs
}

// idlePower is R-1: direction=IDLE ⇒ power_w=0.
func idlePower(m map[string]any, base, dk, pk string) []Violation {
	d, _ := str(m, dk)
	pw, ok := num(m, pk)
	if d == "IDLE" && ok && pw != 0 {
		return []Violation{ve(base+"/"+pk, "R-1", "%s=IDLE 이면 %s=0 이어야 합니다(실제 %d, 04 §7.1 R-1).", dk, pk, pw)}
	}
	return nil
}

// ---- info -----------------------------------------------------------------

func lintInfo(msg map[string]any) []Violation {
	var vs []Violation
	p := obj(msg, "payload")
	lo, a := num(p, "soc_limit_min_pct")
	hi, b := num(p, "soc_limit_max_pct")
	if a && b && lo > hi {
		vs = append(vs, ve("/payload", "soc-limit-order", "soc_limit_min_pct(%d) ≤ soc_limit_max_pct(%d) 이어야 합니다.", lo, hi))
	}
	ids := map[string]bool{}
	var sum int64
	for i, it := range arr(p, "pcs") {
		pc, _ := it.(map[string]any)
		if id, ok := str(pc, "id"); ok {
			if ids[id] {
				vs = append(vs, ve(fmt.Sprintf("/payload/pcs/%d/id", i), "pcs-id-unique", "pcs id %q 가 중복됩니다.", id))
			}
			ids[id] = true
		}
		if r, ok := num(pc, "rated_power_w"); ok {
			sum += r
			if r > 0 && r < 1000 {
				vs = append(vs, vw(fmt.Sprintf("/payload/pcs/%d/rated_power_w", i), "unit-w", "rated_power_w=%d — kW 로 넣은 것 아닌지 확인하십시오(정수 W).", r))
			}
		}
	}
	bat := obj(p, "battery")
	if e, ok := num(bat, "rated_energy_wh"); ok && e > 0 && e < 1000 {
		vs = append(vs, vw("/payload/battery/rated_energy_wh", "unit-wh", "rated_energy_wh=%d — kWh 로 넣은 것 아닌지 확인하십시오(정수 Wh).", e))
	}
	if rp, ok := num(bat, "rated_power_w"); ok && sum > 0 && rp > sum {
		vs = append(vs, vw("/payload/battery/rated_power_w", "rating", "battery.rated_power_w(%d) 가 PCS 정격 합(%d) 보다 큽니다. 실제 출력 상한은 PCS 정격 합으로 제한됩니다.", rp, sum))
	}
	if iv, ok := num(p, "interval_sec"); ok && iv > 60 {
		vs = append(vs, vw("/payload/interval_sec", "interval", "interval_sec=%d — 평시 telemetry 는 1분(60초) 이내 주기입니다(01 §4.1).", iv))
	}
	if !has(p, "failsafe_mode") {
		vs = append(vs, vi("/payload", "failsafe-default", "failsafe_mode 를 생략하면 SCHEDULE_HOLD(등록 스케줄 지속 + SoC 한계 준수)로 간주됩니다(04 §3)."))
	}
	if !has(p, "min_polarity_gap_sec") {
		vs = append(vs, vi("/payload", "polarity-gap-default", "min_polarity_gap_sec 를 생략하면 극성 휴지 제약 없음으로 간주되고 override_polarity_gap 은 no-op 이 됩니다(01 §5.1)."))
	}
	return vs
}

// ---- command ----------------------------------------------------------------

func lintCommand(msg map[string]any) []Violation {
	var vs []Violation
	p := obj(msg, "payload")
	mode, _ := str(p, "mode")
	if mode == "IMMEDIATE" {
		vs = append(vs, idlePower(p, "/payload", "direction", "power_w")...)
	}
	if mode == "SCHEDULE" {
		vs = append(vs, slotsChecks(arr(p, "slots"), 0)...)
		if tz, ok := num(p, "tz_offset_min"); ok && (tz < -720 || tz > 840) {
			vs = append(vs, ve("/payload/tz_offset_min", "tz-range", "tz_offset_min=%d 가 유효한 UTC 오프셋 범위(-720~840분)를 벗어납니다.", tz))
		}
		for _, k := range []string{"hold_sec", "override_polarity_gap"} {
			if has(p, k) {
				vs = append(vs, ve("/payload/"+k, "R-12", "SCHEDULE 에 %s 가 실려 있습니다. EMS 는 이 명령을 failure_reason=BAD_REQUEST 로 거부해야 합니다(무시가 아님, 04 §7.1 R-12).", k))
			}
		}
	}
	smin, a := num(p, "soc_min_pct")
	smax, b := num(p, "soc_max_pct")
	if a && b && smin > smax {
		vs = append(vs, ve("/payload", "R-6", "soc_min_pct(%d) ≤ soc_max_pct(%d) 이어야 합니다(04 §7.1 R-6).", smin, smax))
	}
	if kid, ok := str(p, "key_id"); ok && !keyIDProdRe.MatchString(kid) {
		if keyIDTestRe.MatchString(kid) {
			vs = append(vs, vi("/payload/key_id", "key-id", "시험 전용 key_id(%s) 입니다. 운영 키스토어에 적재하지 마십시오(01 부록 A.1).", kid))
		} else {
			vs = append(vs, vw("/payload/key_id", "key-id", "key_id=%q 가 운영 라벨 형식 haezoom-ctrl-YYYY-MM 이 아닙니다(01 부록 A.1).", kid))
		}
	}
	if s, ok := str(p, "signature"); ok {
		parts := strings.Split(s, ".")
		if len(parts) != 3 || parts[1] != "" {
			vs = append(vs, ve("/payload/signature", "jws-detached", "signature 는 detached compact JWS '<protected>..<signature>' (3세그먼트, 가운데 빈 문자열) 여야 합니다(01 부록 A.2). 서명 검증은 verify-command 로 하십시오."))
		} else if strings.ContainsAny(s, "=+/") {
			vs = append(vs, ve("/payload/signature", "jws-base64url", "signature 에 패딩(=) 또는 표준 base64 문자(+,/)가 있습니다. BASE64URL(패딩 없음)이어야 합니다."))
		}
	}
	ia, ok1 := num(p, "issued_at")
	et, ok2 := num(msg, "event_time")
	if ok1 && ok2 && ia != et {
		vs = append(vs, vi("/payload/issued_at", "issued-at", "issued_at(%d) 과 event_time(%d) 이 다릅니다. 서명·만료 판정은 issued_at 기준입니다.", ia, et))
	}
	if hs, ok := num(p, "hold_sec"); ok && hs > 86400 {
		vs = append(vs, vw("/payload/hold_sec", "hold-sec", "hold_sec=%d 가 하루를 넘습니다. v0.2 는 상한이 없지만 [협의 필요] 항목입니다(01 §5.1).", hs))
	}
	return vs
}

// slotsChecks is R-2 (no overlap, ascending, start<end, resolution multiple)
// plus R-1 per slot. res=0 → only the 5-minute floor (schedule_resolution_min
// is always one of 5/15/30/60, so every boundary must be a multiple of 5).
func slotsChecks(slots []any, res int64) []Violation {
	var vs []Violation
	type iv struct {
		s, e int64
		i    int
	}
	var list []iv
	for i, it := range slots {
		s, _ := it.(map[string]any)
		base := fmt.Sprintf("/payload/slots/%d", i)
		vs = append(vs, slotChecks(s, base, max64(res, 5))...)
		st, a := num(s, "start_min")
		en, b := num(s, "end_min")
		if a && b {
			list = append(list, iv{st, en, i})
		}
	}
	for k := 1; k < len(list); k++ {
		prev, cur := list[k-1], list[k]
		if cur.s < prev.s {
			vs = append(vs, ve(fmt.Sprintf("/payload/slots/%d", cur.i), "R-2/order", "슬롯이 오름차순이 아닙니다: slots[%d].start_min=%d < slots[%d].start_min=%d (04 §7.1 R-2).", cur.i, cur.s, prev.i, prev.s))
		}
	}
	sorted := append([]iv(nil), list...)
	sort.Slice(sorted, func(a, b int) bool { return sorted[a].s < sorted[b].s })
	for k := 1; k < len(sorted); k++ {
		if sorted[k].s < sorted[k-1].e {
			vs = append(vs, ve(fmt.Sprintf("/payload/slots/%d", sorted[k].i), "R-2/overlap", "slots[%d] [%d,%d) 가 slots[%d] [%d,%d) 와 겹칩니다(04 §7.1 R-2).",
				sorted[k].i, sorted[k].s, sorted[k].e, sorted[k-1].i, sorted[k-1].s, sorted[k-1].e))
		}
	}
	return vs
}

func slotChecks(s map[string]any, base string, res int64) []Violation {
	var vs []Violation
	st, a := num(s, "start_min")
	en, b := num(s, "end_min")
	if a && b && st >= en {
		vs = append(vs, ve(base, "R-2/range", "start_min(%d) < end_min(%d) 이어야 합니다([start,end) 반열림, 자정 넘김 슬롯은 둘로 나눕니다).", st, en))
	}
	for _, k := range []string{"start_min", "end_min"} {
		if v, ok := num(s, k); ok && res > 0 && v%res != 0 {
			rule := "R-2/resolution"
			msg := fmt.Sprintf("%s=%d 가 schedule_resolution_min(%d분)의 배수가 아닙니다(04 §7.1 R-2).", k, v, res)
			if res == 5 {
				msg = fmt.Sprintf("%s=%d 가 5분의 배수가 아닙니다 — 슬롯 최소 단위는 5분입니다(01 §5.2). info 를 주면(--info) 신고 해상도로 검사합니다.", k, v)
			}
			vs = append(vs, ve(base+"/"+k, rule, "%s", msg))
		}
	}
	vs = append(vs, idlePower(s, base, "direction", "power_w")...)
	return vs
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// ---- response ---------------------------------------------------------------

func lintResponse(msg map[string]any) []Violation {
	var vs []Violation
	acc, okA := boolv(msg, "accepted")
	res, _ := str(msg, "result")
	if okA && acc && res != "" && res != "IN_PROGRESS" {
		vs = append(vs, ve("/result", "ack-state", "accepted=true 이면 result=\"IN_PROGRESS\" 입니다(01 §5.3)."))
	}
	if okA && !acc && res != "" && res != "FAILURE" {
		vs = append(vs, ve("/result", "ack-state", "accepted=false 이면 result=\"FAILURE\" 입니다(01 §5.3)."))
	}
	if okA && acc && has(msg, "failure_reason") {
		vs = append(vs, vw("/failure_reason", "ack-state", "accepted=true 인데 failure_reason 이 있습니다."))
	}
	mode, _ := str(msg, "mode")
	if mode == "IMMEDIATE" {
		vs = append(vs, idlePower(msg, "", "direction", "power_w")...)
		if has(msg, "slots_count") {
			vs = append(vs, vw("/slots_count", "readback", "IMMEDIATE ACK 에 slots_count 가 있습니다."))
		}
	}
	if mode == "SCHEDULE" && (has(msg, "direction") || has(msg, "power_w")) {
		vs = append(vs, vw("", "readback", "SCHEDULE ACK 의 readback 은 slots_count 입니다(direction·power_w 는 IMMEDIATE 용)."))
	}
	if has(msg, "payload") {
		vs = append(vs, ve("/payload", "flat", "response 는 평면 구조입니다. payload 래퍼를 쓰지 않습니다(01 §5.3)."))
	}
	if has(msg, "ingest_time") || has(msg, "event_time") {
		vs = append(vs, vw("", "flat", "response 에는 event_time·ingest_time 대신 received_at 을 씁니다(01 §2.3)."))
	}
	if !has(msg, "received_at") {
		vs = append(vs, vw("", "received-at", "received_at(수신·수락 시각)을 싣는 것을 권장합니다(01 §5.3)."))
	}
	return vs
}

// ---- result -----------------------------------------------------------------

func lintResult(msg map[string]any) []Violation {
	var vs []Violation
	p := obj(msg, "payload")
	r, _ := str(p, "result")
	vs = append(vs, idlePower(p, "/payload", "target_direction", "target_power_w")...)
	vs = append(vs, idlePower(p, "/payload", "reached_direction", "reached_power_w")...)
	td, _ := str(p, "target_direction")
	rd, _ := str(p, "reached_direction")
	tp, a := num(p, "target_power_w")
	rp, b := num(p, "reached_power_w")
	if r == "SUCCESS" {
		if td != "" && rd != "" && td != rd {
			vs = append(vs, ve("/payload/reached_direction", "achievement", "result=SUCCESS 인데 reached_direction(%s) ≠ target_direction(%s) 입니다(01 §4.2 달성 판정).", rd, td))
		}
		if a && b && tp > 0 {
			dev := float64(rp-tp) / float64(tp)
			if dev < 0 {
				dev = -dev
			}
			if dev > 0.05 {
				vs = append(vs, vw("/payload/reached_power_w", "achievement", "result=SUCCESS 인데 도달 오차 %.1f%% 가 5%% 를 넘습니다(01 §5.4).", dev*100))
			}
		}
		if td == "IDLE" && b && rp != 0 {
			vs = append(vs, ve("/payload/reached_power_w", "idle-zero", "IDLE 목표의 SUCCESS 는 실제 출력 0 을 보장해야 합니다(01 §4.2)."))
		}
	}
	if r == "PARTIAL" && len(arr(p, "pcs")) == 0 {
		vs = append(vs, vw("/payload", "partial-pcs", "PARTIAL 이면 pcs[] 로 PCS별 결과를 보고합니다(01 §4.2)."))
	}
	for i, it := range arr(p, "pcs") {
		pc, _ := it.(map[string]any)
		vs = append(vs, idlePower(pc, fmt.Sprintf("/payload/pcs/%d", i), "reached_direction", "reached_power_w")...)
	}
	if l, ok := num(p, "latency_ms"); ok && l > 120000 {
		vs = append(vs, vw("/payload/latency_ms", "latency", "latency_ms=%d — 제어신호 → 출력변화 시작은 2분 이내 요구입니다(01 §5.4).", l))
	}
	if !has(p, "soc_pct") {
		vs = append(vs, vi("/payload", "recommended", "soc_pct(발효 시점 SoC)는 권장 필드입니다."))
	}
	if !has(p, "latency_ms") {
		vs = append(vs, vi("/payload", "recommended", "latency_ms 는 권장 필드입니다(2분 기준 검증용)."))
	}
	return vs
}
