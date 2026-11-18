package validate

import (
	"fmt"
	"os"
	"strings"
)

// Context is the subset of an info message used by cross-message rules.
type Context struct {
	File           string
	RTUID          string
	ControlModes   map[string]bool
	Resolution     int64
	Capabilities   map[string]bool
	SocMin, SocMax int64
	HasSocLimits   bool
	OperationModes map[string]bool
	HasOpModes     bool
	PVCapacity     bool
	PCSIDs         map[string]bool
	RatedSum       int64
	PolarityGap    int64
	HasPolarityGap bool
}

// LoadContext reads and validates an info message file for use as context.
func LoadContext(v *Validator, path string) (*Context, *Result, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	r := v.ValidateBytes(path, b, Options{Type: TypeInfo})
	msg, err := Decode(b)
	if err != nil {
		return nil, &r, err
	}
	return ContextFromInfo(path, msg), &r, nil
}

// ContextFromInfo extracts the context from a decoded info message.
func ContextFromInfo(file string, msg map[string]any) *Context {
	c := &Context{File: file, ControlModes: map[string]bool{}, Capabilities: map[string]bool{},
		OperationModes: map[string]bool{}, PCSIDs: map[string]bool{}}
	c.RTUID, _ = str(msg, "rtu_id")
	p := obj(msg, "payload")
	for _, x := range arr(p, "control_modes") {
		if s, ok := x.(string); ok {
			c.ControlModes[s] = true
		}
	}
	c.Resolution, _ = num(p, "schedule_resolution_min")
	for _, x := range arr(p, "bms_capabilities") {
		if s, ok := x.(string); ok {
			c.Capabilities[s] = true
		}
	}
	var a, b bool
	c.SocMin, a = num(p, "soc_limit_min_pct")
	c.SocMax, b = num(p, "soc_limit_max_pct")
	c.HasSocLimits = a && b
	if e := obj(p, "ems"); e != nil {
		for _, x := range arr(e, "operation_modes") {
			if s, ok := x.(string); ok {
				c.OperationModes[s] = true
				c.HasOpModes = true
			}
		}
	}
	if pv := obj(p, "pv"); pv != nil && has(pv, "capacity_w") {
		c.PVCapacity = true
	}
	for _, x := range arr(p, "pcs") {
		pc, _ := x.(map[string]any)
		if id, ok := str(pc, "id"); ok {
			c.PCSIDs[id] = true
		}
		if r, ok := num(pc, "rated_power_w"); ok {
			c.RatedSum += r
		}
	}
	c.PolarityGap, c.HasPolarityGap = num(p, "min_polarity_gap_sec")
	return c
}

var capFields = []string{"avail_charge_w", "avail_discharge_w", "rack_total", "rack_online"}

func crossInfo(c *Context, typ string, msg map[string]any) []Violation {
	var vs []Violation
	if rid, ok := str(msg, "rtu_id"); ok && c.RTUID != "" && rid != c.RTUID && typ != TypeInfo {
		vs = append(vs, ve("/rtu_id", "ctx-rtu-id", "rtu_id=%q 가 --info 의 rtu_id=%q 와 다릅니다. 같은 자원의 메시지끼리 대조해야 합니다.", rid, c.RTUID))
	}
	p := obj(msg, "payload")
	switch typ {
	case TypeTelemetry:
		b := obj(p, "battery")
		for _, f := range capFields {
			declared, present := c.Capabilities[f], has(b, f)
			if declared && !present {
				vs = append(vs, ve("/payload/battery", "R-4", "info.bms_capabilities 에 %s 를 신고했는데 telemetry battery 에 없습니다(04 §7.1 R-4).", f))
			}
			if !declared && present {
				vs = append(vs, ve("/payload/battery/"+f, "R-4", "%s 는 info.bms_capabilities 에 신고하지 않은 항목입니다. 신고하지 않은 항목은 싣지 않아야 합니다(04 §7.1 R-4).", f))
			}
		}
		if c.PVCapacity && obj(p, "pv") == nil {
			vs = append(vs, ve("/payload", "R-5", "info.pv.capacity_w 를 신고한 자원은 telemetry 에 pv 블록이 필수입니다(04 §7.1 R-5)."))
		}
		if e := obj(p, "ems"); e != nil {
			if om, ok := str(e, "operation_mode"); ok {
				if !c.HasOpModes {
					vs = append(vs, vw("/payload/ems", "R-9", "telemetry 에 ems.operation_mode 가 있지만 info.ems.operation_modes 를 신고하지 않았습니다."))
				} else if !c.OperationModes[om] {
					vs = append(vs, ve("/payload/ems/operation_mode", "R-9", "operation_mode=%q 가 info.ems.operation_modes 에 신고한 값이 아닙니다(04 §7.1 R-9).", om))
				}
			}
		}
		for i, it := range arr(p, "pcs") {
			pc, _ := it.(map[string]any)
			if id, ok := str(pc, "id"); ok && len(c.PCSIDs) > 0 && !c.PCSIDs[id] {
				vs = append(vs, ve(fmt.Sprintf("/payload/pcs/%d/id", i), "ctx-pcs-id", "pcs id %q 가 info.pcs[] 에 없습니다. telemetry 와 info 의 PCS id 는 같아야 합니다.", id))
			}
		}
		if len(c.PCSIDs) > 0 && len(arr(p, "pcs")) < len(c.PCSIDs) {
			vs = append(vs, vw("/payload/pcs", "ctx-pcs-count", "info 에 PCS %d 대를 신고했는데 telemetry 에는 %d 대만 있습니다.", len(c.PCSIDs), len(arr(p, "pcs"))))
		}
		var sum int64
		for _, it := range arr(p, "pcs") {
			pc, _ := it.(map[string]any)
			if pw, ok := num(pc, "power_w"); ok {
				sum += pw
			}
		}
		if c.RatedSum > 0 && sum > c.RatedSum {
			vs = append(vs, ve("/payload/pcs", "ctx-rating", "PCS 전력 합 %d W 가 info PCS 정격 합 %d W 를 넘습니다.", sum, c.RatedSum))
		}
		if b != nil {
			for _, f := range []string{"avail_charge_w", "avail_discharge_w"} {
				if v, ok := num(b, f); ok && c.RatedSum > 0 && v > c.RatedSum {
					vs = append(vs, vw("/payload/battery/"+f, "ctx-rating", "%s=%d W 가 PCS 정격 합 %d W 보다 큽니다. 실제 가용 상한은 min(avail, Σ정격)으로 판정됩니다(01 §5.1).", f, v, c.RatedSum))
				}
			}
		}
	case TypeCommand:
		mode, _ := str(p, "mode")
		if mode != "" && len(c.ControlModes) > 0 && !c.ControlModes[mode] {
			vs = append(vs, ve("/payload/mode", "ctx-control-mode", "mode=%s 는 info.control_modes 에 없습니다. EMS 는 failure_reason=UNSUPPORTED_CONTROL 로 거부합니다(01 §6).", mode))
		}
		if mode == "SCHEDULE" && c.Resolution > 5 {
			for i, it := range arr(p, "slots") {
				s, _ := it.(map[string]any)
				for _, k := range []string{"start_min", "end_min"} {
					if v, ok := num(s, k); ok && v%5 == 0 && v%c.Resolution != 0 {
						vs = append(vs, ve(fmt.Sprintf("/payload/slots/%d/%s", i, k), "R-2/resolution", "%s=%d 가 info.schedule_resolution_min(%d분)의 배수가 아닙니다(04 §7.1 R-2) → BAD_REQUEST.", k, v, c.Resolution))
					}
				}
			}
		}
		if c.HasSocLimits {
			for _, k := range []string{"soc_min_pct", "soc_max_pct"} {
				if v, ok := num(p, k); ok && (v < c.SocMin || v > c.SocMax) {
					vs = append(vs, ve("/payload/"+k, "R-6", "%s=%d 가 info 등록 SoC 한계 [%d, %d] 를 벗어납니다 → BAD_REQUEST(04 §7.1 R-6).", k, v, c.SocMin, c.SocMax))
				}
			}
		}
		if c.RatedSum > 0 {
			if pw, ok := num(p, "power_w"); ok && pw > c.RatedSum {
				vs = append(vs, ve("/payload/power_w", "ctx-power-limit", "power_w=%d 가 PCS 정격 합 %d 를 넘습니다 → POWER_LIMIT_EXCEEDED(01 §6).", pw, c.RatedSum))
			}
			for i, it := range arr(p, "slots") {
				s, _ := it.(map[string]any)
				if pw, ok := num(s, "power_w"); ok && pw > c.RatedSum {
					vs = append(vs, ve(fmt.Sprintf("/payload/slots/%d/power_w", i), "ctx-power-limit", "슬롯 power_w=%d 가 PCS 정격 합 %d 를 넘습니다.", pw, c.RatedSum))
				}
			}
		}
		if ov, ok := boolv(p, "override_polarity_gap"); ok && ov && !c.HasPolarityGap {
			vs = append(vs, vi("/payload/override_polarity_gap", "polarity-noop", "info.min_polarity_gap_sec 미신고 자원이므로 override_polarity_gap 은 no-op 입니다(01 §5.1)."))
		}
	case TypeInfo:
		// nothing: info is the context itself
	}
	return vs
}

// Command is the originating command used to check response/result readback.
type Command struct {
	File                  string
	ID                    string
	RTUID                 string
	Mode                  string
	Dir                   string
	Power                 int64
	HasPw                 bool
	Slots                 int
	Override, HasOverride bool
}

// CommandFromMsg extracts readback expectations from a decoded command.
func CommandFromMsg(file string, msg map[string]any) *Command {
	c := &Command{File: file}
	c.ID, _ = str(msg, "id")
	c.RTUID, _ = str(msg, "rtu_id")
	p := obj(msg, "payload")
	c.Mode, _ = str(p, "mode")
	c.Dir, _ = str(p, "direction")
	c.Power, c.HasPw = num(p, "power_w")
	c.Slots = len(arr(p, "slots"))
	c.Override, c.HasOverride = boolv(p, "override_polarity_gap")
	return c
}

func crossCommand(c *Command, typ string, msg map[string]any) []Violation {
	var vs []Violation
	var req string
	var base string
	var m map[string]any
	if typ == TypeResponse {
		m, base = msg, ""
	} else {
		m, base = obj(msg, "payload"), "/payload"
	}
	req, _ = str(m, "req_id")
	if req != "" && !strings.EqualFold(req, c.ID) {
		vs = append(vs, ve(base+"/req_id", "ctx-req-id", "req_id=%q 가 대상 명령 id=%q 와 다릅니다.", req, c.ID))
	} else if req != "" && req != c.ID {
		vs = append(vs, vw(base+"/req_id", "ctx-req-id", "req_id 표기가 명령 id 와 대소문자만 다릅니다. verbatim 으로 실으십시오(01 §2.4)."))
	}
	if rid, ok := str(msg, "rtu_id"); ok && rid != c.RTUID {
		vs = append(vs, ve("/rtu_id", "ctx-rtu-id", "rtu_id=%q 가 명령의 rtu_id=%q 와 다릅니다.", rid, c.RTUID))
	}
	if typ == TypeResponse {
		if acc, _ := boolv(msg, "accepted"); acc {
			if md, ok := str(msg, "mode"); ok && md != c.Mode {
				vs = append(vs, ve("/mode", "readback", "readback mode=%s ≠ 명령 mode=%s", md, c.Mode))
			}
			if c.Mode == "IMMEDIATE" {
				if d, ok := str(msg, "direction"); ok && d != c.Dir {
					vs = append(vs, ve("/direction", "readback", "readback direction=%s ≠ 명령 direction=%s — 파싱 오류 의심(01 §5.3).", d, c.Dir))
				}
				if pw, ok := num(msg, "power_w"); ok && c.HasPw && pw != c.Power {
					vs = append(vs, ve("/power_w", "readback", "readback power_w=%d ≠ 명령 power_w=%d — 단위·파싱 오류 의심(01 §5.3).", pw, c.Power))
				}
			}
			if c.Mode == "SCHEDULE" {
				if n, ok := num(msg, "slots_count"); ok && int(n) != c.Slots {
					vs = append(vs, ve("/slots_count", "readback", "readback slots_count=%d ≠ 명령 슬롯 수 %d", n, c.Slots))
				}
			}
		}
		return vs
	}
	// result
	p := m
	if c.Mode == "IMMEDIATE" {
		if d, ok := str(p, "target_direction"); ok && d != c.Dir {
			vs = append(vs, ve("/payload/target_direction", "readback", "target_direction=%s ≠ 명령 direction=%s", d, c.Dir))
		}
		if pw, ok := num(p, "target_power_w"); ok && c.HasPw && pw != c.Power {
			vs = append(vs, ve("/payload/target_power_w", "readback", "target_power_w=%d ≠ 명령 power_w=%d", pw, c.Power))
		}
	}
	ov, hasOv := boolv(p, "override_polarity_gap")
	if c.HasOverride && c.Override && (!hasOv || !ov) {
		vs = append(vs, ve("/payload/override_polarity_gap", "R-8", "명령이 override_polarity_gap=true 로 수행됐으면 result 에 override_polarity_gap=true 를 되읽기해야 합니다(04 §7.1 R-8, 감사 추적)."))
	}
	if c.HasOverride && hasOv && ov != c.Override {
		vs = append(vs, ve("/payload/override_polarity_gap", "R-8", "readback override_polarity_gap=%v ≠ 명령 값 %v", ov, c.Override))
	}
	if !c.HasOverride && hasOv && ov {
		vs = append(vs, ve("/payload/override_polarity_gap", "R-8", "명령에 없던 override_polarity_gap=true 를 보고했습니다."))
	}
	return vs
}
