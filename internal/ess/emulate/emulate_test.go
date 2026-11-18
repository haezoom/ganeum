package emulate

import (
	"os"
	"testing"

	"github.com/haezoom/ganeum/internal/ess/control"
	"github.com/haezoom/ganeum/internal/ess/golden"
	"github.com/haezoom/ganeum/internal/ess/validate"
	"io/fs"
)

func setup(t *testing.T) (*validate.Validator, control.Keyring, *validate.Context, map[string]any) {
	v, err := validate.New()
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := fs.ReadFile(golden.Embedded(), "keys/keystore.json")
	ring, err := control.ParseKeystore(kb)
	if err != nil {
		t.Fatal(err)
	}
	ib, _ := os.ReadFile("../../../testdata/ess/valid/info.json")
	im, _ := validate.Decode(ib)
	tb, _ := os.ReadFile("../../../testdata/ess/valid/telemetry.json")
	tm, _ := validate.Decode(tb)
	return v, ring, validate.ContextFromInfo("info", im), tm
}

func reason(o *Outcome) string {
	s, _ := o.Response["failure_reason"].(string)
	return s
}

func TestDecisions(t *testing.T) {
	v, ring, ctx, tele := setup(t)
	cmd, _ := os.ReadFile("../../../testdata/ess/valid/command_immediate.json")
	sched, _ := os.ReadFile("../../../testdata/ess/valid/command_schedule.json")

	o, _ := Decide(v, cmd, ring, ctx, tele, State{})
	if acc, _ := o.Response["accepted"].(bool); !acc {
		t.Fatalf("정상 명령 거부: %+v", o.Trace)
	}
	// 생성 ACK 가 response 스키마를 통과해야 한다
	b, _ := validateJSON(o.Response)
	if r := v.ValidateBytes("ack", b, validate.Options{Type: "response"}); !r.OK {
		t.Fatalf("생성 ACK 가 스키마 위반: %+v", r.Violations)
	}
	if o, _ := Decide(v, cmd, ring, ctx, tele, State{NowMs: 1794970000000}); reason(o) != "BAD_REQUEST" {
		t.Fatal("만료 미검출")
	}
	if o, _ := Decide(v, cmd, ring, ctx, tele, State{NowMs: 1781000001000, LastPolarity: "CHARGE", LastPolarityAtMs: 1781000000000}); reason(o) != "BAD_REQUEST" {
		t.Fatal("극성 휴지 미검출")
	}
	if o, _ := Decide(v, cmd, control.Keyring{}, ctx, tele, State{}); reason(o) != "PERMISSION_DENIED" {
		t.Fatal("미지 kid 미검출")
	}
	small := *ctx
	small.ControlModes = map[string]bool{"IMMEDIATE": true}
	if o, _ := Decide(v, sched, ring, &small, nil, State{}); reason(o) != "UNSUPPORTED_CONTROL" {
		t.Fatal("UNSUPPORTED_CONTROL 미검출")
	}
	tele["payload"].(map[string]any)["battery"].(map[string]any)["avail_discharge_w"] = 100000
	if o, _ := Decide(v, cmd, ring, ctx, tele, State{}); reason(o) != "POWER_LIMIT_EXCEEDED" {
		t.Fatal("가용 출력 초과 미검출")
	}
	tele["payload"].(map[string]any)["ems"].(map[string]any)["operation_mode"] = "LOCAL"
	if o, _ := Decide(v, cmd, ring, ctx, tele, State{}); reason(o) != "LOCAL_MODE" {
		t.Fatal("LOCAL_MODE 미검출")
	}
}
