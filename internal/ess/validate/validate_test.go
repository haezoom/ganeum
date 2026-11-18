package validate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func mustNew(t *testing.T) *Validator {
	t.Helper()
	v, err := New()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestValidSamples(t *testing.T) {
	v := mustNew(t)
	files, _ := filepath.Glob("../../../testdata/ess/valid/*.json")
	if len(files) < 8 {
		t.Fatalf("valid 샘플 부족: %d", len(files))
	}
	for _, f := range files {
		b, _ := os.ReadFile(f)
		r := v.ValidateBytes(f, b, Options{Strict: true})
		if !r.OK {
			t.Errorf("%s: %+v", f, r.Violations)
		}
	}
}

func TestInvalidManifest(t *testing.T) {
	v := mustNew(t)
	mb, err := os.ReadFile("../../../testdata/ess/invalid_manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var man map[string]struct {
		Rule string `json:"expect_rule"`
		Desc string `json:"desc"`
	}
	if err := json.Unmarshal(mb, &man); err != nil {
		t.Fatal(err)
	}
	for name, c := range man {
		b, err := os.ReadFile("../../../testdata/ess/invalid/" + name)
		if err != nil {
			t.Fatal(err)
		}
		r := v.ValidateBytes(name, b, Options{Strict: true})
		if r.OK {
			t.Errorf("%s (%s): 통과하면 안 됨", name, c.Desc)
			continue
		}
		found := false
		for _, x := range r.Violations {
			if x.Rule == c.Rule {
				found = true
			}
		}
		if !found {
			t.Errorf("%s (%s): 기대 규칙 %s 없음 → %+v", name, c.Desc, c.Rule, r.Violations)
		}
	}
}

func load(t *testing.T, name string) []byte {
	b, err := os.ReadFile("../../../testdata/ess/valid/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCrossInfo(t *testing.T) {
	v := mustNew(t)
	small, _ := Decode(load(t, "info_small.json"))
	ctx := ContextFromInfo("info_small", small)
	r := v.ValidateBytes("t", load(t, "telemetry.json"), Options{Info: ctx})
	want := map[string]bool{"R-4": false, "ctx-rtu-id": false, "ctx-rating": false}
	for _, x := range r.Violations {
		if _, ok := want[x.Rule]; ok {
			want[x.Rule] = true
		}
	}
	for k, ok := range want {
		if !ok {
			t.Errorf("규칙 %s 미검출", k)
		}
	}
	r = v.ValidateBytes("c", load(t, "command_schedule.json"), Options{Info: ctx})
	found := false
	for _, x := range r.Violations {
		if x.Rule == "ctx-control-mode" {
			found = true
		}
	}
	if !found {
		t.Error("SCHEDULE 미지원 자원에 SCHEDULE 명령 미검출")
	}
}

func TestResolutionAndSocRange(t *testing.T) {
	v := mustNew(t)
	info, _ := Decode(load(t, "info.json"))
	info["payload"].(map[string]any)["schedule_resolution_min"] = json.Number("60")
	info["payload"].(map[string]any)["soc_limit_min_pct"] = json.Number("20")
	ctx := ContextFromInfo("info", info)
	cmd, _ := Decode(load(t, "command_schedule.json"))
	cmd["payload"].(map[string]any)["slots"].([]any)[1].(map[string]any)["start_min"] = json.Number("1095")
	cb, _ := json.Marshal(cmd)
	r := v.ValidateBytes("c", cb, Options{Info: ctx})
	rules := map[string]bool{}
	for _, x := range r.Violations {
		rules[x.Rule] = true
	}
	if !rules["R-2/resolution"] {
		t.Error("60분 해상도 위반(1095분) 미검출")
	}
	if !rules["R-6"] {
		t.Error("soc_min_pct=10 < 등록 하한 20 미검출")
	}
}

func TestReadbackAndR8(t *testing.T) {
	v := mustNew(t)
	cmd, _ := Decode(load(t, "command_immediate.json"))
	cmd["payload"].(map[string]any)["override_polarity_gap"] = true
	c := CommandFromMsg("cmd", cmd)
	r := v.ValidateBytes("result", load(t, "result.json"), Options{Command: c})
	ok := false
	for _, x := range r.Violations {
		if x.Rule == "R-8" {
			ok = true
		}
	}
	if !ok {
		t.Error("override=true 명령 결과에 readback 누락 미검출(R-8)")
	}
	resp, _ := Decode(load(t, "response.json"))
	resp["power_w"] = json.Number("20000")
	b, _ := json.Marshal(resp)
	r = v.ValidateBytes("resp", b, Options{Command: c})
	ok = false
	for _, x := range r.Violations {
		if x.Rule == "readback" {
			ok = true
		}
	}
	if !ok {
		t.Error("readback power_w 불일치 미검출")
	}
}

func TestTopic(t *testing.T) {
	v := mustNew(t)
	r := v.ValidateBytes("t", load(t, "telemetry.json"), Options{Topic: "v1/vendor1/ESS-1/info"})
	if r.OK {
		t.Fatal("토픽·type 불일치 통과")
	}
	r = v.ValidateBytes("t", load(t, "response.json"), Options{Topic: "v1/vendor1/ESS-1/command/response"})
	if !r.OK {
		t.Fatalf("정상 토픽 거부: %+v", r.Violations)
	}
}
