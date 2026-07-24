package validate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newT(t *testing.T) *Validator {
	t.Helper()
	v, err := New()
	if err != nil {
		t.Fatalf("New() 실패: %v", err)
	}
	return v
}

func read(t *testing.T, rel string) []byte {
	t.Helper()
	p := filepath.Join("..", "..", "testdata", "phase1", rel)
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("테스트 데이터 읽기 실패 %s: %v", p, err)
	}
	return data
}

// findViolation returns the first violation matching rule, or nil.
func findViolation(vs []Violation, rule string) *Violation {
	for i := range vs {
		if vs[i].Rule == rule {
			return &vs[i]
		}
	}
	return nil
}

func TestValidCases(t *testing.T) {
	v := newT(t)
	dir := filepath.Join("..", "..", "testdata", "phase1", "valid")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		count++
		name := e.Name()
		t.Run(name, func(t *testing.T) {
			data := read(t, filepath.Join("valid", name))
			res := v.ValidateBytes(name, data, Options{Profile: "phase1", Type: "auto"})
			if !res.OK {
				t.Fatalf("유효 파일이 실패로 판정됨. 위반: %+v", res.Violations)
			}
			for _, vi := range res.Violations {
				if vi.Level == LevelError {
					t.Fatalf("유효 파일에 error 위반 존재: %+v", vi)
				}
			}
		})
	}
	if count < 3 {
		t.Fatalf("유효 케이스가 3건 미만입니다: %d", count)
	}
}

// invalidCase declares the expected primary rule/level a file must trigger.
type invalidCase struct {
	file        string
	rule        string
	level       Level
	msgContains string // optional disambiguator for shared rules (e.g. required)
	typeFlag    string // override --type (default auto)
}

func TestInvalidCases(t *testing.T) {
	v := newT(t)
	cases := []invalidCase{
		{file: "uuid_uppercase.json", rule: RuleUUIDLower, level: LevelError},
		{file: "is_control_true.json", rule: RuleIsControlFalse, level: LevelError},
		{file: "stop_without_reason.json", rule: RuleRequired, level: LevelError, msgContains: "reason"},
		{file: "running_without_ac_power.json", rule: RuleRequired, level: LevelError, msgContains: "ac_power_w"},
		{file: "rtu_id_number.json", rule: RuleType, level: LevelError},
		{file: "rtu_id_badchars.json", rule: RulePattern, level: LevelError},
		{file: "event_time_iso.json", rule: RuleType, level: LevelError},
		{file: "schema_version_number.json", rule: RuleType, level: LevelError},
		{file: "ac_power_float.json", rule: RuleType, level: LevelError},
		{file: "inverters_empty.json", rule: RuleMinItems, level: LevelError},
		{file: "type_command.json", rule: RuleTypeControl, level: LevelError},
		{file: "info_missing_capacity.json", rule: RuleRequired, level: LevelError, msgContains: "capacity_w"},
	}

	if len(cases) < 12 {
		t.Fatalf("위반 케이스가 12건 미만입니다: %d", len(cases))
	}

	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			data := read(t, filepath.Join("invalid", c.file))
			typ := c.typeFlag
			if typ == "" {
				typ = "auto"
			}
			res := v.ValidateBytes(c.file, data, Options{Profile: "phase1", Type: typ})

			if res.OK {
				t.Fatalf("위반 파일이 통과로 판정됨. 위반목록: %+v", res.Violations)
			}
			got := findViolation(res.Violations, c.rule)
			if got == nil {
				t.Fatalf("기대 규칙 %q 위반이 없습니다. 실제: %+v", c.rule, res.Violations)
			}
			if got.Level != c.level {
				t.Fatalf("규칙 %q 의 level 불일치: 기대 %q, 실제 %q", c.rule, c.level, got.Level)
			}
			if c.msgContains != "" && !strings.Contains(got.Message, c.msgContains) {
				t.Fatalf("규칙 %q 메시지에 %q 가 없습니다: %q", c.rule, c.msgContains, got.Message)
			}
		})
	}
}

// TestStrictPromotesUnknownField verifies unknown fields warn by default and
// become errors under --strict (§9.4).
func TestStrictPromotesUnknownField(t *testing.T) {
	v := newT(t)
	doc := []byte(`{
      "schema_version":"1.0",
      "id":"3f2504e0-4f89-41d3-9a0c-0305e82c3301",
      "type":"telemetry",
      "rtu_id":"RTU-001",
      "event_time":1721600000000,
      "ingest_time":1721600000500,
      "typoField": 1,
      "payload":{"is_control":false,"inverters":[{"id":"INV-1","ac_power_w":10,"status":"RUN"}]}
    }`)

	base := v.ValidateBytes("x", doc, Options{Profile: "phase1", Type: "auto"})
	uf := findViolation(base.Violations, RuleUnknownField)
	if uf == nil {
		t.Fatalf("미지 필드 warn 이 없습니다: %+v", base.Violations)
	}
	if uf.Level != LevelWarn {
		t.Fatalf("기본 모드 미지 필드는 warn 이어야 합니다: %q", uf.Level)
	}
	if !base.OK {
		t.Fatalf("warn 만 있는 문서는 통과해야 합니다: %+v", base.Violations)
	}

	strict := v.ValidateBytes("x", doc, Options{Profile: "phase1", Type: "auto", Strict: true})
	sf := findViolation(strict.Violations, RuleUnknownField)
	if sf == nil || sf.Level != LevelError {
		t.Fatalf("--strict 에서 미지 필드는 error 여야 합니다: %+v", strict.Violations)
	}
	if strict.OK {
		t.Fatalf("--strict 에서 미지 필드가 있으면 실패해야 합니다")
	}
}

// TestMsHeuristic verifies seconds-granularity timestamps warn (§6.2).
func TestMsHeuristic(t *testing.T) {
	v := newT(t)
	doc := []byte(`{
      "schema_version":"1.0",
      "id":"3f2504e0-4f89-41d3-9a0c-0305e82c3301",
      "type":"telemetry",
      "rtu_id":"RTU-001",
      "event_time":1721600000,
      "ingest_time":1721600000500,
      "payload":{"is_control":false,"inverters":[{"id":"INV-1","ac_power_w":10,"status":"RUN"}]}
    }`)
	res := v.ValidateBytes("x", doc, Options{Profile: "phase1", Type: "auto"})
	h := findViolation(res.Violations, RuleMsHeuristic)
	if h == nil || h.Level != LevelWarn {
		t.Fatalf("초 단위 의심 warn 이 없습니다: %+v", res.Violations)
	}
	if !res.OK {
		t.Fatalf("warn 만으로는 실패하면 안 됩니다: %+v", res.Violations)
	}
}

// TestSchemaVersionWarn verifies non-1.0 schema_version warns (§8).
func TestSchemaVersionWarn(t *testing.T) {
	v := newT(t)
	doc := []byte(`{
      "schema_version":"2.0",
      "id":"3f2504e0-4f89-41d3-9a0c-0305e82c3301",
      "type":"telemetry",
      "rtu_id":"RTU-001",
      "event_time":1721600000000,
      "ingest_time":1721600000500,
      "payload":{"is_control":false,"inverters":[{"id":"INV-1","ac_power_w":10,"status":"RUN"}]}
    }`)
	res := v.ValidateBytes("x", doc, Options{Profile: "phase1", Type: "auto"})
	sv := findViolation(res.Violations, RuleSchemaVersion)
	if sv == nil || sv.Level != LevelWarn {
		t.Fatalf("schema_version warn 이 없습니다: %+v", res.Violations)
	}
}

// TestTypeMismatch verifies --type vs declared type mismatch (§6.5).
func TestTypeMismatch(t *testing.T) {
	v := newT(t)
	data := read(t, filepath.Join("valid", "telemetry_sample.json"))
	res := v.ValidateBytes("x", data, Options{Profile: "phase1", Type: "info"})
	if findViolation(res.Violations, RuleTypeMismatch) == nil {
		t.Fatalf("type-mismatch 위반이 없습니다: %+v", res.Violations)
	}
	if res.OK {
		t.Fatalf("type 불일치는 실패해야 합니다")
	}
}

func TestBadJSON(t *testing.T) {
	v := newT(t)
	res := v.ValidateBytes("x", []byte(`{not json`), Options{Profile: "phase1", Type: "auto"})
	if res.OK || findViolation(res.Violations, RuleJSONParse) == nil {
		t.Fatalf("JSON 파싱 오류가 보고되어야 합니다: %+v", res.Violations)
	}
}
