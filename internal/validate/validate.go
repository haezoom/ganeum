// Package validate compiles the embedded Phase1 schemas and runs both JSON
// Schema validation and 가늠 (ganeum) specific lint rules against telemetry /
// info payloads.
package validate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/haezoom/ganeum/internal/schema"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

// enPrinter renders the library's fallback LocalizedString for kinds we do not
// map explicitly.
var enPrinter = message.NewPrinter(language.English)

// Level is the severity of a violation.
type Level string

const (
	LevelError Level = "error"
	LevelWarn  Level = "warn"
)

// Rule identifiers surfaced to callers and asserted by tests.
const (
	RuleSchema         = "schema"
	RuleType           = "type"
	RuleRequired       = "required"
	RulePattern        = "pattern"
	RuleMinItems       = "min-items"
	RuleMaxItems       = "max-items"
	RuleEnum           = "enum"
	RuleConst          = "const"
	RuleMinimum        = "minimum"
	RuleMaxLength      = "max-length"
	RuleJSONParse      = "json-parse"
	RuleUUIDLower      = "uuid-lowercase"
	RuleIsControlFalse = "is-control-false"
	RuleTypeControl    = "type-controlplane"
	RuleTypeMismatch   = "type-mismatch"
	RuleTypeMissing    = "type-missing"
	RuleUnknownField   = "unknown-field"
	RuleMsHeuristic    = "ms-heuristic"
	RuleSchemaVersion  = "schema-version"
)

// Violation is a single validation finding.
type Violation struct {
	Path    string `json:"path"`
	Rule    string `json:"rule"`
	Level   Level  `json:"level"`
	Message string `json:"message"`
}

// Result is the outcome for one input document.
type Result struct {
	File       string      `json:"file"`
	OK         bool        `json:"ok"`
	Type       string      `json:"type"`
	Violations []Violation `json:"violations"`
}

// Options controls a validation run.
type Options struct {
	Profile string // currently only "phase1"
	Type    string // "telemetry" | "info" | "auto" (or "")
	Strict  bool
}

// Validator holds the compiled Phase1 profile schemas.
type Validator struct {
	telemetry *jsonschema.Schema
	info      *jsonschema.Schema
}

var (
	uuidLowerRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	uuidAnyRe   = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// msMinValid is the lower bound (exclusive) for a plausible millisecond epoch.
// A 13-digit ms timestamp for the current era is ~1.7e12; anything below 1e12
// looks like a seconds-granularity value and is flagged (온보딩 §6.2).
const msMinValid int64 = 1_000_000_000_000

// New compiles the embedded schemas into a ready-to-use Validator.
func New() (*Validator, error) {
	c := jsonschema.NewCompiler()
	for _, res := range schema.Resources() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(res.Data))
		if err != nil {
			return nil, fmt.Errorf("스키마 파싱 실패 %s: %w", res.ID, err)
		}
		if err := c.AddResource(res.ID, doc); err != nil {
			return nil, fmt.Errorf("스키마 등록 실패 %s: %w", res.ID, err)
		}
	}
	tel, err := c.Compile(schema.TelemetryID)
	if err != nil {
		return nil, fmt.Errorf("telemetry 스키마 컴파일 실패: %w", err)
	}
	inf, err := c.Compile(schema.InfoID)
	if err != nil {
		return nil, fmt.Errorf("info 스키마 컴파일 실패: %w", err)
	}
	return &Validator{telemetry: tel, info: inf}, nil
}

// ValidateBytes validates a single JSON document.
func (v *Validator) ValidateBytes(file string, data []byte, opt Options) Result {
	res := Result{File: file, Violations: []Violation{}}

	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		res.Violations = append(res.Violations, Violation{
			Path:    "",
			Rule:    RuleJSONParse,
			Level:   LevelError,
			Message: fmt.Sprintf("JSON 파싱에 실패했습니다: %v", err),
		})
		res.OK = false
		return res
	}

	msg, _ := inst.(map[string]any)
	if msg == nil {
		res.Violations = append(res.Violations, Violation{
			Path:    "",
			Rule:    RuleType,
			Level:   LevelError,
			Message: "최상위 값이 JSON 객체가 아닙니다.",
		})
		res.OK = false
		return res
	}

	declared, _ := msg["type"].(string)
	res.Type = declared

	profile, halt, typeViolations := v.resolveProfile(declared, opt)
	res.Violations = append(res.Violations, typeViolations...)
	if halt {
		res.OK = !hasError(res.Violations)
		return res
	}

	// JSON Schema validation against the resolved profile.
	sch := v.telemetry
	if profile == "info" {
		sch = v.info
	}
	if serr := sch.Validate(inst); serr != nil {
		if verr, ok := serr.(*jsonschema.ValidationError); ok {
			res.Violations = append(res.Violations, mapSchemaErrors(verr)...)
		} else {
			res.Violations = append(res.Violations, Violation{
				Rule: RuleSchema, Level: LevelError, Message: serr.Error(),
			})
		}
	}

	// 가늠 고유 린트 (schema 통과와 별개).
	res.Violations = append(res.Violations, lint(msg, profile, opt.Strict)...)

	res.OK = !hasError(res.Violations)
	return res
}

// resolveProfile decides which schema to validate against and emits type-plane
// violations. halt=true means no schema validation should follow.
func (v *Validator) resolveProfile(declared string, opt Options) (profile string, halt bool, vs []Violation) {
	known := declared == "telemetry" || declared == "info"
	controlPlane := declared != "" && !known

	want := opt.Type
	if want == "" {
		want = "auto"
	}

	if controlPlane {
		vs = append(vs, Violation{
			Path:  "/type",
			Rule:  RuleTypeControl,
			Level: LevelError,
			Message: fmt.Sprintf(
				"type=%q 는 제어평면(command·result·keys 등) 값입니다. Phase1 프로필은 telemetry·info 만 허용합니다.", declared),
		})
		return "", true, vs
	}

	if want == "auto" {
		if declared == "" {
			vs = append(vs, Violation{
				Path:    "/type",
				Rule:    RuleTypeMissing,
				Level:   LevelError,
				Message: "type 필드가 없어 프로필을 자동 판별할 수 없습니다. --type telemetry|info 로 지정하세요.",
			})
			return "", true, vs
		}
		return declared, false, vs
	}

	// Explicit --type telemetry|info.
	profile = want
	if declared != "" && declared != profile {
		vs = append(vs, Violation{
			Path:  "/type",
			Rule:  RuleTypeMismatch,
			Level: LevelError,
			Message: fmt.Sprintf(
				"선언된 type=%q 가 지정한 --type=%q 와 일치하지 않습니다.", declared, profile),
		})
	}
	return profile, false, vs
}

// lint runs the 가늠 specific checks that live outside (or complement) the schema.
func lint(msg map[string]any, profile string, strict bool) []Violation {
	var vs []Violation

	// schema_version != "1.0" → warn (§8).
	if sv, ok := msg["schema_version"].(string); ok && sv != "1.0" {
		vs = append(vs, Violation{
			Path:    "/schema_version",
			Rule:    RuleSchemaVersion,
			Level:   LevelWarn,
			Message: fmt.Sprintf("schema_version=%q 는 현재 배포 세트(v1.0)와 다릅니다.", sv),
		})
	}

	// event_time / ingest_time seconds-granularity heuristic → warn (§6.2).
	for _, f := range []string{"event_time", "ingest_time"} {
		if n, ok := msg[f].(json.Number); ok {
			if i, err := n.Int64(); err == nil && i > 0 && i < msMinValid {
				vs = append(vs, Violation{
					Path:  "/" + f,
					Rule:  RuleMsHeuristic,
					Level: LevelWarn,
					Message: fmt.Sprintf(
						"%s=%s 는 자릿수로 보아 초 단위로 의심됩니다. 표준은 밀리초(ms) 정수를 요구합니다.", f, n.String()),
				})
			}
		}
	}

	// req_id UUID lowercase (id 는 스키마 uuidLower 가 담당, req_id 는 코드가 담당).
	if rid, ok := msg["req_id"].(string); ok {
		if uuidAnyRe.MatchString(rid) && !uuidLowerRe.MatchString(rid) {
			vs = append(vs, Violation{
				Path:    "/req_id",
				Rule:    RuleUUIDLower,
				Level:   LevelError,
				Message: fmt.Sprintf("req_id=%q 에 대문자가 포함되어 있습니다. UUID는 소문자만 허용됩니다(온보딩 §3.3).", rid),
			})
		}
	}

	// telemetry: is_control 은 반드시 false (§6.5).
	if profile == "telemetry" {
		if payload, ok := msg["payload"].(map[string]any); ok {
			if ic, exists := payload["is_control"]; exists {
				if b, ok := ic.(bool); ok && b {
					vs = append(vs, Violation{
						Path:    "/payload/is_control",
						Rule:    RuleIsControlFalse,
						Level:   LevelError,
						Message: "Phase1 telemetry 의 is_control 은 반드시 false 여야 합니다(§6.5).",
					})
				}
			}
		}
	}

	// 알 수 없는 추가 필드 (warn, --strict 시 error).
	vs = append(vs, unknownFields(msg, profile, strict)...)

	return vs
}

var topLevelProps = map[string]bool{
	"schema_version": true, "id": true, "type": true, "rtu_id": true,
	"event_time": true, "ingest_time": true, "seq": true, "payload": true,
}

var telemetryPayloadProps = map[string]bool{
	"is_control": true, "inverters": true, "pulse_energy_wh": true,
}
var telemetryInverterProps = map[string]bool{
	"id": true, "ac_power_w": true, "energy_wh": true,
	"status": true, "reason": true, "reason_text": true,
}
var infoPayloadProps = map[string]bool{
	"model": true, "firmware": true, "control_type": true,
	"interval_sec": true, "inverters": true,
}
var infoInverterProps = map[string]bool{
	"id": true, "model": true, "capacity_w": true,
}

func unknownFields(msg map[string]any, profile string, strict bool) []Violation {
	level := LevelWarn
	if strict {
		level = LevelError
	}
	var vs []Violation

	mk := func(path, key string) Violation {
		return Violation{
			Path:  path,
			Rule:  RuleUnknownField,
			Level: level,
			Message: fmt.Sprintf(
				"알 수 없는 필드 %q 입니다. 서버는 미지 필드를 무시하지만 오타일 수 있습니다(§9.4).", key),
		}
	}

	for k := range msg {
		if !topLevelProps[k] {
			vs = append(vs, mk("/"+k, k))
		}
	}

	payload, ok := msg["payload"].(map[string]any)
	if !ok {
		return vs
	}

	var payloadProps, inverterProps map[string]bool
	switch profile {
	case "telemetry":
		payloadProps, inverterProps = telemetryPayloadProps, telemetryInverterProps
	case "info":
		payloadProps, inverterProps = infoPayloadProps, infoInverterProps
	default:
		return vs
	}

	for k := range payload {
		if !payloadProps[k] {
			vs = append(vs, mk("/payload/"+k, k))
		}
	}

	if invs, ok := payload["inverters"].([]any); ok {
		for i, item := range invs {
			obj, ok := item.(map[string]any)
			if !ok {
				continue
			}
			for k := range obj {
				if !inverterProps[k] {
					vs = append(vs, mk(fmt.Sprintf("/payload/inverters/%d/%s", i, k), k))
				}
			}
		}
	}

	return vs
}

// mapSchemaErrors flattens a jsonschema ValidationError tree into leaf-level
// 가늠 violations, mapping keyword kinds to stable rule ids and Korean messages.
func mapSchemaErrors(root *jsonschema.ValidationError) []Violation {
	var out []Violation
	var walk func(e *jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(e.Causes) > 0 {
			for _, c := range e.Causes {
				walk(c)
			}
			return
		}
		if v, keep := violationFromLeaf(e); keep {
			out = append(out, v)
		}
	}
	walk(root)
	return out
}

func violationFromLeaf(e *jsonschema.ValidationError) (Violation, bool) {
	loc := e.InstanceLocation
	path := jsonPointer(loc)

	// The 'type' field is fully owned by the type-plane logic in resolveProfile;
	// suppress schema-level type/const/enum errors located exactly at /type.
	if len(loc) == 1 && loc[0] == "type" {
		return Violation{}, false
	}

	rule, level, msg := classifyKind(e.ErrorKind, loc)
	return Violation{Path: path, Rule: rule, Level: level, Message: msg}, true
}

func classifyKind(k jsonschema.ErrorKind, loc []string) (string, Level, string) {
	switch kk := k.(type) {
	case *kind.Type:
		return RuleType, LevelError, fmt.Sprintf(
			"타입이 올바르지 않습니다: 실제 %s, 기대 %s.", kk.Got, strings.Join(kk.Want, " 또는 "))
	case *kind.Required:
		return RuleRequired, LevelError, fmt.Sprintf(
			"필수 필드가 없습니다: %s.", strings.Join(kk.Missing, ", "))
	case *kind.Pattern:
		// pattern failure on the top-level /id is the lowercase-UUID rule.
		if len(loc) == 1 && loc[0] == "id" {
			return RuleUUIDLower, LevelError, fmt.Sprintf(
				"id=%q 가 소문자 UUID 형식이 아닙니다. 대문자 UUID는 규약 위반입니다(온보딩 §3.3).", kk.Got)
		}
		return RulePattern, LevelError, fmt.Sprintf(
			"값 %q 가 허용 패턴 %q 을 만족하지 않습니다.", kk.Got, kk.Want)
	case *kind.MinItems:
		return RuleMinItems, LevelError, fmt.Sprintf(
			"배열 항목 수가 부족합니다: 실제 %d, 최소 %d.", kk.Got, kk.Want)
	case *kind.MaxItems:
		return RuleMaxItems, LevelError, fmt.Sprintf(
			"배열 항목 수가 초과했습니다: 실제 %d, 최대 %d.", kk.Got, kk.Want)
	case *kind.Enum:
		return RuleEnum, LevelError, "허용되지 않은 열거값입니다."
	case *kind.Const:
		return RuleConst, LevelError, "허용되지 않은 고정값(const) 입니다."
	case *kind.Minimum:
		return RuleMinimum, LevelError, "허용 최소값보다 작습니다."
	case *kind.MaxLength:
		return RuleMaxLength, LevelError, "허용 최대 길이를 초과했습니다."
	default:
		return RuleSchema, LevelError, k.LocalizedString(enPrinter)
	}
}

func hasError(vs []Violation) bool {
	for _, v := range vs {
		if v.Level == LevelError {
			return true
		}
	}
	return false
}

// jsonPointer renders instance-location segments (RFC 6901).
func jsonPointer(loc []string) string {
	if len(loc) == 0 {
		return ""
	}
	var b strings.Builder
	for _, seg := range loc {
		b.WriteByte('/')
		seg = strings.ReplaceAll(seg, "~", "~0")
		seg = strings.ReplaceAll(seg, "/", "~1")
		b.WriteString(seg)
	}
	return b.String()
}
