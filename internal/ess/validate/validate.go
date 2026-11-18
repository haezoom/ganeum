// Package validate checks ESS v0.2 messages (telemetry·info·command·response·
// result) against the embedded JSON Schemas (04 §1~§6) and the rules the
// schema cannot express (04 §7.1 R-1~R-12, 01 §2·§3·§5). Cross-message rules
// run when an info message (--info) or the originating command (--command)
// is supplied as context.
package validate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/haezoom/ganeum/internal/ess/schema"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

var enPrinter = message.NewPrinter(language.English)

// Level is a violation severity.
type Level string

const (
	LevelError Level = "error"
	LevelWarn  Level = "warn"
	LevelInfo  Level = "info"
)

// Message types (MQTT topic last segment ↔ type, 04 §0).
const (
	TypeTelemetry = "telemetry"
	TypeInfo      = "info"
	TypeCommand   = "command"
	TypeResponse  = "response"
	TypeResult    = "result"
)

// AllTypes in topic order.
var AllTypes = []string{TypeTelemetry, TypeInfo, TypeCommand, TypeResponse, TypeResult}

// Violation is one finding.
type Violation struct {
	Path    string `json:"path"`
	Rule    string `json:"rule"`
	Level   Level  `json:"level"`
	Message string `json:"message"`
}

// Result is the outcome for one document.
type Result struct {
	File       string      `json:"file"`
	OK         bool        `json:"ok"`
	Type       string      `json:"type"`
	Mode       string      `json:"mode,omitempty"`
	Violations []Violation `json:"violations"`
}

// Options controls one run.
type Options struct {
	Type    string   // auto|telemetry|info|command|response|result
	Topic   string   // optional MQTT topic the payload was (or will be) published on
	Strict  bool     // warn → error
	Info    *Context // optional info context for cross rules
	Command *Command // optional originating command for response/result
}

// Validator holds compiled schemas.
type Validator struct {
	schemas map[string]*jsonschema.Schema
	known   map[string]*propTree
}

// New compiles the embedded ESS schemas.
func New() (*Validator, error) {
	res, err := schema.Resources()
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	raw := map[string]any{}
	for _, r := range res {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(r.Data))
		if err != nil {
			return nil, fmt.Errorf("스키마 파싱 실패 %s: %w", r.ID, err)
		}
		if err := c.AddResource(r.ID, doc); err != nil {
			return nil, fmt.Errorf("스키마 등록 실패 %s: %w", r.ID, err)
		}
		raw[r.Name] = doc
	}
	v := &Validator{schemas: map[string]*jsonschema.Schema{}, known: map[string]*propTree{}}
	for _, t := range AllTypes {
		s, err := c.Compile(schema.Base + t + ".schema.json")
		if err != nil {
			return nil, fmt.Errorf("%s 스키마 컴파일 실패: %w", t, err)
		}
		v.schemas[t] = s
		v.known[t] = buildPropTree(raw[t], raw)
	}
	return v, nil
}

// Decode parses JSON preserving integers as json.Number.
func Decode(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("JSON 값 뒤에 추가 데이터가 있습니다(메시지 1건 = JSON 객체 1개)")
	}
	if m == nil {
		return nil, fmt.Errorf("최상위 값이 JSON 객체가 아닙니다")
	}
	return m, nil
}

// ValidateBytes validates one document.
func (v *Validator) ValidateBytes(file string, data []byte, opt Options) Result {
	res := Result{File: file, Violations: []Violation{}}
	add := func(vs ...Violation) { res.Violations = append(res.Violations, vs...) }

	if !utf8Valid(data) {
		add(Violation{Rule: "encoding", Level: LevelError, Message: "UTF-8 이 아닌 바이트가 있습니다. 페이로드는 JSON(UTF-8)이어야 합니다(01 §2.1)."})
	}
	if bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		add(Violation{Rule: "encoding", Level: LevelError, Message: "UTF-8 BOM 이 붙어 있습니다. broker 에 발행되는 바이트에서 BOM 을 제거하십시오."})
		data = data[3:]
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		add(Violation{Rule: "json-parse", Level: LevelError, Message: fmt.Sprintf("JSON 파싱 실패: %v", err)})
		return finish(res, opt.Strict)
	}
	msg, ok := inst.(map[string]any)
	if !ok {
		add(Violation{Rule: "type", Level: LevelError, Message: "최상위 값이 JSON 객체가 아닙니다."})
		return finish(res, opt.Strict)
	}

	declared, _ := msg["type"].(string)
	res.Type = declared
	typ := opt.Type
	if typ == "" || typ == "auto" {
		typ = declared
		if typ == "" && opt.Topic != "" {
			typ = topicType(opt.Topic)
		}
	} else if declared != "" && declared != typ {
		add(Violation{Path: "/type", Rule: "type-mismatch", Level: LevelError,
			Message: fmt.Sprintf("선언된 type=%q 가 지정한 --type=%q 와 다릅니다.", declared, typ)})
	}
	sch, known := v.schemas[typ]
	if !known {
		if typ == "keys" {
			add(Violation{Path: "/type", Rule: "type-unsupported", Level: LevelError,
				Message: "keys(서명키 배포) 메시지 형식은 표준 v0.2 에 스키마가 없어 검증할 수 없습니다(01 부록 A.1, 협의 필요)."})
		} else {
			add(Violation{Path: "/type", Rule: "type-unknown", Level: LevelError,
				Message: fmt.Sprintf("type=%q 를 판별할 수 없습니다. telemetry|info|command|response|result 중 하나여야 합니다(--type 으로 지정 가능).", declared)})
		}
		return finish(res, opt.Strict)
	}
	res.Type = typ
	if p, ok := msg["payload"].(map[string]any); ok {
		res.Mode, _ = p["mode"].(string)
	} else if typ == TypeResponse {
		res.Mode, _ = msg["mode"].(string)
	}

	if opt.Topic != "" {
		add(checkTopic(opt.Topic, typ, msg)...)
	}
	if serr := sch.Validate(inst); serr != nil {
		if verr, ok := serr.(*jsonschema.ValidationError); ok {
			add(mapSchemaErrors(verr, res.Mode)...)
		} else {
			add(Violation{Rule: "schema", Level: LevelError, Message: serr.Error()})
		}
	}
	add(lintCommon(msg, typ)...)
	switch typ {
	case TypeTelemetry:
		add(lintTelemetry(msg)...)
	case TypeInfo:
		add(lintInfo(msg)...)
	case TypeCommand:
		add(lintCommand(msg)...)
	case TypeResponse:
		add(lintResponse(msg)...)
	case TypeResult:
		add(lintResult(msg)...)
	}
	add(v.unknownFields(typ, msg)...)
	if opt.Info != nil {
		add(crossInfo(opt.Info, typ, msg)...)
	}
	if opt.Command != nil && (typ == TypeResponse || typ == TypeResult) {
		add(crossCommand(opt.Command, typ, msg)...)
	}
	return finish(res, opt.Strict)
}

func finish(r Result, strict bool) Result {
	if strict {
		for i := range r.Violations {
			if r.Violations[i].Level == LevelWarn {
				r.Violations[i].Level = LevelError
			}
		}
	}
	sort.SliceStable(r.Violations, func(i, j int) bool { return rank(r.Violations[i].Level) < rank(r.Violations[j].Level) })
	r.OK = true
	for _, v := range r.Violations {
		if v.Level == LevelError {
			r.OK = false
		}
	}
	return r
}

func rank(l Level) int {
	switch l {
	case LevelError:
		return 0
	case LevelWarn:
		return 1
	}
	return 2
}

// ---- schema error mapping -------------------------------------------------

// mapSchemaErrors flattens the error tree. For the command oneOf (mode 분기)
// only the branch matching the message's own mode is reported, so a SCHEDULE
// command is not flooded with "IMMEDIATE 분기" errors.
func mapSchemaErrors(root *jsonschema.ValidationError, mode string) []Violation {
	var out []Violation
	seen := map[string]bool{}
	branch := map[string]string{"IMMEDIATE": "/oneOf/0", "SCHEDULE": "/oneOf/1"}[mode]
	var walk func(e *jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(e.Causes) > 0 {
			causes := e.Causes
			if _, isOneOf := e.ErrorKind.(*kind.OneOf); isOneOf && branch != "" {
				var keep []*jsonschema.ValidationError
				for _, c := range causes {
					if strings.Contains(c.SchemaURL, branch) {
						keep = append(keep, c)
					}
				}
				if len(keep) > 0 {
					causes = keep
				}
			}
			for _, c := range causes {
				walk(c)
			}
			return
		}
		v := leaf(e)
		k := v.Path + "|" + v.Message
		if !seen[k] {
			seen[k] = true
			out = append(out, v)
		}
	}
	walk(root)
	return out
}

func leaf(e *jsonschema.ValidationError) Violation {
	path := jsonPointer(e.InstanceLocation)
	msg := ""
	rule := "schema"
	switch k := e.ErrorKind.(type) {
	case *kind.Type:
		rule = "type"
		msg = fmt.Sprintf("타입이 올바르지 않습니다: 실제 %s, 기대 %s.", k.Got, strings.Join(k.Want, " 또는 "))
		if k.Got == "number" && contains(k.Want, "integer") {
			msg += " 전력·에너지·SoC·시각은 모두 정수입니다(01 §2.1 단위 규칙)."
		}
	case *kind.Required:
		rule = "required"
		msg = fmt.Sprintf("필수 필드가 없습니다: %s.", strings.Join(k.Missing, ", "))
	case *kind.Pattern:
		rule = "pattern"
		msg = fmt.Sprintf("값 %q 가 허용 패턴 %s 와 맞지 않습니다.", k.Got, k.Want)
	case *kind.Enum:
		rule = "enum"
		msg = fmt.Sprintf("허용되지 않은 값입니다: %s. 허용값: %s", jsonStr(k.Got), jsonStr(k.Want))
	case *kind.Const:
		rule = "const"
		msg = fmt.Sprintf("고정값이어야 합니다: %s", jsonStr(k.Want))
		if strings.Contains(path, "/bms_capabilities") {
			rule = "pair"
			msg = fmt.Sprintf("bms_capabilities 쌍 제약 위반: %s 도 함께 신고해야 합니다 — avail_charge_w↔avail_discharge_w, rack_total↔rack_online(04 §3).", jsonStr(k.Want))
			path = "/payload/bms_capabilities"
		}
	case *kind.Minimum:
		rule = "minimum"
		msg = fmt.Sprintf("최소값 %s 보다 작습니다(실제 %s).", k.Want.RatString(), k.Got.RatString())
	case *kind.Maximum:
		rule = "maximum"
		msg = fmt.Sprintf("최대값 %s 를 넘습니다(실제 %s).", k.Want.RatString(), k.Got.RatString())
		if strings.HasSuffix(path, "/ttl_sec") {
			msg += " ttl_sec 상한은 IMMEDIATE ≤ 300, SCHEDULE ≤ 3600 입니다(01 §5.1·§5.2)."
		}
	case *kind.MinItems:
		rule = "min-items"
		msg = fmt.Sprintf("배열 항목 수가 부족합니다: 실제 %d, 최소 %d.", k.Got, k.Want)
	case *kind.MaxItems:
		rule = "max-items"
		msg = fmt.Sprintf("배열 항목 수가 초과했습니다: 실제 %d, 최대 %d.", k.Got, k.Want)
	case *kind.MaxLength:
		rule = "max-length"
		msg = fmt.Sprintf("최대 길이 %d 를 넘습니다.", k.Want)
	case *kind.MinLength:
		rule = "min-length"
		msg = fmt.Sprintf("최소 길이 %d 보다 짧습니다.", k.Want)
	case *kind.UniqueItems:
		rule = "unique-items"
		msg = "배열에 중복 항목이 있습니다."
	case *kind.Not:
		rule = "not"
		msg = "금지된 필드 조합입니다."
		if strings.HasSuffix(path, "/payload") || path == "/payload" {
			msg = "mode 와 맞지 않는 필드가 있습니다 — IMMEDIATE 에는 date·tz_offset_min·slots 금지, SCHEDULE 에는 hold_sec·override_polarity_gap·direction·power_w 금지(04 §4, R-12)."
		}
	case *kind.OneOf:
		rule = "one-of"
		if len(k.Subschemas) == 0 {
			msg = "mode 별 분기(IMMEDIATE/SCHEDULE) 중 어느 쪽에도 맞지 않습니다."
		} else {
			msg = "mode 별 분기 두 개에 동시에 해당합니다."
		}
	case *kind.Contains:
		rule = "contains"
		msg = "쌍(pair) 제약 위반: avail_charge_w↔avail_discharge_w, rack_total↔rack_online 은 함께 신고해야 합니다(04 §3)."
	case *kind.Format:
		rule = "format"
		msg = fmt.Sprintf("형식 %q 에 맞지 않습니다.", k.Want)
	default:
		msg = e.ErrorKind.LocalizedString(enPrinter)
	}
	return Violation{Path: path, Rule: "schema/" + rule, Level: LevelError, Message: msg}
}

func jsonStr(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

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

func utf8Valid(b []byte) bool { return utf8.Valid(b) }
