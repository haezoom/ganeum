package validate

import (
	"bytes"
	"fmt"

	"github.com/haezoom/ganeum/internal/schema"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Phase2 control-plane message kinds.
const (
	KindCommand  = "command"
	KindResponse = "response"
	KindResult   = "result"
)

// Rule ids specific to the Phase2 control plane.
const (
	RuleKindMissing  = "kind-missing"
	RuleKindMismatch = "kind-mismatch"
	RuleKindUnknown  = "kind-unknown"
)

// Phase2Validator holds the compiled control-plane schemas.
type Phase2Validator struct {
	command  *jsonschema.Schema
	response *jsonschema.Schema
	result   *jsonschema.Schema
}

// NewPhase2 compiles the embedded Phase2 schemas into a ready validator. It uses
// its own compiler instance so its common.schema.json (full control-plane type
// enum) never collides with the Phase1 common schema of the same $id.
func NewPhase2() (*Phase2Validator, error) {
	c := jsonschema.NewCompiler()
	for _, res := range schema.Phase2Resources() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(res.Data))
		if err != nil {
			return nil, fmt.Errorf("스키마 파싱 실패 %s: %w", res.ID, err)
		}
		if err := c.AddResource(res.ID, doc); err != nil {
			return nil, fmt.Errorf("스키마 등록 실패 %s: %w", res.ID, err)
		}
	}
	cmd, err := c.Compile(schema.CommandID)
	if err != nil {
		return nil, fmt.Errorf("command 스키마 컴파일 실패: %w", err)
	}
	resp, err := c.Compile(schema.ResponseID)
	if err != nil {
		return nil, fmt.Errorf("response 스키마 컴파일 실패: %w", err)
	}
	rslt, err := c.Compile(schema.ResultID)
	if err != nil {
		return nil, fmt.Errorf("result 스키마 컴파일 실패: %w", err)
	}
	return &Phase2Validator{command: cmd, response: resp, result: rslt}, nil
}

// ValidatePhase2 validates one control-plane document against the command,
// response, or result schema. kind may be "command"|"response"|"result"|"auto".
// In auto mode the message `type` selects the schema (response type is
// "response"; command/result carry a header). A declared type that disagrees
// with an explicit kind is a kind-mismatch error.
func (v *Phase2Validator) ValidatePhase2(file string, data []byte, kind string) Result {
	res := Result{File: file, Violations: []Violation{}}

	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		res.Violations = append(res.Violations, Violation{
			Rule: RuleJSONParse, Level: LevelError,
			Message: fmt.Sprintf("JSON 파싱에 실패했습니다: %v", err),
		})
		return res
	}
	msg, ok := inst.(map[string]any)
	if !ok {
		res.Violations = append(res.Violations, Violation{
			Rule: RuleType, Level: LevelError, Message: "최상위 값이 JSON 객체가 아닙니다.",
		})
		return res
	}

	declared, _ := msg["type"].(string)
	res.Type = declared

	resolved, halt, kv := resolvePhase2Kind(declared, kind)
	res.Violations = append(res.Violations, kv...)
	if halt {
		res.OK = !hasError(res.Violations)
		return res
	}

	sch := v.command
	switch resolved {
	case KindResponse:
		sch = v.response
	case KindResult:
		sch = v.result
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

	res.OK = !hasError(res.Violations)
	return res
}

// resolvePhase2Kind picks the schema to validate against and emits kind-plane
// violations. halt=true means validation should not proceed.
func resolvePhase2Kind(declared, kind string) (resolved string, halt bool, vs []Violation) {
	if kind == "" {
		kind = "auto"
	}
	known := declared == KindCommand || declared == KindResponse || declared == KindResult

	if kind == "auto" {
		if declared == "" {
			return "", true, []Violation{{
				Path: "/type", Rule: RuleKindMissing, Level: LevelError,
				Message: "type 필드가 없어 제어평면 종류를 자동 판별할 수 없습니다. --kind command|response|result 로 지정하세요.",
			}}
		}
		if !known {
			return "", true, []Violation{{
				Path: "/type", Rule: RuleKindUnknown, Level: LevelError,
				Message: fmt.Sprintf("type=%q 는 제어평면(command·response·result) 종류가 아닙니다.", declared),
			}}
		}
		return declared, false, nil
	}

	// Explicit kind.
	if kind != KindCommand && kind != KindResponse && kind != KindResult {
		return "", true, []Violation{{
			Path: "", Rule: RuleKindUnknown, Level: LevelError,
			Message: fmt.Sprintf("--kind 값이 올바르지 않습니다: %q (command|response|result|auto)", kind),
		}}
	}
	if declared != "" && declared != kind {
		vs = append(vs, Violation{
			Path: "/type", Rule: RuleKindMismatch, Level: LevelError,
			Message: fmt.Sprintf("선언된 type=%q 가 지정한 --kind=%q 와 일치하지 않습니다.", declared, kind),
		})
	}
	return kind, false, vs
}
