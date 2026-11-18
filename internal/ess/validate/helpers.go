package validate

import (
	"encoding/json"
	"fmt"
	"regexp"
)

var (
	uuidLowerRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	uuidAnyRe   = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	idStringRe  = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
	keyIDProdRe = regexp.MustCompile(`^haezoom-ctrl-[0-9]{4}-(0[1-9]|1[0-2])$`)
	keyIDTestRe = regexp.MustCompile(`^haezoom-ctrl-test-[A-Za-z0-9._-]+$`)
)

// msMinValid: a plausible ms epoch is 13 digits; smaller looks like seconds.
const msMinValid int64 = 1_000_000_000_000

func obj(m map[string]any, k string) map[string]any {
	if m == nil {
		return nil
	}
	o, _ := m[k].(map[string]any)
	return o
}

func arr(m map[string]any, k string) []any {
	if m == nil {
		return nil
	}
	a, _ := m[k].([]any)
	return a
}

func str(m map[string]any, k string) (string, bool) {
	if m == nil {
		return "", false
	}
	s, ok := m[k].(string)
	return s, ok
}

// num returns an integer field. ok=false when missing or not an integer.
func num(m map[string]any, k string) (int64, bool) {
	if m == nil {
		return 0, false
	}
	switch x := m[k].(type) {
	case json.Number:
		i, err := x.Int64()
		return i, err == nil
	case int:
		return int64(x), true
	case int64:
		return x, true
	}
	return 0, false
}

func has(m map[string]any, k string) bool {
	if m == nil {
		return false
	}
	_, ok := m[k]
	return ok
}

func boolv(m map[string]any, k string) (bool, bool) {
	if m == nil {
		return false, false
	}
	b, ok := m[k].(bool)
	return b, ok
}

func ve(path, rule, f string, a ...any) Violation {
	return Violation{Path: path, Rule: rule, Level: LevelError, Message: fmt.Sprintf(f, a...)}
}
func vw(path, rule, f string, a ...any) Violation {
	return Violation{Path: path, Rule: rule, Level: LevelWarn, Message: fmt.Sprintf(f, a...)}
}
func vi(path, rule, f string, a ...any) Violation {
	return Violation{Path: path, Rule: rule, Level: LevelInfo, Message: fmt.Sprintf(f, a...)}
}
