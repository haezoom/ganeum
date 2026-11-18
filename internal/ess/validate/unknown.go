package validate

import (
	"fmt"
	"strings"
)

// propTree is the set of property names a schema declares at one object level,
// with child trees for object-valued properties and array items. It merges
// properties reachable through $ref, allOf, oneOf, anyOf and if/then so the
// unknown-field lint matches what the standard actually defines.
type propTree struct {
	props map[string]*propTree
	items *propTree
}

func buildPropTree(node any, raw map[string]any) *propTree {
	t := &propTree{props: map[string]*propTree{}}
	mergeInto(t, node, raw, 0)
	return t
}

func resolveRef(ref string, raw map[string]any) any {
	// forms: "common.schema.json#/$defs/x" or "#/$defs/x" (inside common)
	file := "common"
	frag := ref
	if i := strings.Index(ref, "#"); i >= 0 {
		if i > 0 {
			file = strings.TrimSuffix(ref[:i], ".schema.json")
		}
		frag = ref[i+1:]
	}
	cur := raw[file]
	for _, seg := range strings.Split(strings.Trim(frag, "/"), "/") {
		if seg == "" {
			continue
		}
		m, _ := cur.(map[string]any)
		if m == nil {
			return nil
		}
		cur = m[seg]
	}
	return cur
}

func mergeInto(t *propTree, node any, raw map[string]any, depth int) {
	m, _ := node.(map[string]any)
	if m == nil || depth > 20 {
		return
	}
	if ref, ok := m["$ref"].(string); ok {
		mergeInto(t, resolveRef(ref, raw), raw, depth+1)
	}
	for _, k := range []string{"allOf", "oneOf", "anyOf"} {
		if xs, ok := m[k].([]any); ok {
			for _, x := range xs {
				mergeInto(t, x, raw, depth+1)
			}
		}
	}
	for _, k := range []string{"then", "else"} {
		mergeInto(t, m[k], raw, depth+1)
	}
	if ps, ok := m["properties"].(map[string]any); ok {
		for name, sub := range ps {
			child := t.props[name]
			if child == nil {
				child = &propTree{props: map[string]*propTree{}}
				t.props[name] = child
			}
			mergeInto(child, sub, raw, depth+1)
		}
	}
	if it, ok := m["items"]; ok {
		if t.items == nil {
			t.items = &propTree{props: map[string]*propTree{}}
		}
		mergeInto(t.items, it, raw, depth+1)
	}
}

func (v *Validator) unknownFields(typ string, msg map[string]any) []Violation {
	t := v.known[typ]
	if t == nil {
		return nil
	}
	var vs []Violation
	var walk func(val any, tr *propTree, path string)
	walk = func(val any, tr *propTree, path string) {
		switch x := val.(type) {
		case map[string]any:
			if len(tr.props) == 0 {
				return // leaf schema without declared properties (free object)
			}
			for k, sub := range x {
				child, ok := tr.props[k]
				if !ok {
					vs = append(vs, vw(path+"/"+k, "unknown-field",
						"표준에 없는 필드 %q 입니다. 해줌은 미지 필드를 무시하므로 오타라면 데이터가 조용히 버려집니다(04 §7). --strict 면 오류로 처리합니다.", k))
					continue
				}
				walk(sub, child, path+"/"+k)
			}
		case []any:
			if tr.items == nil {
				return
			}
			for i, e := range x {
				walk(e, tr.items, fmt.Sprintf("%s/%d", path, i))
			}
		}
	}
	walk(msg, t, "")
	return vs
}
