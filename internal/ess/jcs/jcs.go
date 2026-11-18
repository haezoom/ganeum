// Package jcs implements RFC 8785 (JSON Canonicalization Scheme) for the value
// shapes used by the ESS signing body (01 부록 A.3): objects, arrays, strings,
// booleans, null and integers. Integers are emitted in their shortest decimal
// form; non-integer numbers are rejected because the standard forbids them in
// signed fields ("정수 채택") and accepting them would invite float drift.
package jcs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// maxSafe is 2^53, the largest integer every JSON implementation round-trips.
var maxSafe = new(big.Int).Lsh(big.NewInt(1), 53)

// Marshal returns the RFC 8785 canonical bytes of v. Numbers may be
// json.Number, int, int64, float64 (integral only) or *big.Int.
func Marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := write(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func write(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeString(b, x)
	case json.Number:
		return writeNumberString(b, x.String())
	case int:
		b.WriteString(strconv.FormatInt(int64(x), 10))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case float64:
		if math.Trunc(x) != x || math.IsInf(x, 0) || math.IsNaN(x) {
			return fmt.Errorf("정수가 아닌 수치는 서명 대상에 허용되지 않습니다: %v", x)
		}
		return writeNumberString(b, strconv.FormatFloat(x, 'f', -1, 64))
	case *big.Int:
		return writeNumberString(b, x.String())
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := write(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			if err := write(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("JCS 직렬화 불가 타입: %T", v)
	}
	return nil
}

// writeNumberString accepts only integer literals (optionally negative) and
// re-emits them in canonical form (no leading zeros, no "+", no exponent).
func writeNumberString(b *bytes.Buffer, s string) error {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		// Allow integral values written as 1e3 / 100.0 only if exactly integral.
		f, _, err := big.ParseFloat(s, 10, 256, big.ToNearestEven)
		if err != nil || !f.IsInt() {
			return fmt.Errorf("정수가 아닌 수치는 서명 대상에 허용되지 않습니다: %s", s)
		}
		n, _ = f.Int(nil)
	}
	if new(big.Int).Abs(n).Cmp(maxSafe) > 0 {
		return fmt.Errorf("정수 %s 가 IEEE-754 안전 범위(2^53)를 넘습니다", s)
	}
	b.WriteString(n.String())
	return nil
}

// writeString follows RFC 8785 §3.2.2.2 (ECMAScript JSON.stringify escaping).
func writeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// lessUTF16 orders property names by their UTF-16 code units (RFC 8785 §3.2.3).
func lessUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}
