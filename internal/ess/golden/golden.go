// Package golden runs the ESS 골든 테스트 벡터 v0.2 (01 부록 A.5) through the
// Go verifier. The bundle is embedded so `ganeum-ess golden` works offline; an
// external directory with the same layout can be supplied instead.
package golden

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"

	"github.com/haezoom/ganeum/internal/ess/control"
)

//go:embed data
var embedded embed.FS

// Embedded returns the bundled vector set rooted at its top directory.
func Embedded() fs.FS {
	sub, _ := fs.Sub(embedded, "data")
	return sub
}

// Dir returns an fs.FS for an external golden_vectors directory.
func Dir(p string) fs.FS { return os.DirFS(p) }

// CaseResult is one vector outcome.
type CaseResult struct {
	CaseID       string `json:"case_id"`
	File         string `json:"file"`
	ExpectVerify bool   `json:"expect_verify"`
	ExpectCode   string `json:"expect_code,omitempty"`
	GotCode      string `json:"got_code"`
	CanonicalOK  *bool  `json:"canonical_match,omitempty"`
	Pass         bool   `json:"pass"`
	Detail       string `json:"detail"`
}

type vector struct {
	CaseID   string          `json:"case_id"`
	Message  json.RawMessage `json:"message"`
	Expected struct {
		Verify       bool   `json:"verify"`
		FailureCode  string `json:"failure_code"`
		Canonical    string `json:"canonical"`
		CanonicalSHA string `json:"canonical_sha256"`
	} `json:"expected"`
}

// Run verifies every vectors/*.json and negative/*.json in fsys.
func Run(fsys fs.FS) ([]CaseResult, error) {
	ksb, err := fs.ReadFile(fsys, "keys/keystore.json")
	if err != nil {
		return nil, fmt.Errorf("keys/keystore.json 을 읽지 못했습니다: %w", err)
	}
	ring, err := control.ParseKeystore(ksb)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, d := range []string{"vectors", "negative"} {
		m, _ := fs.Glob(fsys, d+"/*.json")
		sort.Strings(m)
		files = append(files, m...)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("vectors/·negative/ 아래 벡터가 없습니다")
	}
	var out []CaseResult
	for _, f := range files {
		b, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, err
		}
		var v vector
		if err := json.Unmarshal(b, &v); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		dec := json.NewDecoder(bytes.NewReader(v.Message))
		dec.UseNumber()
		var msg map[string]any
		if err := dec.Decode(&msg); err != nil {
			return nil, fmt.Errorf("%s: message 파싱 실패: %w", f, err)
		}
		res := control.VerifyCommand(msg, ring, control.VerifyOptions{})
		cr := CaseResult{CaseID: v.CaseID, File: path.Base(f), ExpectVerify: v.Expected.Verify,
			ExpectCode: v.Expected.FailureCode, GotCode: res.Code, Detail: res.Detail}
		if v.Expected.Verify {
			match := res.Canonical == v.Expected.Canonical && res.CanonicalSHA == v.Expected.CanonicalSHA
			cr.CanonicalOK = &match
			cr.Pass = res.OK && match
			if res.OK && !match {
				cr.Detail = "서명은 통과했으나 canonical 바이트가 기대값과 다릅니다"
			}
		} else {
			cr.Pass = !res.OK && res.Code == v.Expected.FailureCode
		}
		out = append(out, cr)
	}
	return out, nil
}
