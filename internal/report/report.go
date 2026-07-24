// Package report renders validation results for humans (text) and machines
// (NDJSON). Korean human-readable output per 지시서 §4.
package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/haezoom/ganeum/internal/validate"
)

// Format selects the output rendering.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

// Printer writes results in the chosen format.
type Printer struct {
	w      io.Writer
	format Format
	quiet  bool
	enc    *json.Encoder
}

// New builds a Printer.
func New(w io.Writer, format Format, quiet bool) *Printer {
	p := &Printer{w: w, format: format, quiet: quiet}
	if format == FormatJSON {
		p.enc = json.NewEncoder(w)
	}
	return p
}

// Result renders one file result. For JSON it emits one NDJSON line per file.
func (p *Printer) Result(r validate.Result) error {
	if p.format == FormatJSON {
		return p.enc.Encode(r)
	}
	return p.text(r)
}

func (p *Printer) text(r validate.Result) error {
	if r.OK {
		if p.quiet {
			return nil
		}
		typ := r.Type
		if typ == "" {
			typ = "-"
		}
		_, err := fmt.Fprintf(p.w, "PASS  %s  (type=%s)\n", r.File, typ)
		return err
	}

	if _, err := fmt.Fprintf(p.w, "FAIL  %s\n", r.File); err != nil {
		return err
	}
	for _, v := range r.Violations {
		path := v.Path
		if path == "" {
			path = "(root)"
		}
		if _, err := fmt.Fprintf(p.w, "  [%s] %s  %s\n    → %s\n",
			v.Level, path, v.Rule, v.Message); err != nil {
			return err
		}
	}
	return nil
}

// Summary prints the batch tally (text only). Returns nil for JSON.
func (p *Printer) Summary(passed, failed int) error {
	if p.format == FormatJSON {
		return nil
	}
	_, err := fmt.Fprintf(p.w, "\n%d passed, %d failed\n", passed, failed)
	return err
}
