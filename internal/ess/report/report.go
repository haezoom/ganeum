// Package report renders validation results as Korean text or NDJSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/haezoom/ganeum/internal/ess/validate"
)

// Format selects the rendering.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

// Printer writes results.
type Printer struct {
	w        io.Writer
	format   Format
	quiet    bool
	showInfo bool
	enc      *json.Encoder
}

// New builds a Printer.
func New(w io.Writer, f Format, quiet, showInfo bool) *Printer {
	p := &Printer{w: w, format: f, quiet: quiet, showInfo: showInfo}
	if f == FormatJSON {
		p.enc = json.NewEncoder(w)
		p.enc.SetEscapeHTML(false)
	}
	return p
}

// Result renders one file.
func (p *Printer) Result(r validate.Result) error {
	if p.format == FormatJSON {
		return p.enc.Encode(r)
	}
	typ := r.Type
	if typ == "" {
		typ = "-"
	}
	if r.Mode != "" {
		typ += "/" + r.Mode
	}
	var warns, infos int
	for _, v := range r.Violations {
		switch v.Level {
		case validate.LevelWarn:
			warns++
		case validate.LevelInfo:
			infos++
		}
	}
	if r.OK {
		if p.quiet {
			return nil
		}
		suffix := ""
		if warns > 0 {
			suffix = fmt.Sprintf("  경고 %d", warns)
		}
		fmt.Fprintf(p.w, "PASS  %s  (type=%s)%s\n", r.File, typ, suffix)
	} else {
		fmt.Fprintf(p.w, "FAIL  %s  (type=%s)\n", r.File, typ)
	}
	for _, v := range r.Violations {
		if v.Level == validate.LevelInfo && !p.showInfo {
			continue
		}
		if r.OK && p.quiet {
			continue
		}
		path := v.Path
		if path == "" {
			path = "(root)"
		}
		fmt.Fprintf(p.w, "  [%s] %s  %s\n    → %s\n", v.Level, path, v.Rule, v.Message)
	}
	return nil
}

// Summary prints the tally (text only).
func (p *Printer) Summary(passed, failed int) error {
	if p.format == FormatJSON {
		return nil
	}
	_, err := fmt.Fprintf(p.w, "\n%d passed, %d failed\n", passed, failed)
	return err
}
