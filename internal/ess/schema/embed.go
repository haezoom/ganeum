// Package schema embeds the ESS v0.2 JSON Schemas (04_JSON스키마_협력사용 §1~§6)
// verbatim, so the validator follows the published standard byte-for-byte.
package schema

import "embed"

// StandardVersion is the ESS standard set these schemas were extracted from.
const StandardVersion = "0.2"

// Base is the placeholder $id prefix used by the standard (04 §7).
const Base = "https://example/standards/ess/"

// Canonical $id URLs.
const (
	CommonID    = Base + "common.schema.json"
	TelemetryID = Base + "telemetry.schema.json"
	InfoID      = Base + "info.schema.json"
	CommandID   = Base + "command.schema.json"
	ResponseID  = Base + "response.schema.json"
	ResultID    = Base + "result.schema.json"
)

//go:embed ess/*.schema.json
var files embed.FS

// Resource pairs an $id with schema bytes.
type Resource struct {
	ID   string
	Name string
	Data []byte
}

// Resources returns all ESS schemas (common first).
func Resources() ([]Resource, error) {
	names := []string{"common", "telemetry", "info", "command", "response", "result"}
	out := make([]Resource, 0, len(names))
	for _, n := range names {
		b, err := files.ReadFile("ess/" + n + ".schema.json")
		if err != nil {
			return nil, err
		}
		out = append(out, Resource{ID: Base + n + ".schema.json", Name: n, Data: b})
	}
	return out, nil
}

// Raw returns one schema document by short name (e.g. "command").
func Raw(name string) ([]byte, error) {
	return files.ReadFile("ess/" + name + ".schema.json")
}
