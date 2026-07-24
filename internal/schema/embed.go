// Package schema embeds the Phase1 monitoring JSON Schemas and exposes the
// raw bytes together with their canonical $id URLs so callers can register
// them with a jsonschema compiler and resolve relative $ref between them.
package schema

import (
	_ "embed"
)

// Canonical $id URLs of the embedded Phase1 schemas. Relative $ref such as
// "common.schema.json#/$defs/header" resolve against these.
const (
	CommonID    = "https://example/standards/pv/common.schema.json"
	TelemetryID = "https://example/standards/pv/telemetry.schema.json"
	InfoID      = "https://example/standards/pv/info.schema.json"
)

// Canonical $id URLs of the embedded Phase2 (control-plane) schemas. The Phase2
// common schema shares the same $id as Phase1's but carries the full
// control-plane definitions; it is registered in a *separate* compiler so the
// two never collide.
const (
	CommandID  = "https://example/standards/pv/command.schema.json"
	ResponseID = "https://example/standards/pv/response.schema.json"
	ResultID   = "https://example/standards/pv/result.schema.json"
)

//go:embed phase1/common.schema.json
var commonJSON []byte

//go:embed phase1/telemetry.schema.json
var telemetryJSON []byte

//go:embed phase1/info.schema.json
var infoJSON []byte

//go:embed phase2/common.schema.json
var commonP2JSON []byte

//go:embed phase2/command.schema.json
var commandJSON []byte

//go:embed phase2/response.schema.json
var responseJSON []byte

//go:embed phase2/result.schema.json
var resultJSON []byte

// Resource pairs an $id URL with the embedded schema document bytes.
type Resource struct {
	ID   string
	Data []byte
}

// Resources returns all embedded Phase1 schemas in dependency-friendly order
// (common first, then the concrete profiles).
func Resources() []Resource {
	return []Resource{
		{ID: CommonID, Data: commonJSON},
		{ID: TelemetryID, Data: telemetryJSON},
		{ID: InfoID, Data: infoJSON},
	}
}

// Phase2Resources returns all embedded Phase2 control-plane schemas in
// dependency-friendly order (common first, then command/response/result). The
// CommonID entry uses the Phase2 common document (full type enum + control
// $defs), so these must be registered in their own compiler instance.
func Phase2Resources() []Resource {
	return []Resource{
		{ID: CommonID, Data: commonP2JSON},
		{ID: CommandID, Data: commandJSON},
		{ID: ResponseID, Data: responseJSON},
		{ID: ResultID, Data: resultJSON},
	}
}
