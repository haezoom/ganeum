// Package samples embeds the ESS 01 표준 예시 메시지 (§4.1~§5.3). Command
// samples are signed with the golden-vector test key (haezoom-ctrl-test-0001)
// so they verify end-to-end against the embedded keystore.
package samples

import (
	"embed"
	"sort"
	"strings"
)

//go:embed data/*.json
var files embed.FS

// Names lists the available samples (without .json).
func Names() []string {
	es, _ := files.ReadDir("data")
	var out []string
	for _, e := range es {
		out = append(out, strings.TrimSuffix(e.Name(), ".json"))
	}
	sort.Strings(out)
	return out
}

// Get returns one sample by name.
func Get(name string) ([]byte, error) {
	return files.ReadFile("data/" + strings.TrimSuffix(name, ".json") + ".json")
}
