package emulate

import "encoding/json"

func validateJSON(m map[string]any) ([]byte, error) { return json.Marshal(m) }
