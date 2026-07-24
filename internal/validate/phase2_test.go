package validate

import (
	"os"
	"path/filepath"
	"testing"
)

func newP2(t *testing.T) *Phase2Validator {
	t.Helper()
	v, err := NewPhase2()
	if err != nil {
		t.Fatalf("NewPhase2() 실패: %v", err)
	}
	return v
}

// TestPhase2ValidVectors: the golden command vectors must pass the command
// schema (structure separate from signature).
func TestPhase2CommandSchemaValid(t *testing.T) {
	v := newP2(t)
	dir := filepath.Join("..", "..", "testdata", "phase2", "vectors", "valid")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		count++
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		res := v.ValidatePhase2(e.Name(), data, "auto")
		if !res.OK {
			t.Fatalf("%s 유효 command 인데 스키마 실패: %+v", e.Name(), res.Violations)
		}
	}
	if count < 3 {
		t.Fatalf("유효 command 벡터 3건 미만: %d", count)
	}
}

// TestPhase2ResponseSchema exercises the flat response schema incl. conditional
// requireds (accepted=false → failure_reason, accepted=true → max_power_w).
func TestPhase2ResponseSchema(t *testing.T) {
	v := newP2(t)

	okAccepted := []byte(`{
      "schema_version":"1.0",
      "id":"3f2504e0-4f89-41d3-9a0c-0305e82c3301",
      "type":"response",
      "rtu_id":"TEST-001",
      "req_id":"3f2504e0-4f89-41d3-9a0c-0305e82c3301",
      "accepted":true,
      "result":"IN_PROGRESS",
      "max_power_w":163530
    }`)
	if res := v.ValidatePhase2("resp_ok", okAccepted, "auto"); !res.OK {
		t.Fatalf("유효 response 실패: %+v", res.Violations)
	}

	// accepted=true 인데 max_power_w 누락 → 실패.
	missingReadback := []byte(`{
      "schema_version":"1.0",
      "id":"3f2504e0-4f89-41d3-9a0c-0305e82c3301",
      "type":"response",
      "rtu_id":"TEST-001",
      "req_id":"3f2504e0-4f89-41d3-9a0c-0305e82c3301",
      "accepted":true,
      "result":"IN_PROGRESS"
    }`)
	if res := v.ValidatePhase2("resp_bad", missingReadback, "auto"); res.OK {
		t.Fatalf("accepted=true+max_power_w 누락은 실패해야 함")
	}

	// accepted=false 인데 failure_reason 누락 → 실패.
	rejectedNoReason := []byte(`{
      "schema_version":"1.0",
      "id":"3f2504e0-4f89-41d3-9a0c-0305e82c3301",
      "type":"response",
      "rtu_id":"TEST-001",
      "req_id":"3f2504e0-4f89-41d3-9a0c-0305e82c3301",
      "accepted":false,
      "result":"FAILURE"
    }`)
	if res := v.ValidatePhase2("resp_bad2", rejectedNoReason, "auto"); res.OK {
		t.Fatalf("accepted=false+failure_reason 누락은 실패해야 함")
	}
}

// TestPhase2ResultSchema exercises the result schema conditional requireds.
func TestPhase2ResultSchema(t *testing.T) {
	v := newP2(t)
	ok := []byte(`{
      "schema_version":"1.0",
      "id":"c3d4e5f6-a7b8-4c1d-9e2f-223344556677",
      "type":"result",
      "rtu_id":"TEST-001",
      "event_time":1721692800000,
      "ingest_time":1721692800100,
      "payload":{
        "req_id":"3f2504e0-4f89-41d3-9a0c-0305e82c3301",
        "result":"SUCCESS",
        "effective_at":1721692805000,
        "reached_power_w":163000,
        "max_power_w":163530
      }
    }`)
	if res := v.ValidatePhase2("result_ok", ok, "auto"); !res.OK {
		t.Fatalf("유효 result 실패: %+v", res.Violations)
	}

	// result=FAILURE 인데 failure_reason 누락 → 실패.
	badFail := []byte(`{
      "schema_version":"1.0",
      "id":"c3d4e5f6-a7b8-4c1d-9e2f-223344556677",
      "type":"result",
      "rtu_id":"TEST-001",
      "event_time":1721692800000,
      "ingest_time":1721692800100,
      "payload":{
        "req_id":"3f2504e0-4f89-41d3-9a0c-0305e82c3301",
        "result":"FAILURE",
        "reached_power_w":0,
        "max_power_w":163530
      }
    }`)
	if res := v.ValidatePhase2("result_bad", badFail, "auto"); res.OK {
		t.Fatalf("result=FAILURE+failure_reason 누락은 실패해야 함")
	}
}

// TestPhase2KindMismatch: declared type disagreeing with --kind is rejected.
func TestPhase2KindMismatch(t *testing.T) {
	v := newP2(t)
	cmd, err := os.ReadFile(filepath.Join("..", "..", "testdata", "phase2", "vectors", "valid", "valid_basic.json"))
	if err != nil {
		t.Fatal(err)
	}
	res := v.ValidatePhase2("x", cmd, "response")
	if res.OK || findViolation(res.Violations, RuleKindMismatch) == nil {
		t.Fatalf("kind-mismatch 위반이 있어야 함: %+v", res.Violations)
	}
}

// TestPhase2CommandRequiresSignature: a command missing signature/key_id fails
// schema (structural gate before signature verification).
func TestPhase2CommandRequiresSignature(t *testing.T) {
	v := newP2(t)
	doc := []byte(`{
      "schema_version":"1.0",
      "id":"3f2504e0-4f89-41d3-9a0c-0305e82c3301",
      "type":"command",
      "rtu_id":"TEST-001",
      "event_time":1721692800000,
      "ingest_time":1721692800100,
      "payload":{"max_power_w":163530,"issued_at":1721692800000}
    }`)
	res := v.ValidatePhase2("x", doc, "auto")
	if res.OK || findViolation(res.Violations, RuleRequired) == nil {
		t.Fatalf("signature·key_id 누락은 required 위반이어야 함: %+v", res.Violations)
	}
}
