package control

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	d := json.NewDecoder(strings.NewReader(s))
	d.UseNumber()
	var m map[string]any
	if err := d.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

const immNoTTL = `{"schema_version":"0.2","id":"e1b6e0b2-60a8-432b-a551-2d0a6baa2fc3","type":"command","rtu_id":"ESS-1",
"event_time":1781000000900,"ingest_time":1781000000900,
"payload":{"mode":"IMMEDIATE","issued_at":1781000000900,"key_id":"k","direction":"DISCHARGE","power_w":200000}}`

// A.3 문서 예시 IMM-01 canonical 과 바이트 일치.
func TestCanonicalIMM01(t *testing.T) {
	sb, err := BuildSigningBody(decode(t, immNoTTL))
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := sb.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"direction":"DISCHARGE","id":"e1b6e0b2-60a8-432b-a551-2d0a6baa2fc3","issued_at":1781000000900,"mode":"IMMEDIATE","power_w":200000,"rtu_id":"ESS-1","ttl_sec":120}`
	if string(c) != want {
		t.Fatalf("got  %s\nwant %s", c, want)
	}
	if !sb.TTLInjected {
		t.Fatal("ttl 주입 표시 누락")
	}
}

func TestType2FalseIncluded(t *testing.T) {
	m := decode(t, immNoTTL)
	m["payload"].(map[string]any)["override_polarity_gap"] = false
	sb, _ := BuildSigningBody(m)
	c, _, _ := sb.Canonical()
	if !strings.Contains(string(c), `"override_polarity_gap":false`) {
		t.Fatalf("false 명시 값이 canonical 에 없음: %s", c)
	}
}

func TestOtherModeFieldsExcluded(t *testing.T) {
	m := decode(t, immNoTTL)
	m["payload"].(map[string]any)["date"] = "2026-11-18"
	sb, _ := BuildSigningBody(m)
	if _, ok := sb.Body["date"]; ok {
		t.Fatal("IMMEDIATE 서명 body 에 date 가 들어감")
	}
	if len(sb.Ignored) != 1 || sb.Ignored[0] != "date" {
		t.Fatalf("ignored=%v", sb.Ignored)
	}
}

func TestSignVerifyRoundTripAndAttacks(t *testing.T) {
	for _, alg := range []string{"es256", "ed25519"} {
		privPEM, pubPEM, err := GenerateKey(alg)
		if err != nil {
			t.Fatal(err)
		}
		priv, a, err := ParsePrivateKeyPEM(privPEM)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := ParsePublicKeyPEM(pubPEM)
		if err != nil {
			t.Fatal(err)
		}
		ring := Keyring{"haezoom-ctrl-2026-11": pub}
		m := decode(t, immNoTTL)
		if _, err := SignCommand(m, priv, a, "haezoom-ctrl-2026-11"); err != nil {
			t.Fatal(err)
		}
		if r := VerifyCommand(m, ring, VerifyOptions{}); !r.OK {
			t.Fatalf("%s 왕복 실패: %+v", alg, r)
		}
		// NEG-07 형태 공격: 서명 후 override_polarity_gap 주입
		m["payload"].(map[string]any)["override_polarity_gap"] = true
		if r := VerifyCommand(m, ring, VerifyOptions{}); r.OK || r.Code != CodeSignatureInvalid {
			t.Fatalf("%s 주입 공격 통과: %+v", alg, r)
		}
	}
}

func TestExpiryAndDedup(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ring := Keyring{"kid": &k.PublicKey}
	m := decode(t, immNoTTL)
	if _, err := SignCommand(m, k, AlgES256, "kid"); err != nil {
		t.Fatal(err)
	}
	ia := int64(1781000000900)
	if r := VerifyCommand(m, ring, VerifyOptions{NowMs: ia + 119_000}); !r.OK {
		t.Fatalf("유효기간 내 거부: %+v", r)
	}
	if r := VerifyCommand(m, ring, VerifyOptions{NowMs: ia + 121_000}); r.Code != CodeExpired || r.FailureReason != "BAD_REQUEST" {
		t.Fatalf("만료 미검출: %+v", r)
	}
	if r := VerifyCommand(m, ring, VerifyOptions{NowMs: ia - 61_000}); r.Code != CodeFutureIssued {
		t.Fatalf("미래 시각 미검출: %+v", r)
	}
	d := NewDedup()
	if r := VerifyCommand(m, ring, VerifyOptions{Dedup: d}); r.Code != CodeOK {
		t.Fatal(r.Code)
	}
	if r := VerifyCommand(m, ring, VerifyOptions{Dedup: d}); r.Code != CodeDuplicate || !r.OK {
		t.Fatalf("중복 미검출: %+v", r)
	}
}

func TestKidMismatchAndDER(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ring := Keyring{"a": &k.PublicKey, "b": &k.PublicKey}
	m := decode(t, immNoTTL)
	SignCommand(m, k, AlgES256, "a")
	m["payload"].(map[string]any)["key_id"] = "b"
	if r := VerifyCommand(m, ring, VerifyOptions{}); r.Code != CodeKidMismatch || r.FailureReason != "PERMISSION_DENIED" {
		t.Fatalf("kid 불일치 미검출: %+v", r)
	}
}
