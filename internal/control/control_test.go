package control

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func vectorsDir() string { return filepath.Join("..", "..", "testdata", "phase2", "vectors") }

func decodeMsg(t *testing.T, data []byte) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("JSON 파싱 실패: %v", err)
	}
	return m
}

func loadPub(t *testing.T, name string) crypto.PublicKey {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(vectorsDir(), name))
	if err != nil {
		t.Fatalf("공개키 읽기 실패 %s: %v", name, err)
	}
	pub, err := ParsePublicKeyPEM(data)
	if err != nil {
		t.Fatalf("공개키 파싱 실패 %s: %v", name, err)
	}
	return pub
}

// TestSignVerifyRoundtripES256 signs a fresh body and verifies it (수용기준 §2.4.2).
func TestSignVerifyRoundtripES256(t *testing.T) {
	priv, pub, err := GenerateKey(AlgES256)
	if err != nil {
		t.Fatal(err)
	}
	signer, alg, err := ParsePrivateKeyPEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubKey, err := ParsePublicKeyPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "haezoom-ctrl-2026-07"
	msg := map[string]any{
		"id":     "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
		"type":   "command",
		"rtu_id": "TEST-001",
		"payload": map[string]any{
			"max_power_w": json.Number("163530"),
			"issued_at":   json.Number("1721692800000"),
			"ttl_sec":     json.Number("120"),
		},
	}
	if _, err := SignCommand(msg, signer, alg, kid); err != nil {
		t.Fatalf("서명 실패: %v", err)
	}
	res := VerifyCommand(msg, map[string]crypto.PublicKey{kid: pubKey})
	if !res.OK {
		t.Fatalf("왕복 검증 실패: %+v", res)
	}
}

// TestOneBitTamperRejected flips a single character of the signature and asserts
// rejection (수용기준 §2.4.2 "1비트 변조 시 거부").
func TestOneBitTamperRejected(t *testing.T) {
	priv, pub, _ := GenerateKey(AlgES256)
	signer, alg, _ := ParsePrivateKeyPEM(priv)
	pubKey, _ := ParsePublicKeyPEM(pub)
	const kid = "haezoom-ctrl-2026-07"
	msg := map[string]any{
		"id":     "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
		"type":   "command",
		"rtu_id": "TEST-001",
		"payload": map[string]any{
			"max_power_w": json.Number("163530"),
			"issued_at":   json.Number("1721692800000"),
		},
	}
	if _, err := SignCommand(msg, signer, alg, kid); err != nil {
		t.Fatal(err)
	}
	payload := msg["payload"].(map[string]any)
	sig := payload["signature"].(string)
	// Flip the first char of the signature segment ("hdr..SIG"): it encodes all 6
	// bits of signature byte 0, so the change always alters the decoded bytes
	// (unlike the final base64url char, whose low bits are unused).
	parts := strings.SplitN(sig, "..", 2)
	if len(parts) != 2 || len(parts[1]) == 0 {
		t.Fatalf("예상치 못한 detached JWS 형식: %q", sig)
	}
	segB := []byte(parts[1])
	if segB[0] == 'B' {
		segB[0] = 'C'
	} else {
		segB[0] = 'B'
	}
	payload["signature"] = parts[0] + ".." + string(segB)

	res := VerifyCommand(msg, map[string]crypto.PublicKey{kid: pubKey})
	if res.OK {
		t.Fatalf("변조된 서명이 통과됨: %+v", res)
	}
	if res.FailureReason != ReasonPermissionDenied {
		t.Fatalf("failure_reason 기대 %s, 실제 %s", ReasonPermissionDenied, res.FailureReason)
	}
}

// TestTTLInjectionParity confirms omitting ttl_sec yields the same canonical
// bytes as explicitly setting 120 (부록 A.3 재구성 규칙).
func TestTTLInjectionParity(t *testing.T) {
	omitted := SignBody{ID: "x", RTUID: "TEST-001", MaxPowerW: 1, IssuedAt: 2, TTLSec: DefaultTTLSec}
	explicit := SignBody{ID: "x", RTUID: "TEST-001", MaxPowerW: 1, IssuedAt: 2, TTLSec: 120}
	a, err := omitted.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	b, err := explicit.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("ttl 주입 canonical 불일치:\n  %s\n  %s", a, b)
	}
}

// manifest mirrors testdata/phase2/vectors/manifest.json.
type manifest struct {
	Vectors []struct {
		Name         string `json:"name"`
		File         string `json:"file"`
		Alg          string `json:"alg"`
		TrustedKeyID string `json:"trusted_key_id"`
		Pubkey       string `json:"pubkey"`
		Expect       string `json:"expect"`
		Reason       string `json:"reason"`
		Step         string `json:"step"`
		TTLInjected  bool   `json:"ttl_injected"`
		CanonicalHex string `json:"canonical_hex"`
	} `json:"vectors"`
}

func loadManifest(t *testing.T) manifest {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(vectorsDir(), "manifest.json"))
	if err != nil {
		t.Fatalf("manifest 읽기 실패: %v", err)
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("manifest 파싱 실패: %v", err)
	}
	return m
}

// TestGoldenVectors drives every golden vector through VerifyCommand and asserts
// accept/reject, failure reason, and (for accepts) the locked canonical bytes.
// Covers 수용기준 §2.4.3–4 (alg:none·미지 key_id·필드 변조 거부; RFC 8785 정합).
func TestGoldenVectors(t *testing.T) {
	m := loadManifest(t)
	var accepts, rejects int
	for _, v := range m.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(vectorsDir(), v.File))
			if err != nil {
				t.Fatalf("벡터 읽기 실패: %v", err)
			}
			msg := decodeMsg(t, data)
			pub := loadPub(t, v.Pubkey)
			ring := map[string]crypto.PublicKey{v.TrustedKeyID: pub}
			res := VerifyCommand(msg, ring)

			switch v.Expect {
			case "accept":
				accepts++
				if !res.OK {
					t.Fatalf("accept 기대인데 거부됨: reason=%s step=%s detail=%s",
						res.FailureReason, res.Step, res.Detail)
				}
				if v.TTLInjected != res.TTLInjected {
					t.Fatalf("ttl_injected 기대 %v, 실제 %v", v.TTLInjected, res.TTLInjected)
				}
				if v.CanonicalHex != "" {
					want, _ := hex.DecodeString(v.CanonicalHex)
					got, _ := hex.DecodeString(res.CanonicalHex)
					if !bytes.Equal(want, got) {
						t.Fatalf("canonical 바이트 불일치(RFC 8785):\n  기대 %s\n  실제 %s", want, got)
					}
				}
			case "reject":
				rejects++
				if res.OK {
					t.Fatalf("reject 기대인데 통과됨: %+v", res)
				}
				if v.Reason != "" && res.FailureReason != v.Reason {
					t.Fatalf("failure_reason 기대 %s, 실제 %s", v.Reason, res.FailureReason)
				}
				if v.Step != "" && res.Step != v.Step {
					t.Fatalf("step 기대 %s, 실제 %s (detail=%s)", v.Step, res.Step, res.Detail)
				}
			default:
				t.Fatalf("알 수 없는 expect: %q", v.Expect)
			}
		})
	}
	if accepts < 3 {
		t.Fatalf("유효 벡터가 3건 미만입니다: %d", accepts)
	}
	if rejects < 5 {
		t.Fatalf("위반 벡터가 5건 미만입니다: %d", rejects)
	}
}
