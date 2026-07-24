// Command ganeum (가늠) self-validates Phase1 telemetry/info JSON payloads
// against the 해줌 monitoring standard before a partner connects to the broker.
package main

import (
	"bytes"
	"crypto"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/haezoom/ganeum/internal/control"
	"github.com/haezoom/ganeum/internal/report"
	"github.com/haezoom/ganeum/internal/validate"
)

// Build metadata (overridable via -ldflags -X).
var (
	version = "0.1.0"
	commit  = "dev"
	date    = "unknown"
)

const usage = `가늠(ganeum) — 모니터링(Phase1)·제어(Phase2) 규격 자기검증 도구

사용법:
  ganeum validate [옵션] <경로...>            # 스키마 검증 (phase1/phase2)
  ganeum verify-command --pubkey <pem> --key-id <kid> <command.json>
  ganeum sign-command  --privkey <pem> --key-id <kid> <command.json>
  ganeum gen-key [--alg es256|ed25519] [--priv <path>] [--pub <path>]
  ganeum version

validate 옵션:
  <경로>            .json 파일, 디렉토리(재귀 .json 전수), 또는 '-'(stdin)
  --profile string  phase1(기본) | phase2(제어평면 command/response/result)
  --type string     [phase1] telemetry|info|auto (기본 auto)
  --kind string     [phase2] command|response|result|auto (기본 auto)
  --strict          미지 필드 등 약한 warn 을 error 로 승격
  --format string   text(기본, 사람용) | json(기계용 NDJSON)
  -q, --quiet       통과 항목 생략, 실패만 출력

verify-command 옵션 (부록 A.4 서명 검증):
  --pubkey string   해줌 공개키 PEM (필수)
  --key-id string   위 공개키의 신뢰 key_id (필수, fail-closed 기준)
  --format string   text(기본) | json
  ※ 서명 검증은 5필드(id/rtu_id/max_power_w/issued_at/ttl_sec)의 진정성·무결성만
    보증한다. 재생 방지·만료(issued_at/ttl_sec) 강제는 수행하지 않으며, 실집행
    안전은 소비자/브로커(prod)가 책임진다.

sign-command 옵션 (참조 서명기):
  --privkey string  개인키 PEM (필수)
  --key-id string   protected header kid·payload.key_id (필수)
                    (예: haezoom-ctrl-2026-07)

gen-key 옵션:
  --alg string      es256(기본, P-256) | ed25519
  --priv string     개인키 PEM 출력 경로 (생략 시 stdout)
  --pub string      공개키 PEM 출력 경로 (생략 시 stdout)
  --key-id string   참고용 라벨(출력 주석)

종료코드: 0 전건 통과/검증 성공 · 1 검증 실패 · 2 사용법/입력 오류
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}

	switch args[0] {
	case "validate":
		return runValidate(args[1:], stdin, stdout, stderr)
	case "verify-command":
		return runVerifyCommand(args[1:], stdin, stdout, stderr)
	case "sign-command":
		return runSignCommand(args[1:], stdin, stdout, stderr)
	case "gen-key":
		return runGenKey(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "ganeum %s (commit %s, built %s)\n", version, commit, date)
		return 0
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "알 수 없는 서브커맨드입니다: %q\n\n%s", args[0], usage)
		return 2
	}
}

func runValidate(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }

	profile := fs.String("profile", "phase1", "phase1|phase2")
	typ := fs.String("type", "auto", "telemetry|info|auto")
	kind := fs.String("kind", "auto", "command|response|result|auto")
	strict := fs.Bool("strict", false, "warn 을 error 로 승격")
	format := fs.String("format", "text", "text|json")
	var quiet bool
	fs.BoolVar(&quiet, "quiet", false, "실패만 출력")
	fs.BoolVar(&quiet, "q", false, "실패만 출력 (단축)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	switch *profile {
	case "phase1", "phase2":
	default:
		fmt.Fprintf(stderr, "지원하지 않는 프로필입니다: %q (phase1|phase2)\n", *profile)
		return 2
	}
	switch *typ {
	case "auto", "telemetry", "info":
	default:
		fmt.Fprintf(stderr, "--type 값이 올바르지 않습니다: %q (telemetry|info|auto)\n", *typ)
		return 2
	}
	switch *kind {
	case "auto", "command", "response", "result":
	default:
		fmt.Fprintf(stderr, "--kind 값이 올바르지 않습니다: %q (command|response|result|auto)\n", *kind)
		return 2
	}
	var fmtSel report.Format
	switch *format {
	case "text":
		fmtSel = report.FormatText
	case "json":
		fmtSel = report.FormatJSON
	default:
		fmt.Fprintf(stderr, "--format 값이 올바르지 않습니다: %q (text|json)\n", *format)
		return 2
	}

	paths := fs.Args()
	if len(paths) == 0 {
		fmt.Fprintf(stderr, "검사할 경로가 없습니다.\n\n%s", usage)
		return 2
	}

	// handle validates one document with the resolved profile.
	var handleDoc func(file string, data []byte) validate.Result

	if *profile == "phase2" {
		p2, err := validate.NewPhase2()
		if err != nil {
			fmt.Fprintf(stderr, "제어평면 스키마 초기화 실패: %v\n", err)
			return 2
		}
		handleDoc = func(file string, data []byte) validate.Result {
			return p2.ValidatePhase2(file, data, *kind)
		}
	} else {
		v, err := validate.New()
		if err != nil {
			fmt.Fprintf(stderr, "스키마 초기화 실패: %v\n", err)
			return 2
		}
		opt := validate.Options{Profile: *profile, Type: *typ, Strict: *strict}
		handleDoc = func(file string, data []byte) validate.Result {
			return v.ValidateBytes(file, data, opt)
		}
	}

	printer := report.New(stdout, fmtSel, quiet)

	var passed, failed int
	usageErr := false

	handle := func(file string, data []byte) {
		res := handleDoc(file, data)
		if res.OK {
			passed++
		} else {
			failed++
		}
		if err := printer.Result(res); err != nil {
			fmt.Fprintf(stderr, "출력 오류: %v\n", err)
		}
	}

	for _, p := range paths {
		if p == "-" {
			data, err := io.ReadAll(stdin)
			if err != nil {
				fmt.Fprintf(stderr, "stdin 읽기 실패: %v\n", err)
				usageErr = true
				continue
			}
			handle("<stdin>", data)
			continue
		}

		info, err := os.Stat(p)
		if err != nil {
			fmt.Fprintf(stderr, "경로에 접근할 수 없습니다: %s (%v)\n", p, err)
			usageErr = true
			continue
		}

		if info.IsDir() {
			files, werr := jsonFilesUnder(p)
			if werr != nil {
				fmt.Fprintf(stderr, "디렉토리 탐색 실패: %s (%v)\n", p, werr)
				usageErr = true
				continue
			}
			if len(files) == 0 {
				fmt.Fprintf(stderr, "경고: %s 아래에 .json 파일이 없습니다.\n", p)
			}
			for _, f := range files {
				data, rerr := os.ReadFile(f)
				if rerr != nil {
					fmt.Fprintf(stderr, "파일 읽기 실패: %s (%v)\n", f, rerr)
					usageErr = true
					continue
				}
				handle(f, data)
			}
			continue
		}

		data, rerr := os.ReadFile(p)
		if rerr != nil {
			fmt.Fprintf(stderr, "파일 읽기 실패: %s (%v)\n", p, rerr)
			usageErr = true
			continue
		}
		handle(p, data)
	}

	if err := printer.Summary(passed, failed); err != nil {
		fmt.Fprintf(stderr, "출력 오류: %v\n", err)
	}

	switch {
	case usageErr && passed == 0 && failed == 0:
		return 2
	case failed > 0:
		return 1
	case usageErr:
		return 2
	default:
		return 0
	}
}

// decodeMessage parses a JSON object using json.Number so that integer fields
// (max_power_w, issued_at, ttl_sec) survive without float coercion — essential
// for byte-identical JCS canonicalization.
func decodeMessage(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, fmt.Errorf("최상위 값이 JSON 객체가 아닙니다")
	}
	return m, nil
}

func readInput(path string, stdin io.Reader) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(path)
}

// runVerifyCommand implements `ganeum verify-command` (부록 A.4).
func runVerifyCommand(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify-command", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	pubkey := fs.String("pubkey", "", "해줌 공개키 PEM 경로 (필수)")
	keyID := fs.String("key-id", "", "신뢰 key_id (필수, fail-closed)")
	format := fs.String("format", "text", "text|json")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *pubkey == "" || *keyID == "" {
		fmt.Fprintf(stderr, "verify-command 는 --pubkey 와 --key-id 가 모두 필요합니다.\n")
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintf(stderr, "검사할 command JSON 파일 1개를 지정하세요('-'=stdin).\n")
		return 2
	}

	pubPEM, err := os.ReadFile(*pubkey)
	if err != nil {
		fmt.Fprintf(stderr, "공개키 읽기 실패: %v\n", err)
		return 2
	}
	pub, err := control.ParsePublicKeyPEM(pubPEM)
	if err != nil {
		fmt.Fprintf(stderr, "공개키 파싱 실패: %v\n", err)
		return 2
	}
	ring := map[string]crypto.PublicKey{*keyID: pub}

	data, err := readInput(rest[0], stdin)
	if err != nil {
		fmt.Fprintf(stderr, "입력 읽기 실패: %v\n", err)
		return 2
	}
	msg, err := decodeMessage(data)
	if err != nil {
		fmt.Fprintf(stderr, "JSON 파싱 실패: %v\n", err)
		return 2
	}

	res := control.VerifyCommand(msg, ring)

	if *format == "json" {
		enc := json.NewEncoder(stdout)
		if err := enc.Encode(res); err != nil {
			fmt.Fprintf(stderr, "출력 오류: %v\n", err)
		}
	} else {
		if res.OK {
			fmt.Fprintf(stdout, "PASS  %s  서명 검증 성공 (alg=%s, key_id=%s%s)\n",
				rest[0], res.Alg, res.KeyID, ttlNote(res.TTLInjected))
			fmt.Fprintf(stdout, "  → %s\n", res.Detail)
		} else {
			fmt.Fprintf(stdout, "FAIL  %s  서명 검증 실패\n", rest[0])
			fmt.Fprintf(stdout, "  [%s] step=%s\n    → %s\n", res.FailureReason, res.Step, res.Detail)
		}
	}
	if res.OK {
		return 0
	}
	return 1
}

func ttlNote(injected bool) string {
	if injected {
		return ", ttl_sec 생략→120 주입"
	}
	return ""
}

// runSignCommand implements `ganeum sign-command` (참조 서명기).
func runSignCommand(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sign-command", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	privkey := fs.String("privkey", "", "개인키 PEM 경로 (필수)")
	keyID := fs.String("key-id", "", "kid·key_id (필수)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *privkey == "" || *keyID == "" {
		fmt.Fprintf(stderr, "sign-command 는 --privkey 와 --key-id 가 모두 필요합니다.\n")
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintf(stderr, "서명할 command payload JSON 파일 1개를 지정하세요('-'=stdin).\n")
		return 2
	}

	privPEM, err := os.ReadFile(*privkey)
	if err != nil {
		fmt.Fprintf(stderr, "개인키 읽기 실패: %v\n", err)
		return 2
	}
	priv, alg, err := control.ParsePrivateKeyPEM(privPEM)
	if err != nil {
		fmt.Fprintf(stderr, "개인키 파싱 실패: %v\n", err)
		return 2
	}

	data, err := readInput(rest[0], stdin)
	if err != nil {
		fmt.Fprintf(stderr, "입력 읽기 실패: %v\n", err)
		return 2
	}
	msg, err := decodeMessage(data)
	if err != nil {
		fmt.Fprintf(stderr, "JSON 파싱 실패: %v\n", err)
		return 2
	}

	if _, err := control.SignCommand(msg, priv, alg, *keyID); err != nil {
		fmt.Fprintf(stderr, "서명 실패: %v\n", err)
		return 2
	}

	out, err := json.MarshalIndent(msg, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "출력 직렬화 실패: %v\n", err)
		return 2
	}
	fmt.Fprintln(stdout, string(out))
	return 0
}

// runGenKey implements `ganeum gen-key`.
func runGenKey(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gen-key", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	alg := fs.String("alg", "es256", "es256|ed25519")
	privOut := fs.String("priv", "", "개인키 PEM 출력 경로")
	pubOut := fs.String("pub", "", "공개키 PEM 출력 경로")
	keyID := fs.String("key-id", "", "참고 라벨")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	privPEM, pubPEM, err := control.GenerateKey(control.KeyAlg(*alg))
	if err != nil {
		fmt.Fprintf(stderr, "키 생성 실패: %v\n", err)
		return 2
	}

	wrote := false
	if *privOut != "" {
		if err := os.WriteFile(*privOut, privPEM, 0o600); err != nil {
			fmt.Fprintf(stderr, "개인키 저장 실패: %v\n", err)
			return 2
		}
		fmt.Fprintf(stderr, "개인키 저장: %s (0600)\n", *privOut)
		wrote = true
	}
	if *pubOut != "" {
		if err := os.WriteFile(*pubOut, pubPEM, 0o644); err != nil {
			fmt.Fprintf(stderr, "공개키 저장 실패: %v\n", err)
			return 2
		}
		fmt.Fprintf(stderr, "공개키 저장: %s (0644)\n", *pubOut)
		wrote = true
	}
	if !wrote {
		if *keyID != "" {
			fmt.Fprintf(stdout, "# key_id: %s (alg=%s)\n", *keyID, *alg)
		}
		fmt.Fprintf(stdout, "# --- PRIVATE KEY (개인키: 절대 배포 금지) ---\n%s", privPEM)
		fmt.Fprintf(stdout, "# --- PUBLIC KEY (공개키: 협력사 배포) ---\n%s", pubPEM)
	}
	return 0
}

// jsonFilesUnder returns all .json files under dir (recursive), sorted.
func jsonFilesUnder(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(path), ".json") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}
