// ganeum ess — 가늠 ESS 프로필 (ESS 제어·모니터링 표준 v0.2).
// Original summary: ganeum ess (가늠 ESS) self-validates ESS 제어·모니터링 표준 v0.2
// messages before a partner connects to the 해줌 broker: schema + out-of-schema
// rules, cross-message rules, command signature verification (부록 A), a
// reference signer, the golden-vector runner and a reference EMS ACK emulator.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	iofs "io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	essctl "github.com/haezoom/ganeum/internal/ess/control"
	essemu "github.com/haezoom/ganeum/internal/ess/emulate"
	essgolden "github.com/haezoom/ganeum/internal/ess/golden"
	essreport "github.com/haezoom/ganeum/internal/ess/report"
	esssamples "github.com/haezoom/ganeum/internal/ess/samples"
	essschema "github.com/haezoom/ganeum/internal/ess/schema"
	essval "github.com/haezoom/ganeum/internal/ess/validate"
)

const essUsage = `가늠 ESS 프로필 — ESS 제어·모니터링 표준 v0.2 자기검증 [DRAFT]

사용법:
  ganeum ess validate [옵션] <경로...>        메시지 스키마 + 스키마 밖 규칙(R-1~R-12) 검증
  ganeum ess verify-command [옵션] <파일...>  제어 명령 서명 검증 (부록 A.4 1~7단계)
  ganeum ess sign-command [옵션] <파일>       참조 서명기 (부록 A.2·A.3, 해줌 발행측 참조용)
  ganeum ess canonical <파일>                 서명 대상 body·canonical·서명 입력 출력(디버깅)
  ganeum ess golden [--dir <경로>]            골든 테스트 벡터 v0.2 실행 (기대: PASS 16 / FAIL 0)
  ganeum ess respond [옵션] <command.json>    참조 EMS 판정 → 표준 ACK(response) 생성
  ganeum ess gen-key [옵션]                   시험용 키페어 생성 (es256|ed25519)
  ganeum ess keystore --pub <pem> --kid <id>  공개키 PEM → keystore.json
  ganeum ess sample [이름]                    표준 예시 메시지 출력 (이름 생략 시 목록)
  ganeum ess schema [이름]                    내장 JSON Schema 출력 (common|telemetry|info|command|response|result)
  ganeum ess version

validate 옵션:
  <경로>              .json 파일, 디렉토리(재귀), '-'(stdin)
  --type string       auto(기본)|telemetry|info|command|response|result
  --topic string      발행 토픽(v1/{vendor}/{rtu_id}/...) — type·rtu_id 일치(R-10·R-11) 검사
  --info string       같은 자원의 info 메시지 — R-2(해상도)·R-4·R-5·R-6·R-9·정격 대조
  --command string    대상 명령 — response/result 의 req_id·readback·R-8 대조
  --strict            warn 을 error 로 승격
  --show-info         info 수준 안내도 출력
  --format string     text(기본)|json(NDJSON)
  -q, --quiet         통과 항목 생략

verify-command 옵션:
  --keystore string   keystore.json (golden 벡터 형식) — 또는 아래 두 옵션
  --pubkey string     공개키 PEM (SPKI, P-256 또는 Ed25519)
  --key-id string     위 공개키의 kid
  --test-keystore     내장 시험 키스토어(haezoom-ctrl-test-0001) 사용
  --now string        6단계 만료·스큐 검사 기준 시각: 'now' 또는 epoch ms (생략 시 6단계 생략)
  --skew int          미래 허용 스큐 초 (기본 60)
  --dedup             여러 파일에 걸쳐 7단계 id 중복 검사
  --format string     text|json

sign-command 옵션:
  --privkey string    개인키 PEM (SEC1 EC 또는 PKCS#8 EC/Ed25519)
  --key-id string     kid = payload.key_id (예: haezoom-ctrl-2026-11, 시험: haezoom-ctrl-test-0001)
  --fresh             id(새 UUID)·issued_at·event_time·ingest_time 을 현재 시각으로 갱신 후 서명
  --explain           서명 산출물(canonical·signing_input 등)을 stderr 로 출력

respond 옵션:
  --keystore / --pubkey+--key-id / --test-keystore   (verify-command 와 동일)
  --info string        자원 info (control_modes·해상도·SoC 한계·극성 휴지·정격)
  --telemetry string   최신 telemetry (SoC·avail_*_w·ems.operation_mode)
  --now string         'now' 또는 epoch ms (만료·극성 휴지 판정)
  --last-polarity string   직전 극성 CHARGE|DISCHARGE
  --last-polarity-at string 직전 극성 전환 시각(epoch ms)
  --seen string        이미 처리한 명령 id 목록(쉼표 구분) — 7단계
  --power-limit-partial  가용 출력 초과를 거부 대신 수락 후 부분 수행으로 판정([협의 필요])
  --format string      text|json

종료코드: 0 통과 · 1 검증 실패 · 2 사용법/입력 오류
`

func runESS(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, essUsage)
		return 2
	}
	switch args[0] {
	case "validate":
		return essRunValidate(args[1:], stdin, stdout, stderr)
	case "verify-command", "verify":
		return essRunVerify(args[1:], stdin, stdout, stderr)
	case "sign-command", "sign":
		return essRunSign(args[1:], stdin, stdout, stderr)
	case "canonical":
		return essRunCanonical(args[1:], stdin, stdout, stderr)
	case "golden":
		return essRunGolden(args[1:], stdout, stderr)
	case "respond":
		return essRunRespond(args[1:], stdin, stdout, stderr)
	case "gen-key":
		return essRunGenKey(args[1:], stdout, stderr)
	case "keystore":
		return essRunKeystore(args[1:], stdout, stderr)
	case "sample":
		return essRunSample(args[1:], stdout, stderr)
	case "schema":
		return essRunSchema(args[1:], stdout, stderr)
	case "version", "--version":
		fmt.Fprintf(stdout, "ganeum %s — ess 프로필 [DRAFT] (ESS 표준 v%s, commit %s, built %s)\n", version, essschema.StandardVersion, commit, date)
		return 0
	case "-h", "--help", "help":
		fmt.Fprint(stdout, essUsage)
		return 0
	}
	fmt.Fprintf(stderr, "알 수 없는 서브커맨드: %q\n\n%s", args[0], essUsage)
	return 2
}

func essNewFS(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, essUsage) }
	return fs
}

// parseArgs lets flags appear after positional arguments too.
func essParseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func essReadInput(path string, stdin io.Reader) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(path)
}

func essParseNow(s string) (int64, error) {
	switch s {
	case "":
		return 0, nil
	case "now":
		return time.Now().UnixMilli(), nil
	}
	return strconv.ParseInt(s, 10, 64)
}

// ---- validate ---------------------------------------------------------------

func essRunValidate(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := essNewFS("validate", stderr)
	typ := fs.String("type", "auto", "")
	topic := fs.String("topic", "", "")
	infoPath := fs.String("info", "", "")
	cmdPath := fs.String("command", "", "")
	strict := fs.Bool("strict", false, "")
	showInfo := fs.Bool("show-info", false, "")
	format := fs.String("format", "text", "")
	var quiet bool
	fs.BoolVar(&quiet, "quiet", false, "")
	fs.BoolVar(&quiet, "q", false, "")
	paths, err := essParseArgs(fs, args)
	if err != nil {
		return 2
	}
	if len(paths) == 0 {
		fmt.Fprintf(stderr, "검사할 경로가 없습니다.\n\n%s", essUsage)
		return 2
	}
	switch *typ {
	case "auto", "telemetry", "info", "command", "response", "result":
	default:
		fmt.Fprintf(stderr, "--type 값이 올바르지 않습니다: %q\n", *typ)
		return 2
	}
	v, err := essval.New()
	if err != nil {
		fmt.Fprintf(stderr, "스키마 초기화 실패: %v\n", err)
		return 2
	}
	opt := essval.Options{Type: *typ, Topic: *topic, Strict: *strict}
	if *infoPath != "" {
		ctx, r, err := essval.LoadContext(v, *infoPath)
		if err != nil {
			fmt.Fprintf(stderr, "--info 읽기 실패: %v\n", err)
			return 2
		}
		if !r.OK {
			fmt.Fprintf(stderr, "경고: --info 파일 자체가 검증을 통과하지 못했습니다(%s). 대조 결과를 신뢰하기 어렵습니다.\n", *infoPath)
		}
		opt.Info = ctx
	}
	if *cmdPath != "" {
		b, err := os.ReadFile(*cmdPath)
		if err != nil {
			fmt.Fprintf(stderr, "--command 읽기 실패: %v\n", err)
			return 2
		}
		m, err := essval.Decode(b)
		if err != nil {
			fmt.Fprintf(stderr, "--command 파싱 실패: %v\n", err)
			return 2
		}
		opt.Command = essval.CommandFromMsg(*cmdPath, m)
	}
	fmtSel := essreport.FormatText
	if *format == "json" {
		fmtSel = essreport.FormatJSON
	}
	pr := essreport.New(stdout, fmtSel, quiet, *showInfo)
	var passed, failed int
	usageErr := false
	handle := func(name string, data []byte) {
		r := v.ValidateBytes(name, data, opt)
		if r.OK {
			passed++
		} else {
			failed++
		}
		_ = pr.Result(r)
	}
	for _, p := range paths {
		if p == "-" {
			b, err := io.ReadAll(stdin)
			if err != nil {
				usageErr = true
				continue
			}
			handle("<stdin>", b)
			continue
		}
		st, err := os.Stat(p)
		if err != nil {
			fmt.Fprintf(stderr, "경로에 접근할 수 없습니다: %s (%v)\n", p, err)
			usageErr = true
			continue
		}
		files := []string{p}
		if st.IsDir() {
			files, err = essJsonFilesUnder(p)
			if err != nil {
				usageErr = true
				continue
			}
		}
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				usageErr = true
				continue
			}
			handle(f, b)
		}
	}
	_ = pr.Summary(passed, failed)
	switch {
	case failed > 0:
		return 1
	case usageErr:
		return 2
	}
	return 0
}

// ---- keyring ------------------------------------------------------------------

func essLoadRing(keystore, pubkey, keyID string, test bool) (essctl.Keyring, error) {
	ring := essctl.Keyring{}
	if test {
		b, err := iofs.ReadFile(essgolden.Embedded(), "keys/keystore.json")
		if err != nil {
			return nil, err
		}
		r, err := essctl.ParseKeystore(b)
		if err != nil {
			return nil, err
		}
		for k, v := range r {
			ring[k] = v
		}
	}
	if keystore != "" {
		r, err := essctl.LoadKeystore(keystore)
		if err != nil {
			return nil, err
		}
		for k, v := range r {
			ring[k] = v
		}
	}
	if pubkey != "" || keyID != "" {
		if pubkey == "" || keyID == "" {
			return nil, fmt.Errorf("--pubkey 와 --key-id 는 함께 지정해야 합니다")
		}
		b, err := os.ReadFile(pubkey)
		if err != nil {
			return nil, err
		}
		pub, err := essctl.ParsePublicKeyPEM(b)
		if err != nil {
			return nil, err
		}
		ring[keyID] = pub
	}
	if len(ring) == 0 {
		return nil, fmt.Errorf("신뢰 키가 없습니다: --keystore, --pubkey+--key-id, --test-keystore 중 하나를 지정하세요")
	}
	return ring, nil
}

// ---- verify-command -----------------------------------------------------------

func essRunVerify(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := essNewFS("verify-command", stderr)
	ks := fs.String("keystore", "", "")
	pub := fs.String("pubkey", "", "")
	kid := fs.String("key-id", "", "")
	test := fs.Bool("test-keystore", false, "")
	nowS := fs.String("now", "", "")
	skew := fs.Int64("skew", 60, "")
	dedup := fs.Bool("dedup", false, "")
	format := fs.String("format", "text", "")
	files, err := essParseArgs(fs, args)
	if err != nil {
		return 2
	}
	if len(files) == 0 {
		fmt.Fprintf(stderr, "검사할 command JSON 파일을 지정하세요('-'=stdin).\n")
		return 2
	}
	ring, err := essLoadRing(*ks, *pub, *kid, *test)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	now, err := essParseNow(*nowS)
	if err != nil {
		fmt.Fprintf(stderr, "--now 값이 올바르지 않습니다: %v\n", err)
		return 2
	}
	opt := essctl.VerifyOptions{NowMs: now, SkewSec: *skew}
	if *dedup {
		opt.Dedup = essctl.NewDedup()
	}
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	failed := 0
	for _, f := range files {
		b, err := essReadInput(f, stdin)
		if err != nil {
			fmt.Fprintf(stderr, "읽기 실패 %s: %v\n", f, err)
			return 2
		}
		msg, err := essval.Decode(b)
		if err != nil {
			fmt.Fprintf(stderr, "JSON 파싱 실패 %s: %v\n", f, err)
			return 2
		}
		r := essctl.VerifyCommand(msg, ring, opt)
		if !r.OK {
			failed++
		}
		if *format == "json" {
			_ = enc.Encode(struct {
				File string `json:"file"`
				*essctl.VerifyResult
			}{f, r})
			continue
		}
		if r.OK {
			tag := "PASS"
			if r.Code == essctl.CodeDuplicate {
				tag = "DUP "
			}
			fmt.Fprintf(stdout, "%s  %s  (mode=%s, alg=%s, key_id=%s%s)\n", tag, f, r.Mode, r.Alg, r.KeyID, essTtlNote(r.TTLInjected))
		} else {
			fmt.Fprintf(stdout, "FAIL  %s\n  [%s] step=%s → ACK failure_reason=%s\n", f, r.Code, r.Step, r.FailureReason)
		}
		fmt.Fprintf(stdout, "    → %s\n", r.Detail)
		if r.Canonical != "" && !r.OK && r.Code == essctl.CodeSignatureInvalid {
			fmt.Fprintf(stdout, "    canonical: %s\n", r.Canonical)
		}
		for _, n := range r.Notes {
			fmt.Fprintf(stdout, "    · %s\n", n)
		}
	}
	if failed > 0 {
		return 1
	}
	return 0
}

func essTtlNote(inj bool) string {
	if inj {
		return ", ttl_sec 생략→120 주입"
	}
	return ""
}

// ---- sign-command -------------------------------------------------------------

func essRunSign(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := essNewFS("sign-command", stderr)
	priv := fs.String("privkey", "", "")
	kid := fs.String("key-id", "", "")
	fresh := fs.Bool("fresh", false, "")
	explain := fs.Bool("explain", false, "")
	files, err := essParseArgs(fs, args)
	if err != nil {
		return 2
	}
	if *priv == "" || *kid == "" || len(files) != 1 {
		fmt.Fprintf(stderr, "sign-command 는 --privkey, --key-id 와 command JSON 1개가 필요합니다.\n")
		return 2
	}
	pb, err := os.ReadFile(*priv)
	if err != nil {
		fmt.Fprintf(stderr, "개인키 읽기 실패: %v\n", err)
		return 2
	}
	key, alg, err := essctl.ParsePrivateKeyPEM(pb)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	b, err := essReadInput(files[0], stdin)
	if err != nil {
		fmt.Fprintf(stderr, "입력 읽기 실패: %v\n", err)
		return 2
	}
	msg, err := essval.Decode(b)
	if err != nil {
		fmt.Fprintf(stderr, "JSON 파싱 실패: %v\n", err)
		return 2
	}
	if *fresh {
		now := json.Number(strconv.FormatInt(time.Now().UnixMilli(), 10))
		msg["id"] = essemu.NewUUID()
		msg["event_time"], msg["ingest_time"] = now, now
		if p, ok := msg["payload"].(map[string]any); ok {
			p["issued_at"] = now
		}
	}
	res, err := essctl.SignCommand(msg, key, alg, *kid)
	if err != nil {
		fmt.Fprintf(stderr, "서명 실패: %v\n", err)
		return 2
	}
	if *explain {
		fmt.Fprintln(stderr, essctl.MarshalIndent(res))
	}
	if !strings.HasPrefix(*kid, "haezoom-ctrl-") {
		fmt.Fprintf(stderr, "경고: key_id %q 가 haezoom-ctrl-YYYY-MM / haezoom-ctrl-test-* 형식이 아닙니다(부록 A.1).\n", *kid)
	}
	out, _ := json.MarshalIndent(msg, "", "  ")
	fmt.Fprintln(stdout, string(out))
	return 0
}

// ---- canonical ----------------------------------------------------------------

func essRunCanonical(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := essNewFS("canonical", stderr)
	files, err := essParseArgs(fs, args)
	if err != nil || len(files) != 1 {
		fmt.Fprintf(stderr, "canonical 은 command JSON 1개가 필요합니다.\n")
		return 2
	}
	b, err := essReadInput(files[0], stdin)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	msg, err := essval.Decode(b)
	if err != nil {
		fmt.Fprintf(stderr, "JSON 파싱 실패: %v\n", err)
		return 2
	}
	r, err := essctl.Explain(msg)
	if err != nil {
		fmt.Fprintf(stderr, "서명 대상 구성 실패: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, essctl.MarshalIndent(r))
	return 0
}

// ---- golden -------------------------------------------------------------------

func essRunGolden(args []string, stdout, stderr io.Writer) int {
	fs := essNewFS("golden", stderr)
	dir := fs.String("dir", "", "")
	format := fs.String("format", "text", "")
	if _, err := essParseArgs(fs, args); err != nil {
		return 2
	}
	src := essgolden.Embedded()
	label := "내장 golden_vectors_v0.2"
	if *dir != "" {
		src, label = essgolden.Dir(*dir), *dir
	}
	res, err := essgolden.Run(src)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	pass, fail := 0, 0
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	for _, r := range res {
		if r.Pass {
			pass++
		} else {
			fail++
		}
		if *format == "json" {
			_ = enc.Encode(r)
			continue
		}
		tag := "[ OK ]"
		if !r.Pass {
			tag = "[FAIL]"
		}
		extra := ""
		if !r.ExpectVerify {
			extra = fmt.Sprintf("  (%s)", r.GotCode)
		}
		fmt.Fprintf(stdout, "%s %-8s%s\n", tag, r.CaseID, extra)
		if !r.Pass {
			fmt.Fprintf(stdout, "       기대=%v/%s 실제=%s → %s\n", r.ExpectVerify, r.ExpectCode, r.GotCode, r.Detail)
		}
	}
	if *format != "json" {
		fmt.Fprintf(stdout, "=== %s: PASS %d / FAIL %d (총 %d) ===\n", label, pass, fail, pass+fail)
	}
	if fail > 0 {
		return 1
	}
	return 0
}

// ---- respond ------------------------------------------------------------------

func essRunRespond(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := essNewFS("respond", stderr)
	ks := fs.String("keystore", "", "")
	pub := fs.String("pubkey", "", "")
	kid := fs.String("key-id", "", "")
	test := fs.Bool("test-keystore", false, "")
	infoP := fs.String("info", "", "")
	teleP := fs.String("telemetry", "", "")
	nowS := fs.String("now", "", "")
	lastPol := fs.String("last-polarity", "", "")
	lastAt := fs.Int64("last-polarity-at", 0, "")
	seen := fs.String("seen", "", "")
	partial := fs.Bool("power-limit-partial", false, "")
	format := fs.String("format", "text", "")
	files, err := essParseArgs(fs, args)
	if err != nil || len(files) != 1 {
		fmt.Fprintf(stderr, "respond 는 command JSON 1개가 필요합니다.\n")
		return 2
	}
	ring, err := essLoadRing(*ks, *pub, *kid, *test)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	v, err := essval.New()
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	var ctx *essval.Context
	if *infoP != "" {
		ctx, _, err = essval.LoadContext(v, *infoP)
		if err != nil {
			fmt.Fprintf(stderr, "--info: %v\n", err)
			return 2
		}
	}
	var tele map[string]any
	if *teleP != "" {
		b, err := os.ReadFile(*teleP)
		if err == nil {
			tele, err = essval.Decode(b)
		}
		if err != nil {
			fmt.Fprintf(stderr, "--telemetry: %v\n", err)
			return 2
		}
	}
	now, err := essParseNow(*nowS)
	if err != nil {
		fmt.Fprintf(stderr, "--now: %v\n", err)
		return 2
	}
	st := essemu.State{NowMs: now, LastPolarity: *lastPol, LastPolarityAtMs: *lastAt, PowerLimitPartial: *partial}
	if *seen != "" {
		st.SeenIDs = map[string]bool{}
		for _, s := range strings.Split(*seen, ",") {
			st.SeenIDs[strings.ToLower(strings.TrimSpace(s))] = true
		}
	}
	raw, err := essReadInput(files[0], stdin)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	o, err := essemu.Decide(v, raw, ring, ctx, tele, st)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	if *format == "json" {
		fmt.Fprintln(stdout, essctl.MarshalIndent(o))
	} else {
		fmt.Fprintln(stdout, "# 판정 과정")
		for _, s := range o.Trace {
			fmt.Fprintf(stdout, "  %-5s %-22s %s\n", strings.ToUpper(s.Result), s.Check, s.Detail)
		}
		for _, n := range o.Notes {
			fmt.Fprintf(stdout, "  · %s\n", n)
		}
		fmt.Fprintln(stdout, "# 표준 ACK (…/command/response)")
		fmt.Fprintln(stdout, essctl.MarshalIndent(o.Response))
	}
	if acc, _ := o.Response["accepted"].(bool); acc {
		return 0
	}
	return 1
}

// ---- keys ---------------------------------------------------------------------

func essRunGenKey(args []string, stdout, stderr io.Writer) int {
	fs := essNewFS("gen-key", stderr)
	alg := fs.String("alg", "es256", "")
	privOut := fs.String("priv", "", "")
	pubOut := fs.String("pub", "", "")
	if _, err := essParseArgs(fs, args); err != nil {
		return 2
	}
	privPEM, pubPEM, err := essctl.GenerateKey(*alg)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	if *privOut == "" && *pubOut == "" {
		fmt.Fprintf(stdout, "# --- PRIVATE KEY (개인키: 배포 금지) ---\n%s# --- PUBLIC KEY ---\n%s", privPEM, pubPEM)
		return 0
	}
	if *privOut != "" {
		if err := os.WriteFile(*privOut, privPEM, 0o600); err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return 2
		}
		fmt.Fprintf(stderr, "개인키 저장: %s (0600)\n", *privOut)
	}
	if *pubOut != "" {
		if err := os.WriteFile(*pubOut, pubPEM, 0o644); err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return 2
		}
		fmt.Fprintf(stderr, "공개키 저장: %s\n", *pubOut)
	}
	return 0
}

func essRunKeystore(args []string, stdout, stderr io.Writer) int {
	fs := essNewFS("keystore", stderr)
	pubs := fs.String("pub", "", "")
	kids := fs.String("kid", "", "")
	if _, err := essParseArgs(fs, args); err != nil {
		return 2
	}
	ps, ks := strings.Split(*pubs, ","), strings.Split(*kids, ",")
	if *pubs == "" || len(ps) != len(ks) {
		fmt.Fprintf(stderr, "keystore 는 --pub a.pem[,b.pem] --kid id1[,id2] (같은 개수)가 필요합니다.\n")
		return 2
	}
	type ent struct {
		Kid string            `json:"kid"`
		Alg string            `json:"alg"`
		JWK map[string]string `json:"jwk"`
	}
	var out struct {
		Comment string `json:"_comment"`
		Keys    []ent  `json:"keys"`
	}
	out.Comment = "ganeum ess keystore — kid → 공개키(JWK). 운영 키는 트러스트 앵커 pinning 절차로 수령한 것만 넣으십시오(01 부록 A.1)."
	for i := range ps {
		b, err := os.ReadFile(strings.TrimSpace(ps[i]))
		if err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return 2
		}
		pk, err := essctl.ParsePublicKeyPEM(b)
		if err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return 2
		}
		j, alg, err := essctl.JWKFromPub(pk)
		if err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return 2
		}
		out.Keys = append(out.Keys, ent{strings.TrimSpace(ks[i]), alg, j})
	}
	fmt.Fprintln(stdout, essctl.MarshalIndent(out))
	return 0
}

// ---- sample / schema ------------------------------------------------------------

func essRunSample(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stdout, "사용 가능한 예시 (ESS 01 §4·§5, command 는 시험 키로 서명됨):")
		for _, n := range esssamples.Names() {
			fmt.Fprintln(stdout, "  "+n)
		}
		return 0
	}
	b, err := esssamples.Get(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "예시 %q 가 없습니다. 'ganeum ess sample' 로 목록을 확인하세요.\n", args[0])
		return 2
	}
	stdout.Write(b)
	return 0
}

func essRunSchema(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stdout, "common telemetry info command response result")
		return 0
	}
	b, err := essschema.Raw(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "스키마 %q 가 없습니다.\n", args[0])
		return 2
	}
	stdout.Write(b)
	return 0
}

// ---- utils ----------------------------------------------------------------------

func essJsonFilesUnder(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.EqualFold(filepath.Ext(p), ".json") {
			files = append(files, p)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}
