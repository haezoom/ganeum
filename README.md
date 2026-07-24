# 가늠 (ganeum)

해줌 표준 **자기검증 CLI**. 협력사가 broker에 접속하기 **전에** 로컬에서 전수 검증하는
단일 정적 바이너리입니다.

- **Phase1(모니터링)**: `telemetry`·`info` JSON payload 스키마 검증 (모니터링 표준 §5·§6·§9)
- **Phase2(제어)**: `command`/`response`/`result` 스키마 검증 + 다운링크 명령의
  detached JWS(ES256/EdDSA) **서명 검증·참조 서명** (제어 표준 01 §5·부록 A, 04 §4~6) — 아래 별도 절.

- JSON Schema 엔진: `github.com/santhosh-tekuri/jsonschema/v6` (Draft 2020-12)
- 스키마 3종(common/telemetry/info)은 바이너리에 내장(`embed.FS`)되어 별도 파일이 필요 없습니다.

## 설치 / 빌드

```bash
# 소스에서 빌드 (Go 1.21+)
git clone https://github.com/haezoom/ganeum.git && cd ganeum
make build          # ./ganeum 생성
./ganeum version

# 또는 go install
go install github.com/haezoom/ganeum/cmd/ganeum@latest
```

크로스컴파일(배포용 바이너리):

```bash
make build-all      # dist/ 아래 darwin/linux/windows 바이너리 생성
```

## 사용법

```
ganeum validate [옵션] <경로...>
  <경로>            .json 파일, 디렉토리(재귀 .json 전수), 또는 '-'(stdin)
  --profile string  검증 프로필 (기본 phase1; 현재 phase1만 지원)
  --type string     telemetry|info|auto (기본 auto: 메시지의 type 필드로 판별)
  --strict          미지 필드 등 약한 warn 을 error 로 승격
  --format string   text(기본, 사람용) | json(기계용 NDJSON)
  -q, --quiet       통과 항목 생략, 실패만 출력

ganeum version      버전·빌드정보
```

### 종료코드

| 코드 | 의미 |
|:---:|------|
| `0` | 전건 통과 |
| `1` | 하나 이상 검증 실패 |
| `2` | 사용법/입력 오류 (잘못된 플래그, 없는 경로 등) |

## 로컬 자기시험 (온보딩 절차 ⑤)

```bash
# 1) 단일 파일
ganeum validate ./out/telemetry_sample.json

# 2) 디렉토리 전수 검사
ganeum validate ./out

# 3) 파이프라인/CI 용 기계 판독 (파일당 NDJSON 한 줄)
ganeum validate --format json ./out | jq -c 'select(.ok==false)'

# 4) 오타 조기검출까지 엄격 검사
ganeum validate --strict ./out

# 5) 표준출력에서 바로
cat telemetry.json | ganeum validate --type telemetry -
```

### text 출력 예시

```
PASS  out/telemetry_0001.json  (type=telemetry)
FAIL  out/telemetry_0002.json
  [error] /payload/is_control  is-control-false
    → Phase1 telemetry 의 is_control 은 반드시 false 여야 합니다(§6.5).

12 passed, 1 failed
```

### json(NDJSON) 출력 예시

```json
{"file":"out/telemetry_0002.json","ok":false,"type":"telemetry","violations":[{"path":"/payload/is_control","rule":"is-control-false","level":"error","message":"..."}]}
```

## 검사 규칙

스키마 구조 검증(필수 필드·타입·enum·조건부 필수)에 더해 아래 **가늠 고유 린트**를 적용합니다.

| 규칙(rule) | 수준 | 설명 |
|------|:---:|------|
| `uuid-lowercase` | error | `id`·`req_id` UUID는 **소문자만** 허용 (대문자 = 규약 위반) |
| `is-control-false` | error | telemetry `payload.is_control` 은 반드시 `false` |
| `type-controlplane` | error | `type` 은 `telemetry`/`info` 만. `command`·`result` 등 제어평면 입력 거부 |
| `type-mismatch` | error | 선언된 `type` 이 `--type` 지정과 불일치 |
| `type-missing` | error | auto 모드에서 `type` 필드가 없어 프로필 판별 불가 |
| `unknown-field` | warn (strict→error) | 스키마에 없는 추가 필드 (오타 조기검출) |
| `ms-heuristic` | warn | `event_time`/`ingest_time` 이 초 단위로 의심(표준은 ms 정수) |
| `schema-version` | warn | `schema_version` != `1.0` |
| `required`/`type`/`pattern`/`min-items`/`enum`/`const` … | error | JSON Schema 위반 |

> **미지 필드 기본 비강제**: 표준은 하위호환을 위해 서버가 미지 필드를 무시합니다.
> 따라서 기본 검증에서 추가 필드는 통과(warn)시키되, `--strict` 에서 error 로 승격합니다.

## 개발

```bash
make vet     # go vet ./...
make test    # go test ./...  (testdata/phase1 의 valid/invalid 케이스 검증)
make smoke   # 바이너리 스모크 (valid→0, invalid→1)
```

테스트 데이터는 `testdata/phase1/valid/`(유효)·`testdata/phase1/invalid/`(위반)에 있으며,
각 위반 파일은 파일명이 트리거하는 규칙을 나타냅니다.

## Phase2 — 제어 conformance (자기시험)

Phase2는 제어평면(`command`/`response`/`result`) **스키마 검증**과 다운링크 명령의
**detached JWS(ES256/EdDSA) 서명 검증·서명**을 오프라인으로 자기시험합니다
(표준 01 §5·§4.2·부록 A, 04 §4~6). **테스트 전용**(테스트 키·`TEST-*` rtu·실발전소 없음).

- 서명 라이브러리: `github.com/go-jose/go-jose/v4`(JWS), `github.com/gowebpki/jcs`(RFC 8785 JCS)
- 스키마 4종(phase2 common/command/response/result)도 바이너리에 내장.

### 서명 규격 (부록 A 요약)

- **포맷**: JWS(RFC 7515) **detached** — `signature` 필드엔 `protectedHeader..signature`만 담김.
- protected header = `{"alg":"ES256","kid":"<key_id>"}` (Ed25519 시 `"alg":"EdDSA"`).
- **알고리즘 allowlist [ES256, EdDSA]**, `alg:"none"`·목록 외 거부(RFC 8725).
- **서명 대상 5필드** `{id, rtu_id, max_power_w, issued_at, ttl_sec}` 를 **RFC 8785(JCS)** 로
  canonical 직렬화 후 서명. `ttl_sec` 생략 시 **양측 기본값 120 주입** 후 직렬화.
- **검증 절차**: ① alg allowlist·none 거부 → ② `key_id`로 공개키 조회(미지 key_id fail-closed 거부)
  → ③ 5필드 JCS canonical → ④ ES256/EdDSA 서명 검증. 실패 시 `failure_reason=PERMISSION_DENIED`.

> **스코프 경계**: `verify-command`의 서명 검증은 5필드(`id, rtu_id, max_power_w, issued_at,
> ttl_sec`)의 **진정성·무결성만 보증**한다. `issued_at`/`ttl_sec`은 서명 대상 바이트에는
> 포함되지만 **검증 로직에서 거부 조건으로 쓰이지 않으며**, 재생 방지(replay)·만료(freshness/TTL)
> 강제는 수행하지 않는다. 실집행 시점의 안전(재생 차단·만료 검사)은 소비자/브로커(prod)가
> 책임진다.

### 협력사 제어 자기시험 절차

```bash
# 0) 테스트 키페어 생성 (ES256 P-256; Ed25519 옵션은 --alg ed25519)
ganeum gen-key --alg es256 --priv priv.pem --pub pub.pem --key-id haezoom-ctrl-2026-07

# 1) 명령 payload(헤더+payload, 서명 전)를 참조 서명기로 서명 → 완성 command
ganeum sign-command --privkey priv.pem --key-id haezoom-ctrl-2026-07 cmd_unsigned.json > cmd.json

# 2) 완성 command 의 서명을 검증 (부록 A.4 절차)
ganeum verify-command --pubkey pub.pem --key-id haezoom-ctrl-2026-07 cmd.json
#   PASS → exit 0 / FAIL(PERMISSION_DENIED) → exit 1

# 3) 제어평면 스키마 검증 (command/response/result)
ganeum validate --profile phase2 --kind auto ./control_out
ganeum verify-command --format json --pubkey pub.pem --key-id haezoom-ctrl-2026-07 cmd.json | jq .
```

### 골든 테스트벡터

`testdata/phase2/vectors/` 에 유효 4건·위반 5건 + 테스트 키페어 + `manifest.json`(기대 canonical hex 고정)이 있습니다.

| 구분 | 벡터 | 기대 |
|------|------|------|
| 유효 | `valid_basic` / `valid_ttl_omitted`(120 주입) / `valid_ed25519` / `expired_ref`(참고) | accept |
| 위반 | `bad_sig_tampered`(서명 변조) | PERMISSION_DENIED(signature) |
| 위반 | `bad_alg_none`(alg:none) | PERMISSION_DENIED(alg-allowlist) |
| 위반 | `bad_unknown_key_id`(미지 key_id) | PERMISSION_DENIED(unknown-key-id) |
| 위반 | `bad_field_max_power` / `bad_field_id`(5필드 변조) | PERMISSION_DENIED(signature) |

> `expired_ref`는 서명 자체는 유효하되 `issued_at`이 과거입니다. **만료 판정은 런타임 검증 절차
> step6(`issued_at`+`ttl_sec`, NTP 기준)** 이며 Part1 서명검증 범위 밖이라 서명검증은 accept 입니다.

## 범위 밖 (가늠 아님)

broker 실접속·mTLS 실인증서·`…/keys` 토픽 키교체·모의 발행 루프(Part2, stg broker),
런타임 replay/만료(step6~7) 강제, 시뮬레이터는 포함하지 않습니다. 실제 제어는 prod broker 몫입니다.
