# 가늠 ESS 프로필 (`ganeum ess`) — DRAFT

**해줌 ESS 제어·모니터링 표준 v0.2**(Draft)에 맞춰 협력사가 보내고 받는 MQTT 메시지를 **broker 에 붙기 전에 로컬에서 스스로 검증**합니다.
태양광 프로필(phase1·phase2)과 같은 바이너리(`ganeum`)에 들어 있으며, ESS 기능은 `ganeum ess <서브커맨드>` 로 씁니다.

> ⚠️ **DRAFT** — 표준이 v0.2(Draft)이므로 ESS 프로필도 초안입니다. 범위·미구현·협의 중 항목은 [`DRAFT_NOTES.md`](DRAFT_NOTES.md) 를 보십시오.

## 무엇을 하나

| 서브커맨드 | 하는 일 | 근거 |
|---|---|---|
| `ess validate` | telemetry·info·command·response·result **스키마 검증** + 스키마로 표현되지 않는 **규칙(R-1~R-12)** + 단위·시각·식별자 린트 | 04 §1~§7, 01 §2~§5 |
| `ess validate --info` | 같은 자원의 info 와 대조: **R-2 해상도·R-4 bms_capabilities·R-5 PV·R-6 SoC 범위·R-9 운전모드**, PCS id·정격 합 | 04 §7.1 |
| `ess validate --command` | response/result 가 대상 명령과 맞는지: req_id, **readback**, **R-8 override 되읽기** | 01 §4.2·§5.3 |
| `ess validate --topic` | 토픽 ↔ type(**R-10**), 토픽 rtu_id ↔ 헤더 rtu_id(**R-11** 일부) | 01 §3.2·§3.3 |
| `ess verify-command` | 제어 명령 **서명 검증** — 부록 A.4 1~5단계 + `--now` 로 6단계(만료·스큐) + `--dedup` 로 7단계(id 중복) | 01 부록 A |
| `ess sign-command` | **참조 서명기**(ES256 / Ed25519) — 발행측 구현 대조용 | 01 부록 A.2·A.3 |
| `ess canonical` | 명령의 서명 대상 body·JCS canonical·SHA-256·signing input 출력 (서명 불일치 디버깅) | 01 부록 A.3 |
| `ess golden` | **골든 테스트 벡터 v0.2** 16건 실행 (내장). 기대 결과 `PASS 16 / FAIL 0` | 01 부록 A.5 |
| `ess respond` | **참조 EMS 판정기** — 명령 + info(+telemetry·상태)를 넣으면 표준 EMS 가 내야 할 **ACK(response)** 와 판정 근거를 출력 | 01 §5·§6 |
| `ess gen-key` / `ess keystore` | 시험용 키페어 생성, 공개키 PEM → keystore.json | 부록 A.1 |
| `ess sample` / `ess schema` | 표준 예시 메시지(명령은 시험 키로 서명됨)·내장 JSON Schema 출력 | 01 §4·§5, 04 |

기존 명령에 `--profile ess` 를 붙여도 같습니다: `ganeum validate --profile ess …`, `ganeum verify-command --profile ess …`, `ganeum sign-command --profile ess …`.

## 빠른 시작

```bash
ganeum ess golden                                     # 서명 계층 자기시험: PASS 16 / FAIL 0
ganeum ess validate my_payloads/                      # 내 메시지 전수 검증
ganeum ess validate --info my_info.json my_telemetry.json
ganeum ess verify-command --keystore keystore.json --now now received_command.json
```

자세한 사용법은 [`QUICKSTART.md`](QUICKSTART.md).

## 검증 근거

- 스키마는 `ESS_제어_표준/04_JSON스키마_협력사용.md` (v0.2, 2026-09-07) 의 6개 JSON Schema 를 **수정 없이** 내장했습니다(`internal/ess/schema/ess/`).
- ESS 서명 규칙(A.3 모드별 키 집합)은 태양광 5필드 서명과 달라 `internal/ess/control` 에 따로 구현했습니다. 골든 벡터 16건에서 **canonical 바이트·SHA-256 까지 기대값과 일치**하며, 이 도구로 서명한 명령은 `verify_golden.py`(Python 참조 검증기)로도 통과합니다.
- 추가 외부 의존성은 없습니다(JCS·ECDSA·Ed25519 는 표준 라이브러리로 구현).

## 소스 위치

```
cmd/ganeum/ess.go           ganeum ess 서브커맨드
internal/ess/schema/ess/    ESS v0.2 JSON Schema 6종 (04 원문 그대로)
internal/ess/validate/      스키마 검증 + R-1~R-12 + 교차 규칙 + 미지 필드
internal/ess/control/       A.3 서명 body · JWS(ES256/EdDSA) · A.4 검증 1~7단계
internal/ess/jcs/           RFC 8785 (정수 전용)
internal/ess/golden/data/   골든 테스트 벡터 v0.2 (양성 9 · 음성 7, 시험 키)
internal/ess/emulate/       참조 EMS 판정기 (ess respond)
internal/ess/samples/data/  01 표준 예시 메시지 8종
internal/ess/report/        결과 출력
testdata/ess/               valid 8 · invalid 42 (+ invalid_manifest.json 기대 규칙)
```

테스트: `go test ./internal/ess/...` · 스모크: `make smoke-ess`
