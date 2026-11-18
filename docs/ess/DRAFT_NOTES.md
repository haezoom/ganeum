# DRAFT NOTES — 가늠 ESS 프로필 (`ganeum ess`)

작성 2026-11-18 · 기준 표준: 해줌 ESS 제어·모니터링 표준 **v0.2 (Draft, 2026-09-07)**
목적: ESS 협력사가 **1단계 모니터링부터 바로 자기시험**할 수 있게 하고, 제어 단계 도구를 미리 갖춘다.

## 1. 표준 대비 구현 범위

| 표준 항목 | 구현 | 비고 |
|---|:---:|---|
| 04 §1~§6 JSON Schema 6종 | ✅ | 원문 그대로 내장 |
| R-1 IDLE ⇒ power_w=0 | ✅ | telemetry·command·slots·response·result·active_slot |
| R-2 슬롯 겹침·오름차순·start<end | ✅ | 단일 메시지 |
| R-2 해상도 배수 | ✅ | 단일 메시지는 5분 하한, `--info` 시 신고 해상도 |
| R-3 rack_online ≤ rack_total | ✅ | |
| R-4 bms_capabilities ↔ telemetry | ✅ | `--info` |
| R-5 pv.capacity_w ⇒ pv 블록 | ✅ | `--info` |
| R-6 soc 범위·순서 | ✅ | 순서는 단일, 범위는 `--info` |
| R-7 극성 휴지 | ⚠️ | 상태 의존 → `respond --last-polarity*` 로만 판정 |
| R-8 override readback | ✅ | `validate --command` |
| R-9 operation_mode ∈ 신고 목록 | ✅ | `--info` |
| R-10 type ↔ 토픽 | ✅ | `--topic` |
| R-11 3자 일치 | ⚠️ | 토픽↔헤더 rtu_id 일치만 검사 |
| R-12 SCHEDULE 금지 필드 | ✅ | 스키마 `not` + 규칙 |
| 부록 A.2 JWS detached·R‖S | ✅ | ES256 + EdDSA |
| 부록 A.3 모드별 키 집합 | ✅ | 골든 16/16, canonical 바이트 일치 |
| 부록 A.4 1~5단계 | ✅ | |
| 부록 A.4 6단계 만료·스큐 | ✅ | `--now` |
| 부록 A.4 7단계 dedup | ✅ | `--dedup`(파일 묶음 단위) |
| 01 §2.2 시각(ms) | ✅ | 초 단위 의심 탐지, ingest<event 경고 |
| 01 §2.4 UUID 소문자 | ✅ | 생성 규칙 → 경고(수신은 대소문자 무관) |
| 01 §5.3 ACK 규칙 | ✅ | accepted↔result, 평면 구조, readback |
| 01 §4.2 달성 판정 | ✅ | 방향 일치, 5% 오차 경고, IDLE=0 |
| 01 §6 failure_reason 판정 | ✅ | `respond` (PERMISSION_DENIED·BAD_REQUEST·UNSUPPORTED_CONTROL·LOCAL_MODE·SOC_LIMIT·POWER_LIMIT_EXCEEDED) |

## 2. 구현하지 않은 것 (이유)

| 항목 | 이유 |
|---|---|
| `…/keys` 토픽 메시지 검증·트러스트 앵커 체인 | 표준 v0.2 에 메시지 형식(스키마)이 없음(01 부록 A.1) |
| 결정적 서명(RFC 6979) | Go 표준 ECDSA 는 무작위 nonce. 서명값은 매번 달라도 검증은 동일. 바이트 재현이 필요하면 `verify_golden.py --regenerate` |
| 시험용 golden 외 ES256 벡터 추가(Ed25519) | 표준이 "채택 시 별도 제공"으로 둠. Ed25519 는 서명·검증 기능만 구현 |

## 3. 표준 해석이 필요한 곳 (협의 중)

도구는 아래를 **현재 문면대로** 동작시키고, 협의 결과에 따라 바꿉니다.

| 협의 항목 | 도구의 현재 동작 | 바꿀 곳 |
|---|---|---|
| 고정 충전값 vs PV 범위 내 상한 | 고정값으로 해석(readback·달성 판정 그대로) | `internal/ess/validate/rules.go lintResult` |
| 송전 상한을 avail_discharge_w 에 반영 | 허용 — avail 값만 정격 합 초과 시 경고 | `internal/ess/validate/context.go crossInfo` |
| avail_*_w AC/DC 기준 | 판정 안 함(정수 W 만 검사) | — |
| 두절 시 기존 자율운전 복귀 | **스키마가 거부** (failsafe_mode enum 3종 밖) — `testdata/ess/invalid/info_failsafe_custom.json` | 표준 enum 추가 시 스키마 교체 |
| 즉시 제어 해제(IDLE vs 스케줄 복귀) | 판정 안 함 | — |
| 가용 출력 초과: ACK 거부 vs 부분 수행 | 기본 **거부**(POWER_LIMIT_EXCEEDED), `ganeum ess respond --power-limit-partial` 로 반대 동작 | `internal/ess/emulate.Decide` |
| SCHEDULE result 발송 시점 | 문면대로 "등록 수락 시 1회" 안내만 | — |
| bms_alarm 다중 알람 | 스키마가 단일 객체 → 배열은 거부 | 표준 변경 시 스키마 교체 |

## 4. 다음 단계 제안

1. 1단계(모니터링)용 배포 묶음 제공(바이너리 + samples + golden)
2. 표준 v0.3/v1.0 반영 → DRAFT 표시 해제
3. 태양광 프로필과 공통인 JWS·keystore·report 코드를 한 패키지로 통합 (현재 `internal/ess/` 아래 별도 보유)
