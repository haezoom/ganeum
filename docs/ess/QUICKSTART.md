# 가늠 ESS 프로필 QUICKSTART (DRAFT)

## 0. 준비

ESS 프로필은 `ganeum` 바이너리에 들어 있습니다. 설치·무결성 확인은 저장소 루트의 [QUICKSTART](../../QUICKSTART.md) 와 같습니다.

```bash
ganeum ess version
ganeum ess sample info > info.json            # 표준 예시를 파일로 받아 두기
ganeum ess sample telemetry > telemetry.json
ganeum ess sample command_immediate > command_immediate.json
```

## 1. 서명 계층 자기시험 (가장 먼저)

```bash
ganeum ess golden
# === 내장 golden_vectors_v0.2: PASS 16 / FAIL 0 (총 16) ===
```

자사 검증기가 같은 결과를 내는지는 저장소 `internal/ess/golden/data/` 의 `expected.canonical` 과 비교하십시오. **NEG-01·NEG-05·NEG-07** 은 양성 벡터만으로는 드러나지 않는 결함을 겨냥합니다.

## 2. 내가 보내는 메시지 검증 (모니터링 · 1단계)

**broker 에 실제로 발행하는 바이트 그대로**를 파일로 남겨 검사하십시오. 검증용으로 따로 만든 payload 는 래핑·필드 추가 같은 차이를 잡지 못합니다.

```bash
ganeum ess validate out/telemetry_0001.json out/info.json
ganeum ess validate out/                       # 디렉토리 전수
ganeum ess validate --strict out/              # 미지 필드 등 경고도 실패 처리
ganeum ess validate --topic v1/<vendor>/<rtu_id>/telemetry out/telemetry_0001.json
```

같은 자원의 info 와 대조(신고값 ↔ 실제 전송):

```bash
ganeum ess validate --info out/info.json out/telemetry_*.json
```

- R-4 `bms_capabilities` 에 신고한 항목이 telemetry 에 **있는지**, 신고 안 한 항목이 **없는지**
- R-5 `pv.capacity_w` 신고 시 telemetry `pv` 블록
- R-9 `ems.operation_mode` ∈ `info.ems.operation_modes`
- PCS id 일치, PCS 전력 합 ≤ 정격 합

## 3. 내가 받는 제어 명령 검증 (제어 · 2단계)

```bash
# 해줌이 준 keystore.json 으로 검증 (A.4 1~5)
ganeum ess verify-command --keystore keystore.json cmd.json

# 공개키 PEM 하나로 검증
ganeum ess verify-command --pubkey haezoom.pub.pem --key-id haezoom-ctrl-2026-11 cmd.json

# 운영과 같이 만료·스큐(6단계) + id 중복(7단계)까지
ganeum ess verify-command --keystore keystore.json --now now --dedup cmd1.json cmd2.json
```

서명이 안 맞을 때:

```bash
ganeum ess canonical cmd.json     # 서명 대상 body · canonical · sha256 · signing_input
```

자사 구현의 canonical 과 비교해 어긋난 곳을 찾습니다. 순서는 ① signing_body(A.3 키 집합) → ② canonical(JCS) → ③ signing_input → ④ R‖S 인코딩.

## 4. 내 EMS 판정과 비교 (respond)

명령을 받았을 때 표준 EMS 가 어떤 ACK 를 내야 하는지 보여 줍니다.

```bash
ganeum ess respond --test-keystore --info info.json --telemetry telemetry.json command_immediate.json

# 극성 휴지(R-7): 직전 CHARGE 전환 100초 뒤 DISCHARGE 명령
ganeum ess respond --test-keystore --info info.json \
  --now 1781000001000 --last-polarity CHARGE --last-polarity-at 1780999901000 \
  command_immediate.json        # → BAD_REQUEST

# 가용 출력 초과를 '수락 후 부분 수행'으로 보고 싶을 때 ([협의 필요])
ganeum ess respond ... --power-limit-partial cmd.json
```

판정 순서: 스키마·R-12 → 서명(A.4 1~5) → 만료(6) → 중복(7) → control_modes → 로컬모드 → R-2 해상도 → R-6 SoC 범위 → R-7 극성 휴지 → SoC 한계 → 가용 출력.

생성된 ACK 는 다시 검증할 수 있습니다.

```bash
ganeum ess respond --format json ... | jq .response > ack.json
ganeum ess validate --command cmd.json ack.json
```

## 5. response · result 검증

```bash
ganeum ess validate --command cmd.json out/ack.json out/result.json
```

- req_id = 명령 id (대소문자까지 그대로)
- ACK readback(`mode`·`direction`·`power_w` / `slots_count`)이 명령과 일치
- `override_polarity_gap=true` 로 수행한 명령은 result 에 `override_polarity_gap=true` (R-8)

## 6. 시험용 키로 명령 만들기 (해줌 발행측 · 자체 시험)

```bash
ganeum ess gen-key --priv test.pem --pub test.pub.pem
ganeum ess keystore --pub test.pub.pem --kid haezoom-ctrl-test-0002 > keystore.json
ganeum ess sample command_schedule > cmd.json
ganeum ess sign-command --privkey test.pem --key-id haezoom-ctrl-test-0002 --fresh --explain cmd.json > signed.json
ganeum ess verify-command --keystore keystore.json --now now signed.json
```

시험 키는 `haezoom-ctrl-test-*` 라벨을 쓰고 운영 키스토어에 넣지 마십시오(부록 A.1).

## 출력·종료코드

- `--format json` : 파일당 1줄 NDJSON (CI 연동용)
- `--show-info` : info 수준 안내(기본값 간주 등)도 표시
- 종료코드 `0` 통과 · `1` 검증 실패 · `2` 사용법/입력 오류
