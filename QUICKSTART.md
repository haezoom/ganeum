# 가늠 (ganeum) QUICKSTART — Phase1 협력사 배포판

> 본 문서는 해줌 stg 온보딩 절차(Phase1 모니터링) 5단계 "로컬 자기시험"을 위한 **가늠** CLI 사용 안내입니다.
> 대상 범위는 **Phase1(telemetry·info)** 뿐입니다. 제어(Phase2) 기능은 이 패키지에 포함되지 않습니다.

---

## 1. 가늠이 무엇인가 / 아닌가

- **가늠은 broker에 실제로 접속하기 전에, 협력사가 자사 PC·서버에서 telemetry·info payload의 표준 적합성을 오프라인으로 스스로 검증하는 도구**입니다.
- 인터넷·해줌 인프라 연결 없이 로컬 JSON 파일만으로 동작합니다.
- **가늠은 MQTT 클라이언트가 아닙니다.** broker 접속·publish·구독을 수행하지 않으며, 실제 stg publish(온보딩 절차 ⑥)는 협력사의 자체 MQTT 클라이언트로 별도 수행합니다.
- 가늠이 통과시킨 payload라도, 다음은 별도로 충족해야 합니다.
  - 실제 발행 주기(1분 이내)·MQTT 5.0/TLS 1.3 연결·`rtu_id` 매핑 등 온보딩 절차의 다른 항목
  - **검증한 payload와 broker에 실제로 발행되는 바이트가 동일한지.** 가늠은 건네받은 파일만 읽습니다 — 그 파일이 실제로 발행되는 바이트와 같은지는 보지 않습니다. 직렬화 계층이나 전송 래퍼가 한 겹 더 감싸면 가늠은 전건 통과인데 broker에 도착하는 바이트는 규격을 벗어납니다.

**실제 발행 바이트를 그대로 검증하는 방법.** publish 호출에 넘기는 바로 그 값을 발행 직전에 파일로 남기고, 그 파일을 §6 자기시험에 넣습니다. 그 값을 만들기 전의 객체를 저장하면 같은 빈틈이 그대로 남습니다.

```python
# publish 직전 — payload 는 client.publish(topic, payload) 에 넘기는 그 값
open("out/%d.json" % int(time.time() * 1000), "wb").write(
    payload if isinstance(payload, bytes) else payload.encode("utf-8"))
client.publish(topic, payload)
```

## 2. 패키지 구성

```
ganeum-stg-phase1/
├── bin/
│   ├── ganeum_linux_amd64
│   ├── ganeum_linux_arm64
│   ├── ganeum_darwin_amd64
│   ├── ganeum_darwin_arm64
│   └── ganeum_windows_amd64.exe
├── samples/
│   ├── telemetry_sample.json
│   └── info_sample.json
├── QUICKSTART.md      (본 문서)
└── SHA256SUMS
```

플랫폼에 맞는 바이너리 하나만 사용하면 됩니다.

| 환경 | 바이너리 |
|------|----------|
| Linux (x86_64) | `bin/ganeum_linux_amd64` |
| Linux (ARM64) | `bin/ganeum_linux_arm64` |
| macOS (Intel) | `bin/ganeum_darwin_amd64` |
| macOS (Apple Silicon) | `bin/ganeum_darwin_arm64` |
| Windows (x86_64) | `bin\ganeum_windows_amd64.exe` |

스키마(common/telemetry/info)는 바이너리에 내장되어 있어 별도 파일이 필요 없습니다.

## 3. 무결성 검증 (반드시 가장 먼저 수행)

패키지를 받으면 실행 전에 `SHA256SUMS`로 파일 위변조 여부를 먼저 확인합니다.

**Linux:**
```bash
sha256sum -c SHA256SUMS
```

**macOS:**
```bash
shasum -a 256 -c SHA256SUMS
```

**Windows (PowerShell / cmd):**
```
CertUtil -hashfile bin\ganeum_windows_amd64.exe SHA256
```
출력된 해시값을 `SHA256SUMS` 파일 내 `bin/ganeum_windows_amd64.exe` 항목의 값과 육안으로 대조합니다.

모든 파일이 `OK`(또는 값 일치)로 나와야 다음 단계로 진행합니다. 값이 다르면 해당 파일을 재전달받으십시오.

## 4. 실행 권한 부여 및 버전 확인

**Linux / macOS:**
```bash
chmod +x bin/ganeum_linux_amd64
./bin/ganeum_linux_amd64 version
```

**Windows:** 별도 실행 권한 설정 없이 바로 실행합니다.
```
bin\ganeum_windows_amd64.exe version
```

버전·빌드정보가 출력되면 정상입니다.

## 5. 샘플로 사전 확인

패키지에 포함된 `samples/` 디렉토리로 먼저 동작을 확인합니다.

```bash
./bin/ganeum_linux_amd64 validate --profile phase1 samples/
```

`telemetry_sample.json`·`info_sample.json` 2건 모두 `PASS`, 종료코드 `0`이 기대됩니다.

```
PASS  samples/telemetry_sample.json  (type=telemetry)
PASS  samples/info_sample.json  (type=info)

2 passed, 0 failed
```

이 단계가 실패하면 패키지 손상 또는 잘못된 바이너리 사용 가능성이 있으니 §3 무결성 검증부터 다시 확인합니다.

### 골든 벡터(`testdata/`)는 배포 패키지에 없습니다

이 패키지의 `samples/` 에는 통과 예시 2건만 들어 있습니다. **통과해야 하는 것과 실패해야 하는 것을 모두 담은 골든 벡터(`testdata/`)는 배포 패키지에 포함되지 않으며, 저장소에만 있습니다.**

<https://github.com/haezoom/ganeum/tree/v0.1.0/testdata>

- `testdata/phase1/valid/` — 통과해야 하는 벡터 4건
- `testdata/phase1/invalid/` — 실패해야 하는 벡터 12건 (단위·타입·시각 형식·`rtu_id` 문자셋 등)

자사 검증 파이프라인이 **실패해야 할 것을 실제로 실패시키는지** 확인할 때 씁니다. 통과 벡터만으로는 그것을 알 수 없습니다.

## 6. 자사 payload 자기시험

자사 RTU/게이트웨이가 생성한 telemetry·info JSON payload를 디렉토리(`./out` 등)에 모아 검증합니다.

```bash
# 디렉토리 전수 검사
./bin/ganeum_linux_amd64 validate --profile phase1 ./out

# 오타 등 미지 필드까지 조기 검출 (권장)
./bin/ganeum_linux_amd64 validate --profile phase1 --strict ./out

# CI/파이프라인용 기계 판독 (파일당 NDJSON 한 줄) — 실패건만 추출 예시
./bin/ganeum_linux_amd64 validate --profile phase1 --format json ./out | jq -c 'select(.ok==false)'
```

- `--profile phase1` : Phase1(telemetry·info) 검증 프로필. 현재 배포판은 이 프로필만 사용합니다.
- `--strict` : 스키마에 없는 추가 필드(warn)를 error로 승격 — 필드명 오타를 조기에 잡아냅니다.
- `--format json` : 사람이 읽는 text 대신 기계 판독용 NDJSON을 출력합니다. `jq`로 실패건만 필터링하면 CI에 연동하기 좋습니다.

### 종료코드

| 코드 | 의미 |
|:---:|------|
| `0` | 전건 통과 |
| `1` | 하나 이상 검증 실패 |
| `2` | 사용법/입력 오류 (잘못된 플래그, 없는 경로 등) |

온보딩 절차 ⑤(로컬 자기시험) 통과 기준은 telemetry·info **전수 스키마 검증 통과율 100%**(exit `0`)입니다. 실패 항목은 출력된 `path`·`rule`·안내 문구를 참고해 수정 후 재시험합니다.

## 7. 자주 걸리는 항목 및 추가 문의

단위·타입(전력은 정수 W, 에너지는 정수 Wh)·시각(UTC epoch ms 정수)·`rtu_id` 문자셋·`status`별 필수 필드 등 자주 발생하는 실수는 온보딩 절차서 §6 "자주 걸리는 항목 체크리스트"에 정리되어 있습니다. publish(온보딩 절차 ⑥) 전 해당 체크리스트도 함께 확인하십시오.

가늠 도구 자체의 사용법 문의, 그 외 온보딩 신청·일정·스키마 문의는 온보딩 절차서 §7 문의 채널로 연락합니다.

---

**범위 안내**: 본 패키지는 Phase1(모니터링: telemetry·info) 자기시험 전용입니다. 제어(Phase2: command/response/result, 서명검증)는 포함되지 않으며, 별도 온보딩 절차로 안내됩니다. broker 실접속 정보(호스트·포트·자격증명)는 온보딩 신청 접수 후 별도 안내됩니다.
