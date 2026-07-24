BINARY   := ganeum
PKG      := ./cmd/ganeum
DIST     := dist
VERSION  ?= 0.1.0
COMMIT   := $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
DATE     := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.date=$(DATE)

# GOOS/GOARCH cross-compile targets (지시서 §6: 최소 3종).
PLATFORMS := darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64

.PHONY: all build test vet fmt smoke build-all clean

all: vet test build

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

# 로컬 자기시험 스모크: valid -> exit0, invalid -> exit1
smoke: build
	./$(BINARY) validate testdata/phase1/valid
	@echo "--- phase1 invalid (기대 종료코드 1) ---"
	@./$(BINARY) validate testdata/phase1/invalid/is_control_true.json; test $$? -eq 1 && echo "OK: 종료코드 1"
	@echo "--- phase2 서명 검증: 유효 (기대 종료코드 0) ---"
	./$(BINARY) verify-command --pubkey testdata/phase2/vectors/test_es256_pub.pem \
		--key-id haezoom-ctrl-2026-07 testdata/phase2/vectors/valid/valid_basic.json
	@echo "--- phase2 서명 검증: 서명 변조 (기대 종료코드 1) ---"
	@./$(BINARY) verify-command --pubkey testdata/phase2/vectors/test_es256_pub.pem \
		--key-id haezoom-ctrl-2026-07 testdata/phase2/vectors/invalid/bad_sig_tampered.json; \
		test $$? -eq 1 && echo "OK: 종료코드 1"

build-all: $(PLATFORMS)

$(PLATFORMS):
	$(eval GOOS := $(word 1,$(subst /, ,$@)))
	$(eval GOARCH := $(word 2,$(subst /, ,$@)))
	$(eval EXT := $(if $(filter windows,$(GOOS)),.exe,))
	@mkdir -p $(DIST)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(LDFLAGS)" \
		-o $(DIST)/$(BINARY)_$(GOOS)_$(GOARCH)$(EXT) $(PKG)
	@echo "built $(DIST)/$(BINARY)_$(GOOS)_$(GOARCH)$(EXT)"

clean:
	rm -rf $(BINARY) $(DIST)
