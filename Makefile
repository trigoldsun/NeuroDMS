# DocVault 开发入口
# 只收录当前真实可用的目标，未实现的能力不写进来（避免"看起来有、其实没有"）
#
# 注意：
#  - 本机（Windows）默认没有 make，请优先用 scripts/check.sh。
#  - test-race 需要 CGO 与 gcc；Windows 需安装 TDM-GCC 或 MinGW 后才能跑。

.PHONY: help fmt vet test test-race cover build run clean

help:
	@echo "make fmt       格式化"
	@echo "make vet       静态检查"
	@echo "make test      单元测试"
	@echo "make test-race 竞态检测（需 CGO + gcc）"
	@echo "make cover     覆盖率（authz 核心包）"
	@echo "make build     构建 API 二进制到 bin/"
	@echo "make run       本地开发启动（development 形态）"
	@echo "无 make 时用：bash scripts/check.sh"

fmt:
	gofmt -w ./cmd ./internal

vet:
	go vet ./...

test:
	go test ./... -count=1

test-race:
	go test ./... -race -count=1

cover:
	go test ./internal/authz/ -cover -count=1

build:
	go build -trimpath -o bin/docvault-server ./cmd/server

run:
	DOCVAULT_MODE=development DOCVAULT_HTTP_ADDR=:8080 go run ./cmd/server

clean:
	rm -rf bin
