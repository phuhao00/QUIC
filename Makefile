# QUIC Go项目 Makefile

.PHONY: all build test clean run-server run-client format vet lint deps

# 默认目标
all: test build

# 编译项目
build:
	@echo "编译项目..."
	@go build -o bin/server ./examples/server
	@go build -o bin/client ./examples/client
	@echo "编译完成"

# 运行测试
test:
	@echo "运行测试..."
	@go test -v ./...
	@echo "测试完成"

# 运行测试并生成覆盖率报告
test-coverage:
	@echo "运行测试并生成覆盖率报告..."
	@go test -v -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "覆盖率报告已生成: coverage.html"

# 运行基准测试
benchmark:
	@echo "运行基准测试..."
	@go test -bench=. -benchmem ./...

# 格式化代码
format:
	@echo "格式化代码..."
	@go fmt ./...

# 静态分析
vet:
	@echo "运行go vet..."
	@go vet ./...

# 代码检查 (需要安装golangci-lint)
lint:
	@echo "运行代码检查..."
	@golangci-lint run ./...

# 安装依赖
deps:
	@echo "下载依赖..."
	@go mod tidy
	@go mod download

# 清理生成的文件
clean:
	@echo "清理文件..."
	@rm -rf bin/
	@rm -f coverage.out coverage.html
	@echo "清理完成"

# 运行服务器示例
run-server: build
	@echo "启动QUIC服务器..."
	@./bin/server

# 运行客户端示例
run-client: build
	@echo "启动QUIC客户端..."
	@./bin/client

# 创建二进制文件目录
bin:
	@mkdir -p bin

# 编译时创建目录
build: bin

# 帮助信息
help:
	@echo "可用命令:"
	@echo "  all           - 运行测试并编译项目"
	@echo "  build         - 编译项目"
	@echo "  test          - 运行测试"
	@echo "  test-coverage - 运行测试并生成覆盖率报告"
	@echo "  benchmark     - 运行基准测试"
	@echo "  format        - 格式化代码"
	@echo "  vet           - 运行go vet"
	@echo "  lint          - 运行代码检查"
	@echo "  deps          - 安装依赖"
	@echo "  clean         - 清理生成的文件"
	@echo "  run-server    - 运行服务器示例"
	@echo "  run-client    - 运行客户端示例"
	@echo "  help          - 显示此帮助信息"
