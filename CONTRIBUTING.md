# 贡献指南

感谢您对QUIC Go项目的关注和贡献！

## 开发环境

### 前置要求

- Go 1.21 或更高版本
- Git

### 克隆项目

```bash
git clone https://github.com/quic-go/quic.git
cd quic
```

### 安装依赖

```bash
make deps
```

## 开发流程

### 1. 分支命名规范

- 功能开发：`feature/功能描述`
- Bug修复：`bugfix/问题描述`  
- 文档更新：`docs/更新内容`

### 2. 代码规范

#### 格式化
使用Go标准格式化工具：
```bash
make format
```

#### 静态分析
运行静态分析检查：
```bash
make vet
make lint  # 需要安装golangci-lint
```

#### 命名规范
- 包名：小写，简短，有意义
- 函数名：驼峰命名法
- 变量名：驼峰命名法
- 常量名：大写，下划线分隔
- 接口名：以`er`结尾（如`Reader`, `Writer`）

#### 注释规范
- 所有公开的类型、函数、方法都必须有注释
- 注释以类型/函数名开头
- 注释应该解释"做什么"和"为什么"，而不仅仅是"怎么做"

示例：
```go
// Connection 表示一个QUIC连接，提供可靠的、多路复用的数据传输
type Connection interface {
    // OpenStream 创建一个新的双向流
    // 返回的流可以用于发送和接收数据
    OpenStream() (Stream, error)
}
```

### 3. 测试

#### 运行测试
```bash
make test
```

#### 测试覆盖率
```bash
make test-coverage
```

#### 基准测试
```bash
make benchmark
```

#### 集成测试
```bash
go test -tags=integration ./...
```

#### 测试规范
- 测试函数命名：`TestFunctionName`
- 基准测试命名：`BenchmarkFunctionName`
- 使用表驱动测试处理多个测试用例
- 每个测试应该独立，不依赖其他测试的执行顺序

### 4. 提交规范

#### 提交消息格式
```
<类型>(<范围>): <描述>

<可选的正文>

<可选的脚注>
```

类型包括：
- `feat`: 新功能
- `fix`: Bug修复
- `docs`: 文档更新
- `style`: 代码格式化（不影响功能）
- `refactor`: 代码重构
- `perf`: 性能优化
- `test`: 测试相关
- `chore`: 构建过程或辅助工具的变动

示例：
```
feat(stream): 添加流优先级支持

实现了RFC 9218中定义的流优先级机制，允许应用程序
为不同的流设置不同的优先级。

Closes #123
```

### 5. Pull Request流程

1. Fork项目到你的GitHub账户
2. 创建功能分支：`git checkout -b feature/my-new-feature`
3. 进行开发并提交：`git commit -am 'feat: 添加新功能'`
4. 推送到GitHub：`git push origin feature/my-new-feature`
5. 创建Pull Request

#### PR要求
- PR标题简洁明了
- PR描述详细说明变更内容和原因
- 包含相关的测试
- 确保所有测试通过
- 确保代码格式化正确
- 如果是Bug修复，包含重现步骤

## 项目结构

```
quic/
├── internal/           # 内部实现包
│   ├── packet/        # 数据包处理
│   ├── connection/    # 连接管理
│   ├── stream/        # 流管理
│   ├── crypto/        # 加密处理
│   └── congestion/    # 拥塞控制
├── examples/          # 示例代码
│   ├── server/        # 服务器示例
│   └── client/        # 客户端示例
├── benchmarks_test.go # 基准测试
├── integration_test.go # 集成测试
├── quic.go           # 公共API
├── go.mod            # Go模块文件
└── README.md         # 项目说明
```

## 实现指南

### QUIC协议特性

本项目实现了以下QUIC协议特性：

1. **数据包格式**: RFC 9000定义的长包头和短包头
2. **帧类型**: STREAM、ACK、PADDING、PING、CRYPTO等
3. **连接管理**: 连接建立、握手、关闭
4. **流管理**: 多路复用流、流控制
5. **加密**: TLS 1.3集成、包头保护
6. **拥塞控制**: CUBIC算法实现
7. **丢包恢复**: 快速重传、超时重传

### 添加新功能

如果要添加新的QUIC特性：

1. 在`internal/`相应包中添加实现
2. 更新公共API（如果需要）
3. 添加详细的测试
4. 更新文档
5. 考虑性能影响

### 性能优化

- 避免不必要的内存分配
- 使用对象池来重用频繁分配的对象
- 优化热点路径的代码
- 添加基准测试来衡量性能影响

## 调试技巧

### 启用调试日志
```bash
export QUIC_DEBUG=1
go run examples/server/main.go
```

### 使用Go工具
- `go tool pprof`: 性能分析
- `go tool trace`: 执行跟踪  
- `dlv`: 调试器

### 网络调试
- 使用Wireshark分析QUIC流量
- 启用详细的连接日志
- 检查拥塞控制状态

## 发布流程

1. 更新版本号
2. 更新CHANGELOG.md
3. 创建release标签
4. 发布到GitHub Releases

## 获得帮助

- 创建Issue讨论新功能或报告Bug
- 查看项目Wiki了解更多技术细节
- 参考QUIC RFC文档了解协议详情

## 行为准则

请遵循友善、包容的行为准则：

- 尊重所有贡献者
- 接受建设性的反馈
- 专注于对项目最有利的事情
- 对新手保持耐心和帮助态度

感谢您的贡献！
