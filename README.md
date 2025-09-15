# Go HTTPS Proxy

[![Go Version](https://img.shields.io/badge/go-1.19+-blue.svg)](https://golang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![DeepSeek Coder](https://img.shields.io/badge/Generated%20by-DeepSeek%20Coder-brightgreen.svg)](https://deepseek.com)

一个功能完整的HTTP/HTTPS代理服务器，支持MITM（中间人）方式的HTTPS流量拦截和解密，类似于Charles Proxy的功能。由DeepSeek Coder生成并优化。

## ✨ 特性

- 🔐 **完整的HTTPS支持** - 自动生成和管理CA证书
- 📝 **请求/响应记录** - 详细记录所有HTTP/HTTPS流量
- ⚡ **高性能** - 基于Go语言开发，并发性能优异
- 🔧 **易于使用** - 自动生成CA证书，一键启动
- 🛡️ **安全可靠** - 支持证书缓存和有效期管理
- 📊 **详细日志** - 可选的verbose模式记录完整流量详情

## 🚀 快速开始

### 安装

```bash
go get github.com/chenyu1990/go-web-debug-proxy
```

或直接下载编译：

```bash
git clone https://github.com/chenyu1990/go-web-debug-proxy.git
cd go-web-debug-proxy
go build -o proxy
```

### 使用方法

```bash
# 启动代理服务器（默认端口8888）
./proxy -v

# 指定端口启动
./proxy -port 8080 -v

# 使用自定义CA证书
./proxy -cert my-ca-cert.pem -key my-ca-key.pem -v
```

### 配置客户端

1. **安装CA证书**：
    - 首次运行时会自动生成`proxy-ca-cert.pem`
    - 将此证书安装到系统或浏览器的信任根证书库中

2. **配置代理**：
    - 设置系统或浏览器代理为：`127.0.0.1:8888`

## 📖 功能说明

### HTTP流量拦截
- 完整的HTTP请求/响应记录
- 头信息解析和显示
- 请求体内容记录

### HTTPS流量解密
- 动态证书生成
- TLS握手拦截
- 加密流量明文解析
- 证书缓存优化

### 详细日志输出
```log
HTTP Request: GET https://example.com/api/data
Headers: map[User-Agent:[Go-http-client/1.1] Accept-Encoding:[gzip]]
Request Body: {"key": "value"}
Response Status: 200 OK
Response Headers: map[Content-Type:[application/json]]
Response Body: {"result": "success"}
```

## 🛠️ 技术架构

```
客户端请求 --> 代理服务器 --> 检查HTTPS?
|
|-- 是 --> TLS握手拦截 --> 动态证书生成 --> 双向TLS代理 --> 目标服务器
|
|-- 否 --> 直接转发 --> 目标服务器
|
|--> 流量记录 --> 日志输出
```

## 🔧 配置选项

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-port` | 8888 | 代理服务器监听端口 |
| `-cert` | proxy-ca-cert.pem | CA证书文件路径 |
| `-key` | proxy-ca-key.pem | CA私钥文件路径 |
| `-v` | false | 启用详细日志模式 |


## ⚠️ 注意事项

1. **仅用于合法用途** - 请在授权环境下使用本工具
2. **证书安全** - 妥善保管CA私钥文件
3. **隐私保护** - 尊重用户隐私，遵守相关法律法规
4. **测试环境** - 建议仅在测试和学习环境中使用

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 🙏 致谢

本代码(包括readme)由 [DeepSeek Coder](https://deepseek.com) 生成和优化，感谢DeepSeek团队提供的强大AI编程助手。

---

**免责声明**: 本项目仅用于教育和技术研究目的。使用者应遵守当地法律法规，不得用于非法用途。作者不对滥用本项目造成的任何后果负责。