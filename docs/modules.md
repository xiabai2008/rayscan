# 检测模块说明

RayScan 提供 11 个检测模块，涵盖 OWASP Top 10 常见 Web 漏洞。

## 模块列表

| 模块 | 检测能力 | 覆盖 OWASP |
|------|----------|:----------:|
| `sqli` | SQL 注入 (error/union/boolean-blind/time-based/stacked) | A03:2021 |
| `xss` | 跨站脚本 (反射型/存储型) | A03:2021 |
| `cmdi` | 命令注入 | A03:2021 |
| `lfi` | 本地文件包含 | A01:2021 |
| `rce` | 远程代码执行 | A03:2021 |
| `ssrf` | 服务端请求伪造 | A10:2021 |
| `xxe` | XML 外部实体注入 | A05:2021 |
| `api` | API 安全检测 | API Security Top 10 |
| `sensitive` | 敏感信息泄露 | A04:2021 |
| `waf` | WAF 检测与绕过 | — |
| `jspathfinder` | JavaScript 端点发现 | — |

## 模块架构

每个检测模块遵循统一的结构：

```
modules/
├── base.py              # 基类: BaseDetector
├── sqli/
│   ├── detector.py      # 主检测逻辑
│   ├── payloads.py      # 测试 Payload
│   ├── analyzer.py      # 响应分析
│   └── techniques_mixins.py  # 注入技术混合
├── xss/
│   ├── detector.py      # 主检测逻辑
│   └── payloads.py      # XSS Payload
├── cmdi/
│   ├── detector.py
│   └── payloads.py
├── ...
```

### 模块基类 (`BaseDetector`)

所有模块继承 `BaseDetector`，提供统一的接口：

```python
class BaseDetector:
    async def detect(self, url: str, param: str, value: str) -> Optional[Vulnerability]: ...
    async def batch_detect(self, targets: List[DetectTarget]) -> List[Vulnerability]: ...
    def set_oob_manager(self, manager): ...
```

## 各模块详情

### SQL 注入 (`sqli`)

- **检测技术**: error-based / union / boolean-blind / time-based / stacked queries
- **数据库支持**: MySQL, PostgreSQL, MSSQL, Oracle, SQLite
- **特点**: 智能 payload 选择，减少无效请求；time-based 并发检测

### XSS (`xss`)

- **检测类型**: 反射型 (Reflected) / 存储型 (Stored)
- **Payload**: 事件处理器 / 伪协议 / 标签闭合 / 编码绕过
- **特点**: 参数采样优化，最多 4 个参数以减少请求量

### 命令注入 (`cmdi`)

- **检测**: 多种 OS 命令分隔符与执行方式
- **time-based 优化**: 并发延迟检测 + 本地延迟适配

### 本地文件包含 (`lfi`)

- **检测**: 目录遍历、PHP 伪协议、编码绕过
- **平台**: Linux / Windows 路径风格

### SSRF (`ssrf`)

- **检测**: 内网地址探测、云元数据接口、端口扫描
- **OOB 支持**: 结合 OOB 服务器检测 blind SSRF

### XXE (`xxe`)

- **检测**: 内联实体 / 外部实体 / blind OOB XXE
- **协议**: file / http / ftp / php://

### API 安全 (`api`)

- **检测**: REST API 端点安全、GraphQL 安全检查
- **方法**: 权限绕过、请求方法篡改、批量赋值

### 敏感信息泄露 (`sensitive`)

- **检测**: API Key / Token / 密码 / 密钥文件 / 云凭证
- **扫描范围**: 响应体、HTML 注释、JS 文件、robots.txt

### WAF 检测 (`waf`)

- **检测**: WAF 产品指纹识别、规则测试
- **绕过**: 编码混淆、大小写变换、注释插入、参数污染
