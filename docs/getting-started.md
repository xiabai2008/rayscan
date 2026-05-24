# 快速入门

## 安装

### 从源码安装

```bash
git clone https://github.com/xiabai2004/RayScan
cd RayScan
pip install -e ".[dev]"
```

### Docker

```bash
docker build -t rayscan .
docker run rayscan scan http://example.com

# 或使用 docker-compose
TARGET_URL=http://example.com docker-compose up
```

### 使用 pip

```bash
pip install git+https://github.com/xiabai2004/RayScan.git
```

## 基本使用

### 扫描单个目标

```bash
# 快速扫描（控制台输出 + 自动保存 JSON 报告）
python -m wvs scan http://example.com

# 指定输出格式和路径
python -m wvs scan http://example.com -o report.html -f html

# 仅扫描特定模块
python -m wvs scan http://example.com --modules sqli xss

# 排除特定模块
python -m wvs scan http://example.com --no-modules ssrf xxe
```

### 批量扫描

```bash
# 准备目标文件（每行一个 URL）
echo "http://target1.com" > targets.txt
echo "http://target2.com" >> targets.txt

# 执行批量扫描
python -m wvs batch targets.txt -o batch_results.json
```

### 查看可用模块

```bash
python -m wvs list-modules
```

### 带认证扫描

```bash
# 表单登录
python -m wvs scan http://example.com \
  --auth-type form \
  --login-url http://example.com/login \
  --username admin --password secret

# Bearer Token
python -m wvs scan http://example.com \
  --auth-type bearer --token eyJhbG...

# Cookie
python -m wvs scan http://example.com \
  --auth-type cookie --cookies "PHPSESSID=abc123"
```

### 使用脚本扫描

```python
import asyncio
from wvs.config import ConfigManager
from wvs.core import HTTPPool, WAVScanner
from wvs.models import ScanTarget

async def my_scan():
    config = ConfigManager()
    config.set("crawl_depth", 2)

    session = HTTPPool(config)
    scanner = WAVScanner(config, session)
    scanner.load_all_modules()

    target = ScanTarget(url="http://your-target.com")
    result = await scanner.scan(target)

    print(f"发现 {len(result.vulnerabilities)} 个漏洞")

asyncio.run(my_scan())
```

## 配置

核心配置在 `wvs/config.py` 中，常用可调参数：

| 参数 | 说明 | 默认值 |
|------|------|:------:|
| `crawl_depth` | 爬取深度 | 2 |
| `crawl_max_urls` | 最大爬取 URL 数 | 100 |
| `concurrent_endpoints` | 并发检测数 | 10 |
| `timeout` | 请求超时 (秒) | 15 |
| `verify_ssl` | SSL 证书验证 | False |
| `retry_count` | 失败重试次数 | 1 |

## 扫描报告

扫描完成后，结果自动保存在 `scan_reports/` 目录（除非指定了 `-o`）。

```bash
# 查看最近生成的报告
ls -la scan_reports/
```

支持的报告格式：
- `json` — 结构化数据，适合程序处理（默认）
- `html` — 可视化 HTML 报告
- `markdown` — Markdown 格式
- `csv` — 表格格式
