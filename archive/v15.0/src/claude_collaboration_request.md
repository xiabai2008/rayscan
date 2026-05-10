# WVS v18.3 项目协作请求 - Claude Code

## 项目概述
- **项目名称**: WVS v18.3 (Web Vulnerability Scanner)
- **位置**: `C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs-v18`
- **状态**: 已完成批量扫描、漏洞利用引擎、WAF检测与绕过模块

## 紧急任务：漏洞验证重试机制

### 当前问题
1. **SQLi时间盲注**: 单次检测，易受网络抖动影响
2. **CMDI误报**: 缺乏二次确认机制
3. **XSS反射**: 缺乏完整反射验证
4. **网络重试**: 没有自动重试机制
5. **误报过滤**: 基线对比不够完善

### 需要实现的功能
请创建 `wvs/vuln/validation_enhancer.py`，包含以下核心功能：

#### 1. 时间盲注增强验证 (TimeBasedValidator)
```python
async def validate_time_based_sqli(
    session, url, param, payload, 
    baseline_duration: float = 1.0,
    retry_count: int = 3
) -> ValidationResult:
    """验证时间盲注"""
    # 多次测试（至少3次）
    # 排除异常值（去掉最高和最低）
    # 计算置信区间
    # 对比基线延迟
```

#### 2. CMDI执行确认 (CmdiValidator)
```python
async def validate_cmdi_echo(
    session, url, param, payload,
    os_type: str = "auto"
) -> ValidationResult:
    """验证CMDI命令执行"""
    # 生成随机token: WVS_VERIFY_{random_hex}
    # 发送验证payload: `echo WVS_VERIFY_<random_hex>`
    # 检查响应是否包含完整token
    # 支持Linux/Mac/Windows不同命令格式
```

#### 3. XSS反射验证 (XssReflectionValidator)
```python
async def validate_xss_reflection(
    session, url, param, payload
) -> ValidationResult:
    """验证XSS反射"""
    # 发送包含特定标记的payload
    # 检查标记是否完整反射
    # 验证反射位置（标签/属性/JavaScript）
    # 确认可执行性
```

#### 4. 网络重试机制 (NetworkRetryHandler)
```python
async def retry_with_exponential_backoff(
    request_func, max_retries: int = 3,
    base_delay: float = 1.0
):
    """带指数退避的重试"""
    # 重试策略: 1s, 2s, 4s, 8s
    # 只重试网络错误（不重试400/500）
    # 记录重试统计
```

#### 5. 误报过滤器 (FalsePositiveFilter)
```python
def filter_false_positives(
    content: str, baseline_content: str,
    vulnerability_type: str
) -> float:
    """误报过滤"""
    # 基线对比
    # 常见框架噪声过滤
    # 启发式规则匹配
    # 返回置信度分数
```

### 技术规格
1. **异步设计**: 使用 `asyncio` 和 `aiohttp`
2. **兼容性**: 保持与 `scanner_v18.py` 兼容
3. **配置驱动**: 支持参数化配置
4. **日志记录**: 详细的操作日志
5. **错误处理**: 健壮的错误恢复

### 参考现有代码
- 当前扫描器: `wvs/vuln/scanner_v18.py`
- 重点关注: `test_sqli()` 和 `test_cmdi()` 方法
- 现有payload定义在类常量中

### 集成建议
1. 可以直接修改现有扫描器，在检测后调用验证器
2. 也可以创建独立的验证流水线
3. 需要保持现有的CLI接口不变

---

## 次要任务：Nuclei模板下载优化

### 问题
- Nuclei官方模板40MB，国内下载常失败
- 当前只有二进制下载器 (`download_nuclei.py`)

### 需求
创建 `nuclei_manager.py`，支持：
1. 多源下载（jsDelivr, ghproxy, GitHub）
2. 断点续传（大文件分块下载）
3. 增量更新（只下载变化部分）
4. 命令行管理接口

---

## 优先级
1. **先完成漏洞验证重试机制**（validation_enhancer.py）
2. **再处理Nuclei下载优化**（nuclei_manager.py）

## 项目结构参考
```
wvs-v18/
├── wvs/
│   ├── vuln/
│   │   ├── scanner_v18.py           # 现有扫描器
│   │   ├── validation_enhancer.py   # 需要创建 ← 优先级最高
│   │   └── __init__.py
│   ├── cli.py
│   └── modules/
├── nuclei_manager.py                # 需要创建 ← 次要
├── download_nuclei.py               # 现有
└── requirements.txt
```

## 测试建议
- 使用本地靶机测试（Metasploitable2）
- 模拟网络抖动和超时
- 验证误报率降低效果

---

**请先实现 validation_enhancer.py，完成后我们再进行测试和集成。**

如果对现有代码结构有疑问，请查看：
- `scanner_v18.py` 中的检测逻辑
- `wvs/cli.py` 中的命令行接口
- 现有的 `Vulnerability` 类定义