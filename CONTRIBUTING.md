# Contributing to RayScan

## Development Setup

```bash
# Clone and install with dev deps
git clone https://github.com/xiabai2004/RayScan
cd RayScan
pip install -e ".[dev]"

# Or install everything including optional integrations
pip install -e ".[dev,speedup,nuclei,integrations]"
```

## Running Tests

```bash
# All tests
pytest tests/ -q

# Specific test file
pytest tests/test_sqli_detector.py -v

# With coverage
pytest tests/ --cov=wvs --cov-report=html
```

## Pre-commit Hooks

```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files  # run manually
```

## Code Quality

```bash
# Lint
flake8 wvs/ --max-line-length=150 --max-complexity=20

# Auto-format
ruff format wvs/
ruff check wvs/ --fix

# Type checking (work in progress)
mypy wvs/ --ignore-missing-imports
```

## Project Structure

```
wvs/
├── cli.py              CLI entry point
├── config.py           ConfigManager
├── models.py           Vulnerability, ScanTarget, ScanResult dataclasses
├── constants.py        Shared thresholds and defaults
├── exceptions.py       WVSError hierarchy
├── core/
│   ├── scanner.py      WAVScanner main orchestrator
│   ├── scanner_integrations.py  Nuclei/sqlmap/ffuf/Wappalyzer integration mixin
│   ├── crawler.py      WebCrawler
│   ├── crawler_parsers.py  Sitemap/robots.txt/OpenAPI parser mixin
│   ├── session.py      HTTPPool (httpx-based)
│   ├── cache.py        ScanCache
│   ├── rate_limiter.py IntelligentRateLimiter
│   ├── scheduler.py    TaskScheduler
│   └── oob/            Out-of-band (interactsh/DNSLog)
├── modules/
│   ├── base.py         DetectionModule base + ModuleFactory
│   └── sqli/
│       ├── detector.py       SQLiDetector orchestrator
│       ├── analyzer.py       ResponseAnalyzer
│       ├── techniques_mixins.py  Detection technique implementations
│       └── payloads.py       SQLi payloads + DB error patterns
│   └── xss/, cmdi/, lfi/, rce/, ...  Other detectors
├── integrations/       Third-party tool wrappers
├── reporting/          HTML/JSON/CSV/Markdown/Console reporters
└── plugins/            Auth providers
```

## Adding a New Detection Module

1. Create `wvs/modules/<name>/` with `__init__.py`, `detector.py`, `payloads.py`
2. Subclass `DetectionModule` from `wvs.modules.base`
3. Decorate with `@register_module`
4. Implement `_scan_impl(target) -> List[Vulnerability]`
5. Import in `wvs/modules/__init__.py`
6. Add tests in `tests/test_<name>_detector.py`

## Pull Request Workflow（必读）

`master` 分支已受保护，**所有改动必须通过 Pull Request 合入，禁止直接 push 到 master**。合并前必须满足：

1. **分支**：从最新的 `master` 切出功能分支（建议前缀 `feat/`、`fix/`、`docs/`、`chore/`）。
2. **本地验证**：`pytest tests/ -q` 与 `flake8 wvs/ --max-line-length=150 --max-complexity=20` 均通过。
3. **提交 PR**：目标分支选 `master`，按模板填写（改动类型、关联 Issue、测试情况）。
4. **CI 通过**：GitHub Actions 的 `CI` 检查（Python 3.9–3.12 测试矩阵）必须全部通过。
5. **代码评审**：至少需要 1 名团队成员的 Approving Review；所有评审对话需 Resolve 后方可合并。
6. **合并**：推荐使用 Squash merge，保持 `master` 主干历史整洁。

> 说明：仓库管理员（admin）默认保留紧急情况下的绕过权限；团队日常改动请严格走 PR 流程，不要直接推送 `master`。

## PR Guidelines

- Keep changes focused — one PR per feature/fix
- Run `pytest tests/` and `flake8 wvs/` before pushing
- Add tests for new functionality
- Follow existing module structure and naming conventions
