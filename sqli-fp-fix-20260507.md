# SQLi 误报修复 — 2026-05-07 P15

## 修改文件
- `wvs/modules/sqli/detector.py` (3处)

## 三层防线

### 1. Boolean-blind 检测层 (`is_boolean_blind_positive`)
噪声剥离引擎：HTML标签 → 引号串 → SQL关键词 → 数字归一 → 运算符 → 注释 → 单字符残余 → 折叠

剥离后若 true/false 响应相同 → 判为反射噪声 → 返回 False

### 2. Boolean-blind 验证层 (`_verify_with_different_payload`)
同样使用噪声剥离替代原有的 `_is_response_different` (hash比对)
原 hash 比对只要 payload 被反射一个字节就判阳性 → 对反射页 100% 误报

### 3. Union-based 检测层 (`_test_union_based`)
HTML 标签类型序列比对 (baseline vs payload 响应)
真实注入 → 数据库输出加表行 → 标签数变
反射 → 标签数不变 → 判为反射

## 验证结果 (DVWA low security, 12 lab endpoints)

| 修复前误报 | 修复后 |
|------------|--------|
| Boolean-blind on xss_r | ✅ 拦截 |
| Boolean-blind on xss_s | ✅ 拦截 |
| Boolean-blind on csp | ✅ 拦截 |
| Union-based on xss_r | ✅ 拦截 |
| Union-based on xss_s | ✅ 拦截 |
| Union-based on csp | ✅ 拦截 |

| 真阳性保持 |
|------------|
| Boolean-blind on sqli/id ✅ |
| Union-based on sqli/id ✅ |
| XSS Reflected ✅ |
| LFI /etc/passwd ✅ |
| CMDi Echo ✅ |

## 关键发现
- Boolean-blind payload `' AND 'a'='a'` 经引号剥离后残留 `aa` vs `ab`，需 `\b\w\b` 清理
- `_is_response_different` 的 hash 比对是二次验证层误报根因
- 噪声剥离对真实注入（sqli）和反射（xss_r）有良好区分度
