# WVS 版本档案系统架构

## 📁 目录结构
```
wvs-versions/
├── VERSION_ARCHITECTURE.md      # 本文件
├── CHANGELOG.md                 # 完整更新历史
├── RELEASE_NOTES.md             # 发布说明汇总
├── VERSIONS.md                  # 版本索引
├── README.md                    # 版本系统说明
│
├── v18.4/                       # 当前版本（完整）
│   ├── v18.4.0/                 # 子版本
│   ├── v18.4.1/
│   └── v18.4.2/
│
├── v18.3/                       # 上一个主版本
│   ├── docs/                    # 文档
│   ├── src/                     # 源代码
│   ├── tests/                   # 测试文件
│   └── config/                  # 配置文件
│
├── v18.2/                       # 历史版本
├── v18.1/
├── v18.0/
│
├── archives/                    # 归档文件
│   ├── design_docs/             # 设计文档
│   ├── meeting_notes/           # 会议记录
│   ├── prototypes/              # 原型代码
│   └── research/                # 研究材料
│
└── tools/                       # 版本管理工具
    ├── version_backup.py        # 版本备份脚本
    ├── version_diff.py          # 版本差异分析
    ├── version_rollback.py      # 版本回滚工具
    └── release_builder.py       # 发布包构建工具
```

## 🔄 版本命名规范

### 主版本号
```
v{major}.{minor}
示例：v18.4
```

### 子版本号
```
v{major}.{minor}.{patch}
示例：v18.4.1
```

### 开发版本
```
v{major}.{minor}.{patch}-{label}.{build}
示例：v18.4.1-beta.1
标签：alpha, beta, rc (release candidate)
```

### 特殊版本
```
v{major}.{minor}-{feature}
示例：v18.4-performance-optimization
```

## 📊 版本目录内容要求

每个版本目录必须包含：

### 必需文件
```
1. VERSION.txt            # 版本标识文件
2. CHANGELOG.md           # 该版本变更日志
3. README.md              # 版本说明
4. INSTALL.md             # 安装指南
5. CONFIGURATION.md       # 配置说明
```

### 源代码结构
```
src/
├── core/                 # 核心扫描引擎
├── modules/              # 功能模块
├── utils/                # 工具函数
├── api/                  # API接口
└── main.py              # 主入口
```

### 文档结构
```
docs/
├── user_guide/           # 用户指南
├── api_reference/        # API参考
├── deployment/           # 部署指南
└── troubleshooting/      # 故障排除
```

### 测试结构
```
tests/
├── unit/                 # 单元测试
├── integration/          # 集成测试
├── performance/          # 性能测试
└── security/             # 安全测试
```

## 🚀 版本管理流程

### 1. 新版本创建
```bash
# 备份当前版本
python tools/version_backup.py --version v18.4.1

# 创建新版本目录
mkdir -p v18.4/v18.4.1

# 复制文件
cp -r ../wvs-v18/* v18.4/v18.4.1/
```

### 2. 版本差异分析
```bash
# 比较两个版本
python tools/version_diff.py v18.4.0 v18.4.1
```

### 3. 版本回滚
```bash
# 回滚到指定版本
python tools/version_rollback.py v18.4.0
```

### 4. 发布包构建
```bash
# 构建发布包
python tools/release_builder.py --version v18.4.1
```

## 📈 版本历史记录要求

### 变更日志格式
```markdown
## [v18.4.1] - 2026-04-19

### 新增功能
- 功能1：描述
- 功能2：描述

### 性能优化
- 优化1：性能提升数据
- 优化2：性能提升数据

### Bug修复
- 修复问题1
- 修复问题2

### API变更
- 变更1：描述
- 变更2：描述

### 依赖更新
- 包1：版本更新
- 包2：版本更新
```

### 发布说明格式
```markdown
# WVS v18.4.1 发布说明

## 概述
简要描述本版本的主要改进和目标。

## 新功能亮点
1. **功能名称**：详细描述和用例
2. **性能优化**：具体性能数据

## 升级指南
1. 从v18.4.0升级步骤
2. 配置变更说明
3. 向后兼容性说明

## 已知问题
1. 问题描述和临时解决方案
2. 计划修复时间

## 致谢
贡献者名单
```

## 🛠️ 自动化工具

### version_backup.py
```python
功能：自动备份当前版本到版本档案
参数：
  --version：版本号（必需）
  --description：版本描述
  --tag：Git标签（如果使用）
```

### version_diff.py
```python
功能：比较两个版本的差异
参数：
  --version1：第一个版本
  --version2：第二个版本
  --output：差异报告输出格式
```

### version_rollback.py
```python
功能：回滚到指定版本
参数：
  --version：要回滚的版本号
  --backup：是否备份当前状态
```

### release_builder.py
```python
功能：构建发布包
参数：
  --version：版本号
  --platform：目标平台
  --format：包格式（zip, tar, exe等）
```

## 📋 版本管理最佳实践

1. **每次重要更新都创建新版本目录**
2. **保留所有历史版本，不要删除**
3. **版本目录必须有完整的文档**
4. **定期清理不需要的临时文件**
5. **使用自动化工具减少人工错误**

## 🔗 与Git集成

如果使用Git版本控制：
```bash
# 每个版本对应一个Git标签
git tag -a v18.4.1 -m "WVS v18.4.1 发布"

# 版本目录可以链接到Git标签
git archive v18.4.1 --format=zip --output=wvs-versions/v18.4/v18.4.1.zip
```

---

*最后更新：2026-04-20*
*维护者：WVS开发团队*