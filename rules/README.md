# RayScan 内置规则目录

本目录随仓库分发,作为外部规则的兜底与示例。规则采用 YAML 格式。

## 规则格式(示例:OA 指纹规则)

```yaml
# rules/oa-fingerprints.yaml
# 规则由 `rules update` 从 ~/.rayscan 外部仓库增量拉取,本目录为内置示例
```

## 使用方式

- 运行时规则目录:`~/.rayscan/rules/`(用户可覆盖)
- 内置规则:本目录(随版本发布)
- 外部规则仓库:由 `rayscan rules update` 管理

规则格式规范见 `docs/rules-format.md`。
