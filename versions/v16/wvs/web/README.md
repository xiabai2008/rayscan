# WVS v16.0 Web UI

基于 FastAPI + WebSocket 的 Web 漏洞扫描器界面。

## 功能特性

- 🎨 现代化 UI（Tailwind CSS）
- 📊 实时进度显示（WebSocket）
- 📈 图表可视化（Chart.js）
- 🔍 漏洞筛选和搜索
- 📥 一键导出报告
- 📝 实时日志控制台

## 快速开始

### 安装依赖

```bash
cd wvs-v16
pip install -r requirements.txt
```

### 启动 Web UI

```bash
# 默认端口 8080
python -m wvs.web

# 指定端口
python -m wvs.web --port 8080

# 不自动打开浏览器
python -m wvs.web --no-browser
```

### 访问界面

打开浏览器访问: http://localhost:8080

## 界面截图

### 1. 扫描配置
- 目标 URL 输入
- 爬虫深度和 URL 数设置
- 认证 Cookie 配置
- 检测类型选择（SQLi/XSS）

### 2. 实时进度
- 进度条显示
- 统计卡片（URL/表单/漏洞/耗时）
- 实时日志控制台
- WebSocket 实时推送

### 3. 漏洞统计
- 严重程度分布（饼图）
- 漏洞类型分布（柱状图）
- 风险评分计算

### 4. 漏洞列表
- 严重程度筛选
- 关键词搜索
- 可折叠详情
- Payload 高亮显示

### 5. 报告导出
- JSON 格式
- CSV 格式
- HTML 格式

## API 文档

启动后访问: http://localhost:8080/docs

### REST API

```
POST   /api/scan              创建扫描任务
GET    /api/scan/{id}         获取扫描状态
GET    /api/scan/{id}/report  获取扫描报告
```

### WebSocket

```
WS     /ws/{scan_id}          实时状态推送
```

## 技术栈

- **后端**: FastAPI + Uvicorn
- **前端**: 原生 JS + Tailwind CSS + Chart.js
- **实时通信**: WebSocket
- **数据验证**: Pydantic v2

## 文件结构

```
wvs/web/
├── __init__.py      # FastAPI 应用 + 前端 HTML
├── __main__.py      # 启动脚本
└── README.md        # 本文档
```

## 配置说明

### 扫描配置

| 参数 | 说明 | 默认值 |
|------|------|--------|
| target | 目标 URL | 必填 |
| max_depth | 爬虫深度 | 3 |
| max_urls | 最大 URL 数 | 100 |
| scan_sqli | 检测 SQL 注入 | true |
| scan_xss | 检测 XSS | true |
| auth_cookie | 认证 Cookie | null |

## 浏览器支持

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## 安全提示

⚠️ 本工具仅用于授权的安全测试，请勿用于非法用途。
