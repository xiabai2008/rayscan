# WVS Web管理界面 - 快速启动指南

## 🚀 概述

WVS Web管理界面是基于FastAPI + Vue.js的现代化Web应用程序，提供对WVS v18.4扫描器的可视化管理和监控。

## 📁 项目结构

```
wvs_web/
├── backend/                 # FastAPI后端
│   ├── api/v1/             # RESTful API
│   ├── core/               # 核心配置和数据库
│   ├── services/           # 业务逻辑服务
│   │   └── wvs_scanner_service.py  # WVS扫描器集成服务
│   ├── main.py             # 应用入口
│   └── requirements.txt    # Python依赖
├── frontend/               # Vue.js前端
│   ├── src/                # 前端源代码
│   ├── public/             # 静态资源
│   └── package.json        # 前端依赖
├── docker-compose.yml      # Docker部署配置
├── demo_integration.py     # 集成演示脚本
└── README.md               # 详细文档
```

## ⚡ 快速启动

### 方法1: Docker部署 (推荐)

```bash
# 1. 进入项目目录
cd wvs-v18/wvs_web

# 2. 启动所有服务
docker-compose up -d

# 3. 访问Web界面
# 前端: http://localhost:8080
# API文档: http://localhost:8000/api/docs
```

### 方法2: 本地开发环境

#### 后端启动:
```bash
cd wvs_web/backend

# 安装依赖
pip install -r requirements.txt

# 启动后端服务
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

#### 前端启动:
```bash
cd wvs_web/frontend

# 安装依赖
npm install

# 启动前端开发服务器
npm run serve
```

## 🔧 核心功能

### 1. 扫描器状态监控
- 实时显示WVS扫描器状态和版本信息
- 展示性能指标和功能模块状态
- 监控系统健康状态

### 2. 扫描任务管理
- 创建、启动、暂停、停止扫描任务
- 实时监控扫描进度
- 查看扫描结果和漏洞详情

### 3. 漏洞管理
- 查看发现的所有漏洞
- 按严重程度和类型筛选
- 导出漏洞报告

### 4. 配置管理
- 修改WVS扫描器配置
- 调整性能参数
- 启用/禁用功能模块

### 5. 报告生成
- 生成HTML/PDF/Markdown报告
- 可视化漏洞分布图表
- 导出扫描结果

## 📡 API接口

### 扫描器API (`/api/v1/scanner/*`)

| 端点 | 方法 | 描述 |
|------|------|------|
| `/status` | GET | 获取扫描器状态 |
| `/start` | POST | 启动扫描任务 |
| `/status/{task_id}` | GET | 获取任务状态 |
| `/results/{task_id}` | GET | 获取扫描结果 |
| `/tasks` | GET | 列出所有任务 |
| `/cancel/{task_id}` | POST | 取消扫描任务 |
| `/demo/quick` | POST | 启动快速演示扫描 |
| `/demo/comprehensive` | POST | 启动全面演示扫描 |

### 请求示例

#### 启动扫描:
```bash
curl -X POST "http://localhost:8000/api/v1/scanner/start" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_type": "comprehensive",
    "targets": ["http://192.168.18.131/dvwa/"],
    "scan_depth": "medium"
  }'
```

#### 获取状态:
```bash
curl "http://localhost:8000/api/v1/scanner/status"
```

## 🧪 集成演示

运行集成演示脚本测试Web界面功能:

```bash
cd wvs-v18/wvs_web
python demo_integration.py
```

演示脚本会测试所有API端点，并生成演示报告。

## 🔌 WVS扫描器集成

### 当前集成状态
- ✅ 模拟集成完成 - 提供完整的API接口
- 🔄 实际集成待完成 - 需要连接真实的WVS扫描器引擎

### 实际集成步骤
1. **修改 `wvs_scanner_service.py`** - 连接真实的WVS扫描器
2. **配置扫描器路径** - 设置WVS扫描器的正确路径
3. **实现异步任务队列** - 处理长时间运行的扫描任务
4. **集成WebSocket通知** - 实时推送扫描进度

### 集成示例代码
```python
# 在 wvs_scanner_service.py 中连接真实WVS扫描器
from wvs.scanner import WVSScanner  # 导入真实WVS扫描器

class RealWVSScannerService:
    def __init__(self):
        self.scanner = WVSScanner(config_path="wvs_config.json")
    
    async def start_scan(self, config):
        # 调用真实WVS扫描器
        task_id = await self.scanner.start_scan(config)
        return task_id
```

## 📊 性能特点

### 后端性能
- **FastAPI**: 高性能异步框架
- **Uvicorn**: ASGI服务器，支持高并发
- **Redis**: 缓存和任务队列
- **WebSocket**: 实时通信支持

### 前端性能
- **Vue 3**: 现代化前端框架
- **Element Plus**: UI组件库
- **响应式设计**: 支持PC和移动端
- **实时更新**: 轮询和WebSocket

## 🔒 安全性

### 已实现的安全功能
- **JWT认证**: 用户身份验证
- **CORS配置**: 跨域资源共享
- **输入验证**: Pydantic数据验证
- **SQL注入防护**: ORM和参数化查询

### 待实现的安全功能
- **HTTPS支持**: SSL/TLS加密
- **访问控制**: 基于角色的权限管理
- **审计日志**: 操作记录和审计跟踪
- **API限流**: 防止API滥用

## 🚀 部署选项

### 1. Docker容器化部署
```bash
docker-compose up -d
```
支持快速部署和扩展。

### 2. Kubernetes集群部署
```yaml
# kubernetes部署配置
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wvs-web
spec:
  replicas: 3
  # ... 详细配置
```

### 3. 传统服务器部署
- **Nginx反向代理**: 负载均衡和静态文件服务
- **Supervisor进程管理**: 服务监控和自动重启
- **Systemd服务**: 系统服务集成

## 📈 监控和维护

### 健康检查
```bash
# 检查后端服务
curl http://localhost:8000/health

# 检查前端服务
curl http://localhost:8080
```

### 日志查看
```bash
# Docker日志
docker-compose logs -f backend

# 应用日志
tail -f wvs_web/backend/logs/app.log
```

### 性能监控
- **API响应时间监控**
- **数据库连接池监控**
- **内存和CPU使用率监控**
- **错误率和异常监控**

## 🆘 故障排除

### 常见问题

#### 1. 后端服务无法启动
```bash
# 检查端口占用
netstat -tlnp | grep :8000

# 检查依赖安装
pip list | grep fastapi
```

#### 2. 前端无法连接后端
```bash
# 检查CORS配置
# 修改 backend/core/config.py 中的 BACKEND_CORS_ORIGINS

# 检查网络连接
curl http://localhost:8000/health
```

#### 3. Docker容器启动失败
```bash
# 查看详细日志
docker-compose logs

# 重建容器
docker-compose down
docker-compose up --build
```

### 获取帮助
- **查看完整文档**: `README.md`
- **查看API文档**: `http://localhost:8000/api/docs`
- **查看示例代码**: `demo_integration.py`

## 📞 联系和支持

- **项目主页**: WVS v18.4 Web管理界面
- **维护团队**: WVS开发团队
- **更新频率**: 持续开发和维护

---

**最后更新**: 2026-04-20  
**版本**: v1.0  
**状态**: ✅ 可部署使用

> *注意: 当前版本是模拟集成版本，实际WVS扫描器连接需要进一步开发。*