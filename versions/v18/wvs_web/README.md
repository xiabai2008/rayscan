# WVS v18.4 Web管理平台

基于FastAPI + Vue.js + Element Plus的WVS漏洞扫描器Web管理平台。

## 功能特性

### 后端功能
- ✅ 用户认证和权限管理（JWT令牌）
- ✅ 扫描任务管理（创建、启动、暂停、停止、删除）
- ✅ 实时进度监控（WebSocket）
- ✅ 漏洞发现和管理
- ✅ 报告生成和导出（PDF/HTML/JSON/CSV）
- ✅ 系统配置管理
- ✅ 性能优化和缓存
- ✅ 任务调度（Celery）
- ✅ API文档（Swagger/ReDoc）

### 前端功能
- ✅ 响应式设计，支持PC和移动端
- ✅ 暗色/亮色主题切换
- ✅ 仪表板和数据可视化
- ✅ 扫描任务管理界面
- ✅ 实时监控和通知
- ✅ 漏洞管理和筛选
- ✅ 报告查看和下载
- ✅ 系统配置界面
- ✅ 用户管理（管理员）

### WVS集成
- ✅ 支持WVS v18.4扫描引擎集成
- ✅ 并发扫描器控制
- ✅ 缓存系统和限速系统
- ✅ 四大高级检测模块：
  - 逻辑漏洞检测
  - API安全检测
  - 认证绕过检测
  - 零日漏洞检测

## 技术栈

### 后端
- **FastAPI** - 高性能Python Web框架
- **SQLAlchemy** - ORM框架
- **Alembic** - 数据库迁移
- **PostgreSQL** - 主数据库
- **Redis** - 缓存和消息队列
- **Celery** - 分布式任务队列
- **WebSocket** - 实时通信
- **JWT** - 身份认证

### 前端
- **Vue 3** - 渐进式JavaScript框架
- **Vue Router** - 路由管理
- **Vuex/Pinia** - 状态管理
- **Element Plus** - UI组件库
- **ECharts** - 数据可视化
- **Axios** - HTTP客户端
- **WebSocket** - 实时通信

### 部署
- **Docker** - 容器化
- **Docker Compose** - 多容器编排
- **Nginx** - 反向代理
- **PostgreSQL** - 数据库
- **Redis** - 缓存

## 项目结构

```
wvs_web/
├── backend/                 # FastAPI后端
│   ├── api/                # API路由
│   │   └── v1/             # API版本1
│   ├── core/               # 核心模块
│   ├── schemas/            # Pydantic模型
│   ├── services/           # 业务逻辑
│   ├── websocket/          # WebSocket模块
│   ├── main.py             # 应用入口
│   └── requirements.txt    # Python依赖
├── frontend/               # Vue.js前端
│   ├── public/             # 静态资源
│   ├── src/                # 源代码
│   │   ├── api/            # API接口
│   │   ├── assets/         # 资源文件
│   │   ├── components/     # 通用组件
│   │   ├── layouts/        # 布局组件
│   │   ├── router/         # 路由配置
│   │   ├── store/          # 状态管理
│   │   ├── styles/         # 样式文件
│   │   ├── utils/          # 工具函数
│   │   └── views/          # 页面组件
│   └── package.json        # 前端依赖
├── nginx/                  # Nginx配置
├── docker-compose.yml      # Docker编排
└── README.md               # 项目文档
```

## 快速开始

### 前提条件

- Docker 20.10+ 和 Docker Compose 2.0+
- Python 3.11+（仅开发环境）
- Node.js 18+（仅开发环境）

### Docker部署

1. 克隆项目
```bash
git clone <repository-url>
cd wvs_web
```

2. 配置环境变量
```bash
cp .env.example .env
# 编辑.env文件，设置必要的环境变量
```

3. 启动服务
```bash
docker-compose up -d
```

4. 访问应用
- 前端界面：http://localhost:8080
- API文档：http://localhost:8000/api/docs
- 管理员账号：admin / admin123

### 开发环境部署

#### 后端开发

1. 安装Python依赖
```bash
cd backend
pip install -r requirements.txt
```

2. 配置环境变量
```bash
cp .env.example .env
# 编辑.env文件
```

3. 初始化数据库
```bash
# 创建数据库表
python -c "from core.database import Base, engine; Base.metadata.create_all(bind=engine)"
```

4. 启动开发服务器
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

#### 前端开发

1. 安装Node.js依赖
```bash
cd frontend
npm install
```

2. 启动开发服务器
```bash
npm run serve
```

3. 访问前端
```
http://localhost:8080
```

## API文档

启动后端服务后，访问以下地址查看API文档：

- Swagger UI: http://localhost:8000/api/docs
- ReDoc: http://localhost:8000/api/redoc

## 配置说明

### 后端配置

编辑 `backend/.env` 文件：

```env
# 应用配置
DEBUG=true
SECRET_KEY=your-secret-key-change-in-production
HOST=0.0.0.0
PORT=8000

# 数据库配置
DATABASE_URL=postgresql://user:password@localhost:5432/wvsdb

# Redis配置
REDIS_URL=redis://localhost:6379/0

# JWT配置
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# WVS配置
WVS_SCANNER_PATH=/usr/local/bin/wvs
WVS_MAX_CONCURRENT_SCANS=5
```

### 前端配置

编辑 `frontend/.env.development` 文件：

```env
VUE_APP_API_BASE_URL=http://localhost:8000/api
VUE_APP_WS_BASE_URL=ws://localhost:8000/ws
```

## 使用指南

### 1. 用户管理

1. 注册新用户
2. 登录系统
3. 管理员可以管理用户权限

### 2. 扫描任务

1. 创建扫描任务
   - 输入目标URL
   - 选择扫描类型
   - 配置扫描参数

2. 启动扫描
   - 实时查看进度
   - 监控扫描状态
   - 查看实时日志

3. 管理任务
   - 暂停/恢复扫描
   - 停止扫描
   - 查看扫描结果

### 3. 漏洞管理

1. 查看漏洞列表
   - 按严重程度筛选
   - 按状态筛选
   - 搜索漏洞

2. 漏洞详情
   - 查看漏洞描述
   - 查看影响和修复建议
   - 验证漏洞

3. 漏洞处理
   - 标记为确认
   - 标记为误报
   - 标记为已修复

### 4. 报告管理

1. 生成报告
   - 选择报告类型
   - 选择导出格式
   - 定制报告内容

2. 查看报告
   - 在线预览
   - 下载报告
   - 分享报告

### 5. 系统配置

1. WVS扫描器配置
2. 性能优化配置
3. 安全配置
4. 通知配置

## 性能优化

### 缓存策略
- Redis缓存扫描结果
- 数据库查询缓存
- 静态资源缓存

### 并发控制
- 限制并发扫描数量
- 连接池管理
- 请求队列

### 资源管理
- 内存使用限制
- CPU使用限制
- 磁盘空间监控

## 安全特性

### 认证安全
- JWT令牌认证
- 令牌刷新机制
- 密码哈希存储

### 权限控制
- 基于角色的访问控制
- API权限验证
- 数据隔离

### 安全防护
- SQL注入防护
- XSS防护
- CSRF防护
- 速率限制

## 故障排除

### 常见问题

1. **数据库连接失败**
   - 检查数据库服务状态
   - 验证连接字符串
   - 检查网络连接

2. **Redis连接失败**
   - 检查Redis服务状态
   - 验证连接配置
   - 检查防火墙设置

3. **扫描任务失败**
   - 检查WVS扫描器路径
   - 验证目标URL可达性
   - 检查磁盘空间

4. **WebSocket连接失败**
   - 检查WebSocket服务状态
   - 验证代理配置
   - 检查防火墙设置

### 日志查看

```bash
# 查看所有服务日志
docker-compose logs -f

# 查看特定服务日志
docker-compose logs -f backend
docker-compose logs -f frontend
docker-compose logs -f redis
```

## 开发指南

### 添加新API

1. 在 `backend/api/v1/` 创建新的路由文件
2. 定义Pydantic模型（`schemas/`）
3. 实现业务逻辑（`services/`）
4. 注册路由到 `backend/api/v1/api.py`

### 添加新前端页面

1. 在 `frontend/src/views/` 创建新的Vue组件
2. 在 `frontend/src/router/index.js` 添加路由
3. 创建对应的API调用（`frontend/src/api/`）
4. 更新状态管理（`frontend/src/store/`）

### 数据库迁移

```bash
# 创建迁移
alembic revision --autogenerate -m "描述"

# 应用迁移
alembic upgrade head

# 回滚迁移
alembic downgrade -1
```

## 贡献指南

1. Fork项目
2. 创建特性分支
3. 提交更改
4. 推送到分支
5. 创建Pull Request

## 许可证

本项目采用MIT许可证。详见LICENSE文件。

## 支持

- 问题反馈：GitHub Issues
- 文档：查看项目Wiki
- 社区：加入讨论组

## 版本历史

### v1.0.0 (2024-04-20)
- 初始版本发布
- 基础功能实现
- Docker部署支持

---

**注意**：本系统为WVS漏洞扫描器的Web管理界面，需要配合WVS v18.4扫描器使用。实际部署前请确保已获得合法的WVS扫描器授权。