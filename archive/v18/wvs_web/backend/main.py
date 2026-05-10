from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import uvicorn

from api.v1.api import api_router
from core.config import settings
from core.database import engine, Base
from core.redis import redis_client
from websocket.manager import websocket_manager

@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    # 启动时初始化数据库
    print("正在初始化数据库...")
    Base.metadata.create_all(bind=engine)

    # 连接Redis
    print("正在连接Redis...")
    await redis_client.initialize()

    # 启动WebSocket管理器
    print("正在启动WebSocket管理器...")
    await websocket_manager.initialize()

    yield

    # 关闭时清理资源
    print("正在关闭资源...")
    await redis_client.close()
    await websocket_manager.shutdown()

app = FastAPI(
    title="WVS v18.4 Web管理平台",
    description="基于FastAPI的WVS漏洞扫描器Web管理平台",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan
)

# 配置CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 挂载静态文件
app.mount("/static", StaticFiles(directory="static"), name="static")

# 包含API路由
app.include_router(api_router, prefix="/api/v1")

@app.get("/")
async def root():
    return {
        "message": "Welcome to WVS v18.4 Web Management Platform",
        "docs": "/api/docs",
        "version": "1.0.0"
    }

@app.get("/health")
async def health_check():
    """健康检查端点"""
    return {"status": "healthy", "service": "wvs-web-backend"}

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL
    )