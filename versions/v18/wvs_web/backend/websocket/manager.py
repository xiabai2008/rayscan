from typing import Dict, Set
import asyncio
import json
from fastapi import WebSocket

class ConnectionManager:
    """WebSocket连接管理器"""
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.connection_groups: Dict[str, Set[str]] = {}

    async def connect(self, websocket: WebSocket, client_id: str):
        """接受WebSocket连接"""
        await websocket.accept()
        self.active_connections[client_id] = websocket
        print(f"客户端 {client_id} 已连接")

    async def disconnect(self, client_id: str):
        """断开WebSocket连接"""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
            # 从所有组中移除
            for group in self.connection_groups.values():
                if client_id in group:
                    group.remove(client_id)
            print(f"客户端 {client_id} 已断开连接")

    async def send_personal_message(self, message: dict, client_id: str):
        """发送个人消息"""
        if client_id in self.active_connections:
            try:
                await self.active_connections[client_id].send_json(message)
            except Exception as e:
                print(f"发送消息到客户端 {client_id} 失败: {e}")

    async def broadcast(self, message: dict):
        """广播消息给所有客户端"""
        disconnected = []
        for client_id, connection in self.active_connections.items():
            try:
                await connection.send_json(message)
            except Exception as e:
                print(f"广播消息到客户端 {client_id} 失败: {e}")
                disconnected.append(client_id)

        # 清理断开连接的客户端
        for client_id in disconnected:
            await self.disconnect(client_id)

    async def send_to_group(self, group_name: str, message: dict):
        """发送消息到指定组"""
        if group_name in self.connection_groups:
            disconnected = []
            for client_id in self.connection_groups[group_name]:
                if client_id in self.active_connections:
                    try:
                        await self.active_connections[client_id].send_json(message)
                    except Exception as e:
                        print(f"发送消息到组 {group_name} 客户端 {client_id} 失败: {e}")
                        disconnected.append(client_id)
                else:
                    disconnected.append(client_id)

            # 清理断开连接的客户端
            for client_id in disconnected:
                self.connection_groups[group_name].remove(client_id)

    async def add_to_group(self, client_id: str, group_name: str):
        """将客户端添加到组"""
        if group_name not in self.connection_groups:
            self.connection_groups[group_name] = set()
        self.connection_groups[group_name].add(client_id)

    async def remove_from_group(self, client_id: str, group_name: str):
        """将客户端从组中移除"""
        if group_name in self.connection_groups and client_id in self.connection_groups[group_name]:
            self.connection_groups[group_name].remove(client_id)

class WebSocketManager:
    """WebSocket管理器"""
    def __init__(self):
        self.manager = ConnectionManager()

    async def initialize(self):
        """初始化"""
        print("WebSocket管理器已初始化")

    async def shutdown(self):
        """关闭"""
        # 断开所有连接
        for client_id in list(self.manager.active_connections.keys()):
            await self.manager.disconnect(client_id)
        print("WebSocket管理器已关闭")

    async def handle_connection(self, websocket: WebSocket, client_id: str):
        """处理WebSocket连接"""
        await self.manager.connect(websocket, client_id)
        try:
            while True:
                # 接收消息
                data = await websocket.receive_text()
                try:
                    message = json.loads(data)
                    await self.handle_message(message, client_id)
                except json.JSONDecodeError:
                    await self.manager.send_personal_message({
                        "type": "error",
                        "message": "无效的JSON格式"
                    }, client_id)
        except Exception as e:
            print(f"WebSocket连接处理异常: {e}")
        finally:
            await self.manager.disconnect(client_id)

    async def handle_message(self, message: dict, client_id: str):
        """处理消息"""
        msg_type = message.get("type")
        data = message.get("data", {})

        if msg_type == "subscribe":
            # 订阅组
            group = data.get("group")
            if group:
                await self.manager.add_to_group(client_id, group)
                await self.manager.send_personal_message({
                    "type": "subscribed",
                    "group": group,
                    "message": f"已成功订阅 {group} 组"
                }, client_id)

        elif msg_type == "unsubscribe":
            # 取消订阅组
            group = data.get("group")
            if group:
                await self.manager.remove_from_group(client_id, group)
                await self.manager.send_personal_message({
                    "type": "unsubscribed",
                    "group": group,
                    "message": f"已取消订阅 {group} 组"
                }, client_id)

        elif msg_type == "ping":
            # 心跳
            await self.manager.send_personal_message({
                "type": "pong",
                "timestamp": asyncio.get_event_loop().time()
            }, client_id)

        else:
            await self.manager.send_personal_message({
                "type": "error",
                "message": f"未知的消息类型: {msg_type}"
            }, client_id)

    # 通知方法
    async def notify_scan_progress(self, task_id: str, progress: float, stage: str = None):
        """通知扫描进度"""
        message = {
            "type": "scan_progress",
            "data": {
                "task_id": task_id,
                "progress": progress,
                "stage": stage,
                "timestamp": asyncio.get_event_loop().time()
            }
        }
        # 发送到任务组和广播
        await self.manager.send_to_group(f"scan:{task_id}", message)
        await self.manager.send_to_group("scans", message)

    async def notify_scan_status(self, task_id: str, status: str):
        """通知扫描状态变化"""
        message = {
            "type": "scan_status",
            "data": {
                "task_id": task_id,
                "status": status,
                "timestamp": asyncio.get_event_loop().time()
            }
        }
        await self.manager.send_to_group(f"scan:{task_id}", message)
        await self.manager.send_to_group("scans", message)
        await self.manager.broadcast(message)

    async def notify_vulnerability_found(self, task_id: str, vulnerability: dict):
        """通知发现漏洞"""
        message = {
            "type": "vulnerability_found",
            "data": {
                "task_id": task_id,
                "vulnerability": vulnerability,
                "timestamp": asyncio.get_event_loop().time()
            }
        }
        await self.manager.send_to_group(f"scan:{task_id}", message)
        await self.manager.send_to_group("vulnerabilities", message)

    async def notify_system_alert(self, level: str, message_text: str):
        """通知系统告警"""
        message = {
            "type": "system_alert",
            "data": {
                "level": level,  # info, warning, error
                "message": message_text,
                "timestamp": asyncio.get_event_loop().time()
            }
        }
        await self.manager.broadcast(message)

# 全局WebSocket管理器实例
websocket_manager = WebSocketManager()