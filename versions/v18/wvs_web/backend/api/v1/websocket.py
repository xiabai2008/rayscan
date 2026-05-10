import uuid
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import HTMLResponse

from websocket.manager import websocket_manager

router = APIRouter()

# WebSocket连接页面（用于测试）
html = """
<!DOCTYPE html>
<html>
    <head>
        <title>WVS WebSocket Test</title>
    </head>
    <body>
        <h1>WVS WebSocket Test</h1>
        <div>
            <button id="connect">连接</button>
            <button id="subscribeScans">订阅扫描</button>
            <button id="subscribeVulnerabilities">订阅漏洞</button>
            <button id="ping">发送心跳</button>
            <button id="disconnect">断开连接</button>
        </div>
        <div>
            <h2>消息日志</h2>
            <ul id="messages"></ul>
        </div>
        <script>
            let ws = null;
            const clientId = 'test_' + Math.random().toString(36).substr(2, 9);

            function logMessage(message) {
                const li = document.createElement('li');
                li.textContent = message;
                document.getElementById('messages').appendChild(li);
            }

            document.getElementById('connect').addEventListener('click', () => {
                if (ws) {
                    logMessage('已经连接');
                    return;
                }

                ws = new WebSocket(`ws://localhost:8000/api/v1/ws/${clientId}`);

                ws.onopen = () => {
                    logMessage('连接已建立');
                };

                ws.onmessage = (event) => {
                    const data = JSON.parse(event.data);
                    logMessage(`收到消息: ${JSON.stringify(data)}`);
                };

                ws.onclose = () => {
                    logMessage('连接已关闭');
                    ws = null;
                };

                ws.onerror = (error) => {
                    logMessage(`连接错误: ${error}`);
                };
            });

            document.getElementById('subscribeScans').addEventListener('click', () => {
                if (!ws) {
                    logMessage('请先建立连接');
                    return;
                }

                const message = {
                    type: 'subscribe',
                    data: { group: 'scans' }
                };
                ws.send(JSON.stringify(message));
                logMessage('已发送订阅扫描请求');
            });

            document.getElementById('subscribeVulnerabilities').addEventListener('click', () => {
                if (!ws) {
                    logMessage('请先建立连接');
                    return;
                }

                const message = {
                    type: 'subscribe',
                    data: { group: 'vulnerabilities' }
                };
                ws.send(JSON.stringify(message));
                logMessage('已发送订阅漏洞请求');
            });

            document.getElementById('ping').addEventListener('click', () => {
                if (!ws) {
                    logMessage('请先建立连接');
                    return;
                }

                const message = {
                    type: 'ping'
                };
                ws.send(JSON.stringify(message));
                logMessage('已发送心跳请求');
            });

            document.getElementById('disconnect').addEventListener('click', () => {
                if (!ws) {
                    logMessage('尚未连接');
                    return;
                }

                ws.close();
                logMessage('已发送断开连接请求');
            });
        </script>
    </body>
</html>
"""

@router.get("/test")
async def websocket_test_page():
    """WebSocket测试页面"""
    return HTMLResponse(html)

@router.websocket("/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """WebSocket端点"""
    await websocket_manager.handle_connection(websocket, client_id)

@router.get("/connections")
async def get_connections():
    """获取当前连接信息"""
    manager = websocket_manager.manager
    connections_info = {
        "total_connections": len(manager.active_connections),
        "active_connections": list(manager.active_connections.keys()),
        "connection_groups": {
            group_name: list(members) for group_name, members in manager.connection_groups.items()
        }
    }
    return connections_info

@router.post("/broadcast")
async def broadcast_message(message: dict):
    """广播消息（仅用于测试）"""
    await websocket_manager.manager.broadcast(message)
    return {"message": "广播消息已发送", "recipients": len(websocket_manager.manager.active_connections)}

@router.post("/notify/scan-progress")
async def notify_scan_progress(task_id: str, progress: float, stage: str = None):
    """通知扫描进度（仅用于测试）"""
    await websocket_manager.notify_scan_progress(task_id, progress, stage)
    return {"message": "扫描进度通知已发送"}

@router.post("/notify/scan-status")
async def notify_scan_status(task_id: str, status: str):
    """通知扫描状态（仅用于测试）"""
    await websocket_manager.notify_scan_status(task_id, status)
    return {"message": "扫描状态通知已发送"}

@router.post("/notify/vulnerability")
async def notify_vulnerability(task_id: str, vulnerability: dict):
    """通知漏洞发现（仅用于测试）"""
    await websocket_manager.notify_vulnerability_found(task_id, vulnerability)
    return {"message": "漏洞通知已发送"}