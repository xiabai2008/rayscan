"""WVS v16.0 - Web UI 后端

基于 FastAPI 的 RESTful API + WebSocket 实时推送
"""
import asyncio
import json
from datetime import datetime
from typing import List, Dict, Optional
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uvicorn

from ..vuln.crawler_v16 import CrawlerV16
from ..vuln.sqli_v16 import SQLiScannerV16
from ..vuln.xss_v16 import XSSScannerV16
from ..vuln.report_v16 import ReportGeneratorV16, Vulnerability

app = FastAPI(title="WVS v16.0 Web UI", version="16.0.0")

# 扫描任务存储
active_scans: Dict[str, dict] = {}
scan_results: Dict[str, dict] = {}


# ============== Pydantic 模型 ==============

class ScanRequest(BaseModel):
    target: str
    max_depth: int = 3
    max_urls: int = 100
    scan_sqli: bool = True
    scan_xss: bool = True
    auth_cookie: Optional[str] = None
    auth_header: Optional[str] = None


class ScanStatus(BaseModel):
    scan_id: str
    status: str  # pending, running, completed, failed
    progress: int  # 0-100
    current_url: Optional[str] = None
    urls_scanned: int = 0
    total_urls: int = 0
    vulns_found: int = 0
    message: Optional[str] = None


class VulnerabilityItem(BaseModel):
    name: str
    severity: str
    url: str
    parameter: str
    payload: str
    description: str
    remediation: str
    confidence: float
    evidence: str


# ============== API 路由 ==============

@app.get("/", response_class=HTMLResponse)
async def root():
    """主页面"""
    return """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WVS v16.0 - Web 漏洞扫描器</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        .gradient-bg { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .card { background: white; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .severity-critical { background: #fee2e2; color: #dc2626; }
        .severity-high { background: #fef3c7; color: #d97706; }
        .severity-medium { background: #fef9c3; color: #ca8a04; }
        .severity-low { background: #dcfce7; color: #16a34a; }
        .progress-bar { transition: width 0.3s ease; }
        .vuln-card { transition: all 0.2s; }
        .vuln-card:hover { transform: translateY(-2px); box-shadow: 0 8px 16px rgba(0,0,0,0.1); }
        .log-entry { font-family: monospace; font-size: 13px; }
        .pulse { animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
    </style>
</head>
<body class="bg-gray-100 min-h-screen">
    <!-- 导航栏 -->
    <nav class="gradient-bg text-white shadow-lg">
        <div class="container mx-auto px-6 py-4 flex items-center justify-between">
            <div class="flex items-center space-x-3">
                <i class="fas fa-shield-alt text-2xl"></i>
                <h1 class="text-xl font-bold">WVS v16.0</h1>
            </div>
            <div class="flex items-center space-x-4">
                <span class="text-sm opacity-80">Web 漏洞扫描器</span>
                <a href="/docs" class="text-sm hover:underline">API 文档</a>
            </div>
        </div>
    </nav>

    <div class="container mx-auto px-6 py-8">
        <!-- 扫描配置 -->
        <div class="card p-6 mb-6">
            <h2 class="text-lg font-bold mb-4 flex items-center">
                <i class="fas fa-cog mr-2 text-blue-600"></i>
                扫描配置
            </h2>
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">目标 URL</label>
                    <input type="url" id="target" placeholder="https://example.com" 
                           class="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">爬虫深度</label>
                    <input type="number" id="maxDepth" value="3" min="1" max="10"
                           class="w-full px-4 py-2 border rounded-lg">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">最大 URL 数</label>
                    <input type="number" id="maxUrls" value="100" min="10" max="1000"
                           class="w-full px-4 py-2 border rounded-lg">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">认证 Cookie (可选)</label>
                    <input type="text" id="authCookie" placeholder="session=xxx"
                           class="w-full px-4 py-2 border rounded-lg">
                </div>
            </div>
            <div class="mt-4 flex items-center space-x-4">
                <label class="flex items-center">
                    <input type="checkbox" id="scanSqli" checked class="mr-2">
                    <span>SQL 注入</span>
                </label>
                <label class="flex items-center">
                    <input type="checkbox" id="scanXss" checked class="mr-2">
                    <span>XSS</span>
                </label>
                <button onclick="startScan()" id="startBtn"
                        class="ml-auto bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition">
                    <i class="fas fa-play mr-2"></i>开始扫描
                </button>
            </div>
        </div>

        <!-- 扫描进度 -->
        <div class="card p-6 mb-6" id="progressCard" style="display: none;">
            <h2 class="text-lg font-bold mb-4 flex items-center">
                <i class="fas fa-spinner fa-spin mr-2 text-blue-600"></i>
                扫描进度
                <span id="scanStatus" class="ml-2 text-sm text-gray-500">准备中...</span>
            </h2>
            <div class="mb-4">
                <div class="flex justify-between text-sm text-gray-600 mb-1">
                    <span id="progressText">0%</span>
                    <span id="progressDetail">0/0 URLs</span>
                </div>
                <div class="w-full bg-gray-200 rounded-full h-2">
                    <div id="progressBar" class="progress-bar bg-blue-600 h-2 rounded-full" style="width: 0%"></div>
                </div>
            </div>
            <div class="grid grid-cols-4 gap-4 text-center">
                <div class="bg-gray-50 p-3 rounded-lg">
                    <div id="statUrls" class="text-2xl font-bold text-blue-600">0</div>
                    <div class="text-xs text-gray-500">已扫描 URL</div>
                </div>
                <div class="bg-gray-50 p-3 rounded-lg">
                    <div id="statForms" class="text-2xl font-bold text-purple-600">0</div>
                    <div class="text-xs text-gray-500">已测试表单</div>
                </div>
                <div class="bg-gray-50 p-3 rounded-lg">
                    <div id="statVulns" class="text-2xl font-bold text-red-600">0</div>
                    <div class="text-xs text-gray-500">发现漏洞</div>
                </div>
                <div class="bg-gray-50 p-3 rounded-lg">
                    <div id="statTime" class="text-2xl font-bold text-green-600">0s</div>
                    <div class="text-xs text-gray-500">耗时</div>
                </div>
            </div>
            <div class="mt-4 bg-gray-900 text-green-400 p-4 rounded-lg h-40 overflow-y-auto" id="logConsole">
                <div class="log-entry">等待扫描开始...</div>
            </div>
        </div>

        <!-- 统计卡片 -->
        <div class="grid grid-cols-1 md:grid-cols-5 gap-4 mb-6" id="statsCard" style="display: none;">
            <div class="card p-4 text-center border-l-4 border-red-500">
                <div id="countCritical" class="text-3xl font-bold text-red-600">0</div>
                <div class="text-sm text-gray-600">严重</div>
            </div>
            <div class="card p-4 text-center border-l-4 border-orange-500">
                <div id="countHigh" class="text-3xl font-bold text-orange-600">0</div>
                <div class="text-sm text-gray-600">高危</div>
            </div>
            <div class="card p-4 text-center border-l-4 border-yellow-500">
                <div id="countMedium" class="text-3xl font-bold text-yellow-600">0</div>
                <div class="text-sm text-gray-600">中危</div>
            </div>
            <div class="card p-4 text-center border-l-4 border-green-500">
                <div id="countLow" class="text-3xl font-bold text-green-600">0</div>
                <div class="text-sm text-gray-600">低危</div>
            </div>
            <div class="card p-4 text-center border-l-4 border-blue-500">
                <div id="riskScore" class="text-3xl font-bold text-blue-600">0</div>
                <div class="text-sm text-gray-600">风险评分</div>
            </div>
        </div>

        <!-- 图表区域 -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6" id="chartsCard" style="display: none;">
            <div class="card p-6">
                <h3 class="font-bold mb-4">漏洞严重程度分布</h3>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="card p-6">
                <h3 class="font-bold mb-4">漏洞类型分布</h3>
                <canvas id="typeChart"></canvas>
            </div>
        </div>

        <!-- 漏洞列表 -->
        <div class="card p-6" id="vulnsCard" style="display: none;">
            <div class="flex items-center justify-between mb-4">
                <h2 class="text-lg font-bold flex items-center">
                    <i class="fas fa-bug mr-2 text-red-600"></i>
                    漏洞列表
                    <span id="vulnCount" class="ml-2 bg-gray-200 text-gray-700 px-2 py-1 rounded-full text-sm">0</span>
                </h2>
                <div class="flex space-x-2">
                    <select id="severityFilter" onchange="filterVulns()" class="px-3 py-1 border rounded-lg text-sm">
                        <option value="all">所有严重程度</option>
                        <option value="CRITICAL">严重</option>
                        <option value="HIGH">高危</option>
                        <option value="MEDIUM">中危</option>
                        <option value="LOW">低危</option>
                    </select>
                    <input type="text" id="searchVuln" placeholder="搜索..." onkeyup="filterVulns()"
                           class="px-3 py-1 border rounded-lg text-sm">
                    <button onclick="exportReport('json')" class="px-3 py-1 bg-green-600 text-white rounded-lg text-sm hover:bg-green-700">
                        <i class="fas fa-download mr-1"></i>JSON
                    </button>
                    <button onclick="exportReport('csv')" class="px-3 py-1 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-700">
                        <i class="fas fa-download mr-1"></i>CSV
                    </button>
                </div>
            </div>
            <div id="vulnList" class="space-y-3">
                <!-- 漏洞卡片将在这里动态生成 -->
            </div>
        </div>
    </div>

    <script>
        let ws = null;
        let scanId = null;
        let vulnerabilities = [];
        let severityChart = null;
        let typeChart = null;
        let startTime = null;

        async function startScan() {
            const target = document.getElementById('target').value;
            if (!target) {
                alert('请输入目标 URL');
                return;
            }

            const config = {
                target: target,
                max_depth: parseInt(document.getElementById('maxDepth').value),
                max_urls: parseInt(document.getElementById('maxUrls').value),
                scan_sqli: document.getElementById('scanSqli').checked,
                scan_xss: document.getElementById('scanXss').checked,
                auth_cookie: document.getElementById('authCookie').value || null
            };

            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(config)
                });
                const data = await response.json();
                scanId = data.scan_id;
                startTime = Date.now();

                // 显示进度卡片
                document.getElementById('progressCard').style.display = 'block';
                document.getElementById('statsCard').style.display = 'none';
                document.getElementById('chartsCard').style.display = 'none';
                document.getElementById('vulnsCard').style.display = 'none';
                document.getElementById('startBtn').disabled = true;
                document.getElementById('startBtn').innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>扫描中...';

                // 连接 WebSocket
                connectWebSocket(scanId);
            } catch (error) {
                alert('启动扫描失败: ' + error.message);
            }
        }

        function connectWebSocket(scanId) {
            const wsUrl = `ws://${window.location.host}/ws/${scanId}`;
            ws = new WebSocket(wsUrl);

            ws.onopen = () => {
                addLog('WebSocket 连接成功');
            };

            ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                handleWebSocketMessage(data);
            };

            ws.onerror = (error) => {
                addLog('WebSocket 错误: ' + error.message, 'error');
            };

            ws.onclose = () => {
                addLog('WebSocket 连接关闭');
            };
        }

        function handleWebSocketMessage(data) {
            switch (data.type) {
                case 'status':
                    updateProgress(data);
                    break;
                case 'log':
                    addLog(data.message, data.level);
                    break;
                case 'vulnerability':
                    addVulnerability(data.vulnerability);
                    break;
                case 'complete':
                    onScanComplete(data);
                    break;
                case 'error':
                    addLog('错误: ' + data.message, 'error');
                    break;
            }
        }

        function updateProgress(data) {
            const progress = data.progress || 0;
            document.getElementById('progressBar').style.width = progress + '%';
            document.getElementById('progressText').textContent = progress + '%';
            document.getElementById('progressDetail').textContent = 
                `${data.urls_scanned || 0}/${data.total_urls || 0} URLs`;
            document.getElementById('scanStatus').textContent = data.message || '扫描中...';
            
            document.getElementById('statUrls').textContent = data.urls_scanned || 0;
            document.getElementById('statVulns').textContent = data.vulns_found || 0;
            
            if (startTime) {
                const elapsed = Math.floor((Date.now() - startTime) / 1000);
                document.getElementById('statTime').textContent = elapsed + 's';
            }
        }

        function addLog(message, level = 'info') {
            const console = document.getElementById('logConsole');
            const entry = document.createElement('div');
            entry.className = 'log-entry';
            
            const time = new Date().toLocaleTimeString();
            let color = 'text-green-400';
            if (level === 'error') color = 'text-red-400';
            if (level === 'warn') color = 'text-yellow-400';
            
            entry.innerHTML = `<span class="text-gray-500">[${time}]</span> <span class="${color}">${message}</span>`;
            console.appendChild(entry);
            console.scrollTop = console.scrollHeight;
        }

        function addVulnerability(vuln) {
            vulnerabilities.push(vuln);
            updateStats();
        }

        function updateStats() {
            const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
            vulnerabilities.forEach(v => {
                counts[v.severity] = (counts[v.severity] || 0) + 1;
            });
            
            document.getElementById('countCritical').textContent = counts.CRITICAL;
            document.getElementById('countHigh').textContent = counts.HIGH;
            document.getElementById('countMedium').textContent = counts.MEDIUM;
            document.getElementById('countLow').textContent = counts.LOW;
            
            // 风险评分
            const score = counts.CRITICAL * 10 + counts.HIGH * 7 + counts.MEDIUM * 4 + counts.LOW * 2;
            document.getElementById('riskScore').textContent = Math.min(score, 100);
        }

        function onScanComplete(data) {
            document.getElementById('scanStatus').textContent = '扫描完成';
            document.getElementById('startBtn').disabled = false;
            document.getElementById('startBtn').innerHTML = '<i class="fas fa-play mr-2"></i>开始扫描';
            
            // 显示结果
            document.getElementById('statsCard').style.display = 'grid';
            document.getElementById('chartsCard').style.display = 'grid';
            document.getElementById('vulnsCard').style.display = 'block';
            
            renderCharts();
            renderVulnList();
            
            addLog('扫描完成！发现 ' + vulnerabilities.length + ' 个漏洞');
        }

        function renderCharts() {
            const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
            const typeCount = {};
            
            vulnerabilities.forEach(v => {
                counts[v.severity] = (counts[v.severity] || 0) + 1;
                const type = v.name.split('(')[0].trim();
                typeCount[type] = (typeCount[type] || 0) + 1;
            });

            // 严重程度饼图
            const severityCtx = document.getElementById('severityChart').getContext('2d');
            severityChart = new Chart(severityCtx, {
                type: 'doughnut',
                data: {
                    labels: ['严重', '高危', '中危', '低危'],
                    datasets: [{
                        data: [counts.CRITICAL, counts.HIGH, counts.MEDIUM, counts.LOW],
                        backgroundColor: ['#dc2626', '#d97706', '#ca8a04', '#16a34a']
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: { position: 'bottom' }
                    }
                }
            });

            // 类型柱状图
            const typeCtx = document.getElementById('typeChart').getContext('2d');
            typeChart = new Chart(typeCtx, {
                type: 'bar',
                data: {
                    labels: Object.keys(typeCount),
                    datasets: [{
                        label: '漏洞数量',
                        data: Object.values(typeCount),
                        backgroundColor: '#667eea'
                    }]
                },
                options: {
                    responsive: true,
                    plugins: { legend: { display: false } }
                }
            });
        }

        function renderVulnList() {
            const list = document.getElementById('vulnList');
            document.getElementById('vulnCount').textContent = vulnerabilities.length;
            list.innerHTML = '';
            
            vulnerabilities.forEach((vuln, index) => {
                const card = document.createElement('div');
                card.className = 'vuln-card card p-4 cursor-pointer';
                card.dataset.severity = vuln.severity;
                card.onclick = () => toggleVulnDetail(index);
                
                const severityClass = 'severity-' + vuln.severity.toLowerCase();
                
                card.innerHTML = `
                    <div class="flex items-center justify-between">
                        <div class="flex items-center space-x-3">
                            <span class="${severityClass} px-3 py-1 rounded-full text-xs font-bold">${vuln.severity}</span>
                            <span class="font-medium">${vuln.name}</span>
                        </div>
                        <div class="text-sm text-gray-500">
                            置信度: ${(vuln.confidence * 100).toFixed(0)}%
                            <i class="fas fa-chevron-down ml-2 transition" id="icon-${index}"></i>
                        </div>
                    </div>
                    <div class="text-sm text-blue-600 mt-1">${vuln.url}</div>
                    <div id="detail-${index}" class="hidden mt-4 pt-4 border-t border-gray-200">
                        <div class="grid grid-cols-2 gap-4 text-sm">
                            <div><strong>参数:</strong> ${vuln.parameter}</div>
                            <div><strong>证据:</strong> ${vuln.evidence}</div>
                        </div>
                        <div class="mt-3"><strong>描述:</strong> ${vuln.description}</div>
                        <div class="mt-2 bg-gray-100 p-3 rounded font-mono text-sm">${vuln.payload}</div>
                        <div class="mt-3"><strong>修复建议:</strong> ${vuln.remediation}</div>
                    </div>
                `;
                list.appendChild(card);
            });
        }

        function toggleVulnDetail(index) {
            const detail = document.getElementById(`detail-${index}`);
            const icon = document.getElementById(`icon-${index}`);
            detail.classList.toggle('hidden');
            icon.classList.toggle('rotate-180');
        }

        function filterVulns() {
            const severity = document.getElementById('severityFilter').value;
            const search = document.getElementById('searchVuln').value.toLowerCase();
            
            document.querySelectorAll('.vuln-card').forEach(card => {
                const matchSeverity = severity === 'all' || card.dataset.severity === severity;
                const matchSearch = !search || card.textContent.toLowerCase().includes(search);
                card.style.display = matchSeverity && matchSearch ? 'block' : 'none';
            });
        }

        async function exportReport(format) {
            if (!scanId) return;
            
            const response = await fetch(`/api/scan/${scanId}/report?format=${format}`);
            const blob = await response.blob();
            
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `wvs-report-${scanId}.${format}`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        }
    </script>
</body>
</html>"""


# ============== API 端点 ==============

@app.post("/api/scan")
async def create_scan(request: ScanRequest):
    """创建扫描任务"""
    import uuid
    scan_id = str(uuid.uuid4())[:8]
    
    active_scans[scan_id] = {
        "config": request.dict(),
        "status": "pending",
        "progress": 0,
        "vulnerabilities": [],
    }
    
    # 启动后台扫描
    asyncio.create_task(run_scan(scan_id, request))
    
    return {"scan_id": scan_id, "status": "started"}


@app.get("/api/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    """获取扫描状态"""
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan = active_scans[scan_id]
    return {
        "scan_id": scan_id,
        "status": scan["status"],
        "progress": scan["progress"],
        "vulns_found": len(scan["vulnerabilities"]),
    }


@app.get("/api/scan/{scan_id}/report")
async def get_scan_report(scan_id: str, format: str = "json"):
    """获取扫描报告"""
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan = active_scans[scan_id]
    
    if format == "json":
        return scan
    
    # 生成报告文件
    reporter = ReportGeneratorV16()
    for v in scan["vulnerabilities"]:
        reporter.add_vulnerability(Vulnerability(**v))
    
    if format == "html":
        path = reporter.generate_html_report(f"report_{scan_id}.html")
        return Path(path).read_text()
    elif format == "csv":
        path = reporter.generate_csv_report(f"report_{scan_id}.csv")
        return Path(path).read_text()
    
    raise HTTPException(status_code=400, detail="Invalid format")


# ============== WebSocket ==============

@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    """WebSocket 实时推送"""
    await websocket.accept()
    
    if scan_id not in active_scans:
        await websocket.send_json({"type": "error", "message": "Scan not found"})
        await websocket.close()
        return
    
    scan = active_scans[scan_id]
    
    try:
        while True:
            # 发送当前状态
            await websocket.send_json({
                "type": "status",
                "status": scan["status"],
                "progress": scan["progress"],
                "urls_scanned": scan.get("urls_scanned", 0),
                "total_urls": scan.get("total_urls", 0),
                "vulns_found": len(scan["vulnerabilities"]),
                "message": scan.get("message", ""),
            })
            
            if scan["status"] in ["completed", "failed"]:
                await websocket.send_json({
                    "type": "complete",
                    "vulnerabilities": scan["vulnerabilities"],
                })
                break
            
            await asyncio.sleep(1)
    
    except WebSocketDisconnect:
        pass


# ============== 扫描执行 ==============

async def run_scan(scan_id: str, config: ScanRequest):
    """执行扫描任务"""
    import aiohttp
    
    scan = active_scans[scan_id]
    scan["status"] = "running"
    
    try:
        async with aiohttp.ClientSession() as session:
            # 爬虫
            scan["message"] = "爬取中..."
            crawler = CrawlerV16({
                "max_depth": config.max_depth,
                "max_urls": config.max_urls,
            })
            
            pages = await crawler.crawl(config.target, session)
            scan["urls_scanned"] = len(pages)
            scan["total_urls"] = len(pages)
            scan["progress"] = 30
            
            # SQL 注入
            if config.scan_sqli:
                scan["message"] = "检测 SQL 注入..."
                sqli_scanner = SQLiScannerV16()
                
                for i, page in enumerate(pages):
                    results = await sqli_scanner.scan(page.url, session)
                    for r in results:
                        if r.vulnerable:
                            vuln = {
                                "name": f"SQL 注入 ({r.injection_type.value})",
                                "severity": "CRITICAL" if r.injection_type.value in ["error_based", "union_based"] else "HIGH",
                                "url": page.url,
                                "parameter": r.parameter,
                                "payload": r.payload,
                                "description": f"检测到 {r.injection_type.value} 型 SQL 注入",
                                "remediation": "使用参数化查询，禁止拼接 SQL 字符串",
                                "confidence": r.confidence,
                                "evidence": r.evidence,
                            }
                            scan["vulnerabilities"].append(vuln)
                    
                    scan["progress"] = 30 + (i + 1) / len(pages) * 30
            
            # XSS
            if config.scan_xss:
                scan["message"] = "检测 XSS..."
                xss_scanner = XSSScannerV16()
                
                for i, page in enumerate(pages):
                    results = await xss_scanner.scan(page.url, session)
                    for r in results:
                        if r.vulnerable:
                            vuln = {
                                "name": f"XSS ({r.xss_type.value})",
                                "severity": "HIGH",
                                "url": page.url,
                                "parameter": r.parameter,
                                "payload": r.payload,
                                "description": f"检测到 {r.xss_type.value} 型 XSS",
                                "remediation": "对用户输入进行 HTML 转义，使用 CSP",
                                "confidence": r.confidence,
                                "evidence": r.evidence,
                            }
                            scan["vulnerabilities"].append(vuln)
                    
                    scan["progress"] = 60 + (i + 1) / len(pages) * 30
            
            scan["progress"] = 100
            scan["status"] = "completed"
            scan["message"] = "扫描完成"
    
    except Exception as e:
        scan["status"] = "failed"
        scan["message"] = str(e)


# ============== 启动 ==============

def start_web_ui(host: str = "0.0.0.0", port: int = 8080):
    """启动 Web UI"""
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    start_web_ui()
