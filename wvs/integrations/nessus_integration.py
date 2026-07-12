"""
Nessus Integration Module — Tenable Nessus API 集成

通过 Nessus REST API 远程调度扫描，获取结果并转换为 Vulnerability 对象。

支持:
  - Nessus v8 ~ v10.9 (REST API v1)
  - 多 Nessus 实例管理
  - 扫描策略管理
  - 结果拉取与转换
"""

import asyncio
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import urljoin

from ..config import ConfigManager
from ..models import Confidence, Severity, Vulnerability, VulnerabilityType

logger = logging.getLogger("wvs.integrations.nessus")

# Nessus Severity 映射 (Nessus: 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical)
NESSUS_SEVERITY_MAP = {
    0: Severity.INFO,
    1: Severity.LOW,
    2: Severity.MEDIUM,
    3: Severity.HIGH,
    4: Severity.CRITICAL,
}

NESSUS_POLL_INTERVAL = 30
NESSUS_DEFAULT_TIMEOUT = 7200  # 2 hours


@dataclass
class NessusInstance:
    """Nessus 实例配置"""

    name: str
    host: str
    port: int = 8834
    access_key: str = ""
    secret_key: str = ""
    verify_ssl: bool = False
    max_concurrent: int = 1
    policy_id: int = 0  # 0 = Basic Network Scan
    description: str = ""


class NessusClient:
    """Nessus REST API 客户端"""

    def __init__(self, instance: NessusInstance, timeout: int = 60):
        self.instance = instance
        self.base_url = f"https://{instance.host}:{instance.port}"
        self.timeout = timeout
        self._headers = {
            "X-ApiKeys": f"accessKey={instance.access_key}; secretKey={instance.secret_key}",
            "Content-Type": "application/json",
        }

    async def _request(self, method: str, path: str, data: Optional[dict] = None) -> Optional[dict]:
        """发送 HTTP 请求到 Nessus API"""
        import httpx

        url = urljoin(self.base_url, path)
        try:
            async with httpx.AsyncClient(
                verify=self.instance.verify_ssl,
                timeout=self.timeout,
            ) as client:
                if method.upper() == "GET":
                    resp = await client.get(url, headers=self._headers)
                elif method.upper() == "POST":
                    resp = await client.post(url, headers=self._headers, json=data)
                else:
                    return None

                if resp.status_code in (200, 201):
                    return resp.json() if resp.text else {}
                elif resp.status_code == 401:
                    logger.error(f"[Nessus] 认证失败: {self.instance.name}")
                    return None
                else:
                    logger.warning(f"[Nessus] API 错误 ({resp.status_code})")
                    return None
        except Exception as e:
            logger.error(f"[Nessus] 连接失败 ({self.instance.host}): {e}")
            return None

    async def test_connection(self) -> bool:
        """测试连接"""
        result = await self._request("GET", "/server/status")
        return result is not None

    async def create_scan(self, name: str, target: str, policy_id: int = 0) -> Optional[str]:
        """创建扫描任务"""
        data = {
            "uuid": "ad629e16-03b6-8c1d-cef6-ef8c9dd3c658" if not policy_id else None,
            "settings": {
                "name": name,
                "text_targets": target,
                "enabled": True,
                "launch": "ONETIME",
            },
        }
        result = await self._request("POST", "/scans", data)
        if result:
            scan_id = result.get("scan", {}).get("id")
            if scan_id:
                logger.info(f"[Nessus] 扫描创建成功: {name} (id={scan_id})")
                return str(scan_id)
        return None

    async def launch_scan(self, scan_id: str) -> bool:
        """启动扫描"""
        result = await self._request("POST", f"/scans/{scan_id}/launch")
        return result is not None

    async def get_scan_status(self, scan_id: str) -> Optional[dict]:
        """获取扫描状态"""
        result = await self._request("GET", f"/scans/{scan_id}")
        if result:
            info = result.get("info", {}) or result
            status = info.get("status", "unknown")
            progress = 100 if status == "completed" else 50 if status == "running" else 0
            return {"status": status, "progress": progress}
        return None

    async def wait_for_completion(self, scan_id: str, timeout: int = NESSUS_DEFAULT_TIMEOUT) -> dict:
        """等待扫描完成"""
        start = asyncio.get_event_loop().time()
        while True:
            elapsed = asyncio.get_event_loop().time() - start
            if elapsed > timeout:
                return {"status": "timeout", "scan_id": scan_id}

            status = await self.get_scan_status(scan_id)
            if not status:
                return {"status": "error", "scan_id": scan_id}

            if status["status"] in ("completed", "canceled", "aborted"):
                return {"status": status["status"], "scan_id": scan_id}

            await asyncio.sleep(NESSUS_POLL_INTERVAL)

    async def get_vulnerabilities(self, scan_id: str) -> Optional[List[dict]]:
        """获取扫描结果的漏洞列表"""
        result = await self._request("GET", f"/scans/{scan_id}")
        if not result:
            return None

        vulns = result.get("vulnerabilities", []) or []
        # 获取每个漏洞的详情
        detailed_vulns = []
        for v in vulns[:100]:  # 限制最多 100 个
            plugin_id = v.get("plugin_id")
            if plugin_id:
                detail = await self._get_vuln_detail(scan_id, plugin_id)
                if detail:
                    detailed_vulns.append(detail)
        return detailed_vulns or vulns

    async def _get_vuln_detail(self, scan_id: str, plugin_id: int) -> Optional[dict]:
        """获取单个漏洞详情"""
        result = await self._request("GET", f"/scans/{scan_id}/plugins/{plugin_id}")
        return result

    async def delete_scan(self, scan_id: str) -> bool:
        """删除扫描"""
        result = await self._request("DELETE", f"/scans/{scan_id}")
        return result is not None


class NessusIntegration:
    """Nessus 扫描器集成"""

    def __init__(self, config: Optional[ConfigManager] = None):
        self.config = config or ConfigManager()
        self.instances: List[NessusInstance] = []
        self._clients: Dict[str, NessusClient] = {}
        self._stats = {"scans_started": 0, "scans_completed": 0, "vulns_found": 0, "errors": 0}
        self._load_instances()

    def _load_instances(self) -> None:
        nessus_config = self.config.get("integrations.nessus", {})
        instances_config = nessus_config.get("instances", [])
        if isinstance(instances_config, list):
            for cfg in instances_config:
                inst = NessusInstance(
                    name=cfg.get("name", "default"),
                    host=cfg.get("host", ""),
                    port=cfg.get("port", 8834),
                    access_key=cfg.get("access_key", ""),
                    secret_key=cfg.get("secret_key", ""),
                    verify_ssl=cfg.get("verify_ssl", False),
                )
                if inst.host and inst.access_key:
                    self.add_instance(inst)

    def add_instance(self, instance: NessusInstance) -> None:
        self.instances.append(instance)
        self._clients[instance.name] = NessusClient(instance)

    def get_client(self, name: str = "default") -> Optional[NessusClient]:
        if name in self._clients:
            return self._clients[name]
        if self._clients:
            return list(self._clients.values())[0]
        return None

    @property
    def is_available(self) -> bool:
        return len(self.instances) > 0

    async def scan(
        self,
        url: str,
        instance_name: str = "default",
        wait_for_result: bool = True,
        timeout: int = NESSUS_DEFAULT_TIMEOUT,
    ) -> List[Vulnerability]:
        """使用 Nessus 扫描目标"""
        client = self.get_client(instance_name)
        if not client:
            logger.error(f"[Nessus] 无可用的实例: {instance_name}")
            return []

        logger.info(f"[Nessus] 开始扫描: {url}")

        scan_id = await client.create_scan(f"RayScan-{url[:40]}", url)
        if not scan_id:
            self._stats["errors"] += 1
            return []

        launched = await client.launch_scan(scan_id)
        if not launched:
            self._stats["errors"] += 1
            return []

        self._stats["scans_started"] += 1

        if not wait_for_result:
            return []

        result = await client.wait_for_completion(scan_id, timeout)
        self._stats["scans_completed"] += 1

        if result["status"] != "completed":
            return []

        raw_vulns = await client.get_vulnerabilities(scan_id)
        if not raw_vulns:
            return []

        vulns = [self._convert_vulnerability(v, url) for v in raw_vulns]
        vulns = [v for v in vulns if v is not None]
        self._stats["vulns_found"] += len(vulns)
        return vulns

    def _convert_vulnerability(self, nessus_vuln: dict, base_url: str) -> Optional[Vulnerability]:
        """转换 Nessus 漏洞到 Vulnerability"""
        try:
            plugin_name = nessus_vuln.get("plugin_name", "") or ""
            severity_id = nessus_vuln.get("severity", 0) or 0
            severity = NESSUS_SEVERITY_MAP.get(int(severity_id), Severity.INFO)
            plugin_id = nessus_vuln.get("plugin_id", 0)
            description = nessus_vuln.get("description", "") or nessus_vuln.get("plugin_name", "")
            solution = nessus_vuln.get("solution", "") or nessus_vuln.get("remediation", "")
            cvss_score = nessus_vuln.get("cvss3_score") or nessus_vuln.get("cvss_score")
            output = nessus_vuln.get("output", "") or ""
            host = nessus_vuln.get("hostname", "") or base_url

            # 推断漏洞类型
            vuln_type = self._infer_type(plugin_name, description)

            # CWE
            cwe_id = nessus_vuln.get("cwe_id")
            if cwe_id and isinstance(cwe_id, str):
                try:
                    cwe_id = int(cwe_id.replace("CWE-", ""))
                except ValueError:
                    cwe_id = None

            return Vulnerability(
                type=vuln_type,
                title=f"[Nessus] {plugin_name}",
                url=host,
                severity=severity,
                confidence=Confidence.HIGH,
                cvss_score=float(cvss_score) if cvss_score else None,
                cwe_id=cwe_id,
                description=description[:500] if description else plugin_name,
                recommendation=solution[:500] if solution else "参考 Nessus 修复建议",
                evidence=output[:200] if output else f"Plugin {plugin_id}",
                module="nessus",
                tags=["nessus", "tenable", vuln_type.value],
                context={"source": "nessus", "plugin_id": plugin_id, "plugin_name": plugin_name},
            )
        except Exception as e:
            logger.debug(f"[Nessus] 漏洞转换失败: {e}")
            return None

    @staticmethod
    def _infer_type(plugin_name: str, description: str) -> VulnerabilityType:
        combined = (plugin_name + " " + description).lower()
        keywords = {
            VulnerabilityType.SQL_INJECTION: ["sql injection", "sql injection"],
            VulnerabilityType.XSS: ["xss", "cross-site", "cross site scripting"],
            VulnerabilityType.REMOTE_CODE_EXECUTION: ["rce", "remote code", "code exec"],
            VulnerabilityType.INFO_DISCLOSURE: ["disclosure", "leak", "exposed", "information"],
            VulnerabilityType.LFI: ["lfi", "file inclusion", "directory traversal"],
            VulnerabilityType.SSRF: ["ssrf", "server-side request"],
            VulnerabilityType.XXE: ["xxe", "xml external entity"],
            VulnerabilityType.BROKEN_AUTH: ["authentication", "login", "credential"],
        }
        for vuln_type, kws in keywords.items():
            if any(kw in combined for kw in kws):
                return vuln_type
        return VulnerabilityType.OTHER

    def get_stats(self) -> dict:
        return self._stats.copy()
