"""
Metasploit Integration Module — 漏洞验证链

通过 Metasploit RPC (msgrpc) 接口，对扫描发现的漏洞进行自动化验证利用。

功能:
  - 自动匹配漏洞到 MSF exploit/auxiliary 模块
  - 执行 check 命令验证漏洞真实性
  - 可选执行 exploit 获取 shell
  - 结果状态追踪
"""

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ..config import ConfigManager
from ..models import Vulnerability, VulnerabilityType

logger = logging.getLogger("wvs.integrations.metasploit")

# Metasploit 默认连接配置
MSF_DEFAULT_HOST = "127.0.0.1"
MSF_DEFAULT_PORT = 55552
MSF_DEFAULT_PASS = "rayScanMSF!"
MSF_DEFAULT_TIMEOUT = 120

# ── 漏洞类型 → MSF 模块匹配规则 ─────────────────────────────
# 每条规则: (关键匹配词, 模块类型, 模块路径模板)
MSF_MODULE_RULES: List[Tuple[List[str], str, str]] = [
    # Web 应用漏洞
    (["phpmyadmin", "phpmyadmin"], "auxiliary", "scanner/http/phpmyadmin_{suffix}"),
    (["jenkins", "jenkins"], "exploit", "multi/http/jenkins_{suffix}"),
    (["tomcat", "tomcat"], "exploit", "multi/http/tomcat_{suffix}"),
    (["struts", "struts2", "s2-"], "exploit", "multi/http/struts2_{suffix}"),
    (["weblogic", "oracle-weblogic"], "exploit", "multi/http/weblogic_{suffix}"),
    (["jboss", "jbossas"], "exploit", "multi/http/jboss_{suffix}"),
    (["confluence", "atlassian-confluence"], "exploit", "multi/http/confluence_{suffix}"),
    (["wordpress", "wp-"], "exploit", "unix/webapp/wp_{suffix}"),
    (["drupal"], "exploit", "unix/webapp/drupal_{suffix}"),
    (["joomla"], "exploit", "unix/webapp/joomla_{suffix}"),
    (["phpmyadmin"], "auxiliary", "scanner/http/phpmyadmin_login"),
    # SQL 注入
    (["sql_injection", "sqli"], "auxiliary", "scanner/http/sql_injection"),
    # RCE
    (["rce", "remote_code_execution", "code_exec"], "exploit", "multi/handler"),
    # 文件包含
    (["lfi", "local_file_inclusion", "file_read"], "auxiliary", "scanner/http/lfi"),
    # SSRF
    (["ssrf", "server_side_request_forgery"], "auxiliary", "scanner/http/ssrf"),
]

COMMON_TARGET_PATTERNS: Dict[str, str] = {
    "tomcat": "multi/http/tomcat_mgr_upload",
    "jenkins": "multi/http/jenkins_script_console",
    "weblogic": "multi/http/weblogic_deserialize_asyncresponseservice",
    "struts2": "multi/http/struts2_content_type_ognl",
    "jboss": "multi/http/jboss_deploymentfilerepository",
    "confluence": "multi/http/confluence_webwork_ognl_injection",
}

try:
    from msgpack import Unpacker, packb

    MSGPACK_AVAILABLE = True
except ImportError:
    MSGPACK_AVAILABLE = False


@dataclass
class MSFResult:
    """Metasploit 验证结果"""

    module_name: str
    module_type: str  # exploit / auxiliary
    target_url: str
    status: str  # vulnerable / not_vulnerable / error / timeout
    confidence: float = 0.0  # 0-1
    output: str = ""
    session_id: Optional[int] = None  # 如果 exploit 成功
    error: Optional[str] = None


class MetasploitRPCClient:
    """Metasploit RPC 客户端 (msgpack 协议)"""

    def __init__(
        self,
        host: str = MSF_DEFAULT_HOST,
        port: int = MSF_DEFAULT_PORT,
        password: str = MSF_DEFAULT_PASS,
        timeout: int = MSF_DEFAULT_TIMEOUT,
        ssl: bool = False,
    ):
        self.host = host
        self.port = port
        self.password = password
        self.timeout = timeout
        self.ssl = ssl
        self._token: Optional[str] = None
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._connected = False

    async def connect(self) -> bool:
        """连接到 Metasploit RPC 服务"""
        if self._connected:
            return True

        if not MSGPACK_AVAILABLE:
            logger.warning("[MSF] msgpack 未安装 (pip install msgpack)")
            return False

        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=10,
            )
            # 认证
            result = await self._send_request("auth.login", self.password)
            if result and isinstance(result, dict) and result.get(b"result") == b"success":
                self._token = (
                    result.get(b"token", b"").decode()
                    if isinstance(result.get(b"token"), bytes)
                    else str(result.get("token", ""))
                )
                self._connected = True
                logger.info(f"[MSF] 连接成功 ({self.host}:{self.port})")
                return True
            else:
                logger.error(f"[MSF] 认证失败: {result}")
                await self.disconnect()
                return False
        except asyncio.TimeoutError:
            logger.error(f"[MSF] 连接超时 ({self.host}:{self.port})")
            return False
        except ConnectionRefusedError:
            logger.error(f"[MSF] 连接被拒绝 ({self.host}:{self.port})")
            return False
        except Exception as e:
            logger.error(f"[MSF] 连接失败: {e}")
            return False

    async def disconnect(self) -> None:
        """断开连接"""
        self._connected = False
        if self._writer:
            try:
                self._writer.close()
            except Exception:
                pass
            self._writer = None
            self._reader = None

    async def _send_request(self, method: str, *args) -> Optional[dict]:
        """发送 msgpack RPC 请求"""
        if not self._writer or not self._reader:
            return None

        # 构建请求
        if self._token:
            params = [self._token, method] + list(args)
        else:
            params = [method] + list(args)

        try:
            data = packb(params) if MSGPACK_AVAILABLE else b""
            self._writer.write(data)
            await self._writer.drain()

            # 读取响应
            unpacker = Unpacker()
            while True:
                chunk = await asyncio.wait_for(
                    self._reader.read(4096),
                    timeout=self.timeout,
                )
                if not chunk:
                    break
                unpacker.feed(chunk)
                for item in unpacker:
                    return item
            return None
        except asyncio.TimeoutError:
            logger.warning(f"[MSF] RPC 请求超时: {method}")
            return None
        except Exception as e:
            logger.error(f"[MSF] RPC 请求失败: {method}: {e}")
            return None

    async def execute_module(
        self,
        module_type: str,
        module_name: str,
        payload: str = "",
        options: Optional[Dict[str, Any]] = None,
    ) -> dict:
        """执行 MSF 模块 (check 或 exploit)"""
        if not self._connected:
            return {"error": "not connected"}

        opts = options or {}
        if module_type == "exploit" and payload:
            opts["PAYLOAD"] = payload

        # 设置模块选项
        for key, value in opts.items():
            await self._send_request("module.set_option", module_type, module_name, key, str(value))

        result = await self._send_request("module.execute", module_type, module_name)
        return result or {}

    async def check_vulnerability(
        self,
        module_name: str,
        target_url: str,
        module_type: str = "auxiliary",
        extra_options: Optional[Dict[str, Any]] = None,
    ) -> MSFResult:
        """验证某个模块是否可利用"""
        opts = {
            "RHOSTS": target_url.split("://")[-1].split(":")[0] if "://" in target_url else target_url,
            "RPORT": 80 if not target_url.startswith("https") else 443,
            "SSL": str(target_url.startswith("https")).lower(),
            "TARGETURI": "/",
        }
        if extra_options:
            opts.update(extra_options)

        if ":" in target_url.split("://")[-1] if "://" in target_url else target_url:
            host_part = target_url.split("://")[-1] if "://" in target_url else target_url
            if ":" in host_part:
                host, port = host_part.split(":")[0], host_part.split(":")[1].split("/")[0]
                opts["RHOSTS"] = host
                opts["RPORT"] = int(port)

        result = await self.execute_module(module_type, module_name, options=opts)

        # 解析结果
        if isinstance(result, dict):
            output = str(result.get(b"message", result.get("message", "")))
            status_text = (
                (result.get(b"result") or result.get("result") or b"").decode()
                if isinstance(result.get(b"result"), bytes)
                else str(result.get("result", ""))
            )

            if "vulnerable" in output.lower() or "vulnerable" in status_text.lower():
                return MSFResult(
                    module_name=module_name,
                    module_type=module_type,
                    target_url=target_url,
                    status="vulnerable",
                    confidence=0.9,
                    output=output[:500],
                )
            elif status_text == "success" or "success" in output.lower():
                return MSFResult(
                    module_name=module_name,
                    module_type=module_type,
                    target_url=target_url,
                    status="vulnerable",
                    confidence=0.8,
                    output=output[:500],
                )
            elif "not vulnerable" in output.lower() or "not found" in output.lower():
                return MSFResult(
                    module_name=module_name,
                    module_type=module_type,
                    target_url=target_url,
                    status="not_vulnerable",
                    confidence=0.1,
                    output=output[:500],
                )
            else:
                return MSFResult(
                    module_name=module_name,
                    module_type=module_type,
                    target_url=target_url,
                    status="unknown",
                    confidence=0.3,
                    output=output[:500],
                )

        return MSFResult(
            module_name=module_name,
            module_type=module_type,
            target_url=target_url,
            status="error",
            error=str(result),
        )


class MetasploitIntegration:
    """Metasploit 漏洞验证集成"""

    def __init__(self, config: Optional[ConfigManager] = None):
        self.config = config or ConfigManager()
        self._client: Optional[MetasploitRPCClient] = None
        self._stats = {"checks_run": 0, "confirmed": 0, "rejected": 0, "errors": 0}

    async def _get_client(self) -> Optional[MetasploitRPCClient]:
        """获取或创建 RPC 客户端"""
        if self._client and self._client._connected:
            return self._client

        msf_config = self.config.get("integrations.metasploit", {})
        if not msf_config:
            logger.info("[MSF] Metasploit 未配置 (integrations.metasploit)")
            return None

        self._client = MetasploitRPCClient(
            host=msf_config.get("host", MSF_DEFAULT_HOST),
            port=msf_config.get("port", MSF_DEFAULT_PORT),
            password=msf_config.get("password", MSF_DEFAULT_PASS),
            timeout=msf_config.get("timeout", MSF_DEFAULT_TIMEOUT),
        )

        connected = await self._client.connect()
        if not connected:
            self._client = None
            return None
        return self._client

    @property
    def is_available(self) -> bool:
        """检查 MSF RPC 是否可用 (消息同步检查)"""
        return MSGPACK_AVAILABLE

    async def verify_vulnerability(self, vuln: Vulnerability) -> Optional[MSFResult]:
        """验证单个漏洞"""
        client = await self._get_client()
        if not client:
            return None

        module_name = self._find_msf_module(vuln)
        if not module_name:
            logger.debug(f"[MSF] 未找到匹配模块: {vuln.title}")
            return None

        logger.info(f"[MSF] 验证: {module_name} -> {vuln.url}")
        self._stats["checks_run"] += 1

        # 确定模块类型
        module_type = (
            "exploit"
            if vuln.type
            in (
                VulnerabilityType.REMOTE_CODE_EXECUTION,
                VulnerabilityType.SQL_INJECTION,
                VulnerabilityType.COMMAND_INJECTION,
            )
            else "auxiliary"
        )

        result = await client.check_vulnerability(module_name, vuln.url or "", module_type)

        if result.status == "vulnerable":
            self._stats["confirmed"] += 1
        elif result.status == "not_vulnerable":
            self._stats["rejected"] += 1
        else:
            self._stats["errors"] += 1

        return result

    async def verify_batch(self, vulnerabilities: List[Vulnerability]) -> List[Tuple[Vulnerability, MSFResult]]:
        """批量验证漏洞"""
        results = []
        for vuln in vulnerabilities:
            result = await self.verify_vulnerability(vuln)
            if result:
                results.append((vuln, result))
        return results

    def _find_msf_module(self, vuln: Vulnerability) -> Optional[str]:
        """从漏洞信息匹配 MSF 模块"""
        url_lower = (vuln.url or "").lower()
        title_lower = (vuln.title or "").lower()
        tags_lower = [t.lower() for t in (vuln.tags or [])]
        desc_lower = (vuln.description or "").lower()
        combined = f"{url_lower} {title_lower} {desc_lower} {' '.join(tags_lower)}"

        # 先匹配已知服务
        for service, module in COMMON_TARGET_PATTERNS.items():
            if service in combined:
                return module

        # 再匹配规则
        for keywords, mtype, template in MSF_MODULE_RULES:
            for kw in keywords:
                if kw.lower() in combined:
                    # 提取后缀
                    suffix = "rce" if "rce" in combined.lower() else "exec" if "exec" in combined else "exploit"
                    return template.replace("{suffix}", suffix)

        return None

    def get_stats(self) -> dict:
        return self._stats.copy()
