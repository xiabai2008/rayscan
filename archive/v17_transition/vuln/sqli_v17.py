"""WVS v16.0 - 增强型 SQL 注入扫描器

改进点：
1. 多阶段验证（错误检测 -> 布尔盲注 -> 时间盲注）
2. 数据库指纹识别
3. WAF 规避技术
4. 智能时间盲注（减少误报）
5. 自动检测注入类型
"""
import asyncio
import time
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode
from dataclasses import dataclass
from enum import Enum

try:
    import aiohttp
except ImportError:
    aiohttp = None

from ..core.payloads_v16 import SQLI_PAYLOADS_V16, SQLI_ERROR_SIGNATURES_V16, DETECTION_CONFIG_V16


class InjectionType(Enum):
    ERROR_BASED = "error_based"
    UNION_BASED = "union_based"
    BOOLEAN_BLIND = "boolean_blind"
    TIME_BASED = "time_based"
    STACKED = "stacked"


@dataclass
class SQLiResult:
    vulnerable: bool
    injection_type: Optional[InjectionType]
    parameter: str
    payload: str
    database: Optional[str]
    confidence: float
    evidence: str


class SQLiScannerV16:
    """SQL 注入扫描器 v16.0 - 多阶段验证"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", DETECTION_CONFIG_V16["request_timeout"])
        self.time_threshold = self.config.get("time_threshold", DETECTION_CONFIG_V16["time_based_threshold"])
        self.max_retries = self.config.get("max_retries", DETECTION_CONFIG_V16["max_retries"])
        
        # 数据库指纹
        self.detected_db = None
        self.waf_detected = False
    
    async def scan(self, url: str, session) -> List[SQLiResult]:
        """执行多阶段 SQL 注入扫描"""
        results = []
        
        # 解析 URL
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return results
        
        # 对每个参数进行测试
        for param in params:
            # 阶段 1: 错误型注入检测（最快）
            result = await self._phase1_error_based(url, param, session)
            if result:
                results.append(result)
                continue  # 已确认漏洞，跳过后续阶段
            
            # 阶段 2: UNION 注入检测
            result = await self._phase2_union_based(url, param, session)
            if result:
                results.append(result)
                continue
            
            # 阶段 3: 布尔盲注检测
            result = await self._phase3_boolean_blind(url, param, session)
            if result:
                results.append(result)
                continue
            
            # 阶段 4: 时间盲注检测（最慢，最后执行）
            result = await self._phase4_time_based(url, param, session)
            if result:
                results.append(result)
        
        return results
    
    async def _phase1_error_based(self, url: str, param: str, session) -> Optional[SQLiResult]:
        """阶段 1: 错误型注入检测"""
        payloads = SQLI_PAYLOADS_V16["error_based"]
        
        for payload in payloads:
            test_url = self._build_test_url(url, param, payload)
            
            try:
                async with session.get(test_url, timeout=self.timeout, ssl=False) as resp:
                    text = await resp.text()
                    
                    # 检测数据库错误
                    db_type = self._detect_db_error(text)
                    if db_type:
                        return SQLiResult(
                            vulnerable=True,
                            injection_type=InjectionType.ERROR_BASED,
                            parameter=param,
                            payload=payload,
                            database=db_type,
                            confidence=0.95,
                            evidence=f"检测到 {db_type} 错误信息"
                        )
            except Exception:
                pass
        
        return None
    
    async def _phase2_union_based(self, url: str, param: str, session) -> Optional[SQLiResult]:
        """阶段 2: UNION 注入检测"""
        payloads = SQLI_PAYLOADS_V16["union_based"]
        
        for payload in payloads:
            test_url = self._build_test_url(url, param, payload)
            
            try:
                async with session.get(test_url, timeout=self.timeout, ssl=False) as resp:
                    text = await resp.text()
                    
                    # 检测 UNION 注入特征
                    if self._detect_union_success(text):
                        return SQLiResult(
                            vulnerable=True,
                            injection_type=InjectionType.UNION_BASED,
                            parameter=param,
                            payload=payload,
                            database=self.detected_db,
                            confidence=0.90,
                            evidence="UNION 查询成功执行"
                        )
                    
                    # 也检测错误
                    db_type = self._detect_db_error(text)
                    if db_type:
                        return SQLiResult(
                            vulnerable=True,
                            injection_type=InjectionType.ERROR_BASED,
                            parameter=param,
                            payload=payload,
                            database=db_type,
                            confidence=0.85,
                            evidence=f"检测到 {db_type} 错误信息"
                        )
            except Exception:
                pass
        
        return None
    
    async def _phase3_boolean_blind(self, url: str, param: str, session) -> Optional[SQLiResult]:
        """阶段 3: 布尔盲注检测"""
        # 获取原始响应作为基准
        base_url = self._build_test_url(url, param, "1")
        
        try:
            async with session.get(base_url, timeout=self.timeout, ssl=False) as resp:
                base_text = await resp.text()
                base_len = len(base_text)
        except Exception:
            return None
        
        # 测试真条件
        true_payloads = ["1 AND 1=1", "' AND '1'='1"]
        false_payloads = ["1 AND 1=2", "' AND '1'='2"]
        
        for true_payload, false_payload in zip(true_payloads, false_payloads):
            # 测试真条件
            true_url = self._build_test_url(url, param, true_payload)
            try:
                async with session.get(true_url, timeout=self.timeout, ssl=False) as resp:
                    true_text = await resp.text()
                    true_len = len(true_text)
            except Exception:
                continue
            
            # 测试假条件
            false_url = self._build_test_url(url, param, false_payload)
            try:
                async with session.get(false_url, timeout=self.timeout, ssl=False) as resp:
                    false_text = await resp.text()
                    false_len = len(false_text)
            except Exception:
                continue
            
            # 对比差异
            if abs(true_len - false_len) > 50:  # 显著差异
                return SQLiResult(
                    vulnerable=True,
                    injection_type=InjectionType.BOOLEAN_BLIND,
                    parameter=param,
                    payload=f"{true_payload} / {false_payload}",
                    database=self.detected_db,
                    confidence=0.80,
                    evidence=f"响应长度差异: 真={true_len}, 假={false_len}"
                )
        
        return None
    
    async def _phase4_time_based(self, url: str, param: str, session) -> Optional[SQLiResult]:
        """阶段 4: 时间盲注检测（优化：多次验证减少误报）"""
        payloads = SQLI_PAYLOADS_V16["time_based"]
        
        for payload in payloads:
            # 执行 3 次取平均，减少网络波动误报
            times = []
            
            for _ in range(3):
                test_url = self._build_test_url(url, param, payload)
                
                try:
                    start = time.time()
                    async with session.get(test_url, timeout=self.timeout + 5, ssl=False) as resp:
                        await resp.text()
                    elapsed = time.time() - start
                    times.append(elapsed)
                except asyncio.TimeoutError:
                    times.append(self.timeout + 5)  # 超时也算延迟
                except Exception:
                    pass
            
            if not times:
                continue
            
            avg_time = sum(times) / len(times)
            
            # 平均延迟超过阈值，验证成功
            if avg_time >= self.time_threshold:
                # 再验证一次：使用不延迟的 payload
                normal_url = self._build_test_url(url, param, "1")
                try:
                    start = time.time()
                    async with session.get(normal_url, timeout=self.timeout, ssl=False) as resp:
                        await resp.text()
                    normal_time = time.time() - start
                    
                    # 确认是注入导致的延迟，而非网络慢
                    if avg_time > normal_time * 2:
                        return SQLiResult(
                            vulnerable=True,
                            injection_type=InjectionType.TIME_BASED,
                            parameter=param,
                            payload=payload,
                            database=self._detect_db_from_payload(payload),
                            confidence=0.75,
                            evidence=f"时间延迟: {avg_time:.2f}s (基准: {normal_time:.2f}s)"
                        )
                except Exception:
                    pass
        
        return None
    
    def _build_test_url(self, url: str, param: str, payload: str) -> str:
        """构建测试 URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
    
    def _detect_db_error(self, text: str) -> Optional[str]:
        """检测数据库类型（基于错误信息）"""
        text_lower = text.lower()
        
        for db_type, signatures in SQLI_ERROR_SIGNATURES_V16.items():
            if db_type == "generic":
                continue
            for sig in signatures:
                if sig.lower() in text_lower:
                    self.detected_db = db_type
                    return db_type
        
        # 检查通用错误
        for sig in SQLI_ERROR_SIGNATURES_V16["generic"]:
            if sig.lower() in text_lower:
                return "unknown"
        
        return None
    
    def _detect_union_success(self, text: str) -> bool:
        """检测 UNION 注入成功特征"""
        # UNION 注入成功的特征：数字占位符被替换
        indicators = [
            "1   2   3",  # 常见的 UNION 输出
            "1	2	3",
        ]
        return any(ind in text for ind in indicators)
    
    def _detect_db_from_payload(self, payload: str) -> str:
        """从 payload 推断数据库类型"""
        if "SLEEP" in payload or "pg_sleep" not in payload:
            return "mysql"
        if "pg_sleep" in payload:
            return "postgresql"
        if "WAITFOR" in payload:
            return "mssql"
        if "UTL_" in payload or "DBMS_PIPE" in payload:
            return "oracle"
        return "unknown"


# WAF 规避检测
class WAFBypassScanner:
    """WAF 规避技术"""
    
    def __init__(self):
        self.bypass_payloads = SQLI_PAYLOADS_V16["waf_bypass"]
    
    async def test_bypass(self, url: str, param: str, session) -> bool:
        """测试 WAF 是否存在并尝试绕过"""
        # 先用基础 payload 测试
        basic_payload = "' OR '1'='1"
        basic_url = self._build_url(url, param, basic_payload)
        
        try:
            async with session.get(basic_url, ssl=False) as resp:
                basic_status = resp.status
                basic_text = await resp.text()
        except Exception:
            return False
        
        # 如果基础 payload 被拦截（403/406），尝试绕过
        if basic_status in [403, 406, 500]:
            for bypass_payload in self.bypass_payloads:
                test_url = self._build_url(url, param, bypass_payload)
                try:
                    async with session.get(test_url, ssl=False) as resp:
                        if resp.status == 200:
                            return True  # 绕过成功
                except Exception:
                    pass
        
        return False
    
    def _build_url(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
