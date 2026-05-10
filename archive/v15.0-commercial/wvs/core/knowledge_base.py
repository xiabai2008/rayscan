"""漏洞知识库 - CVE 关联和修复指南"""
from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class VulnKnowledge:
    """漏洞知识条目"""
    name: str
    category: str  # xss, sqli, csrf, etc.
    description: str
    severity: str
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    fix_guide: str = ""
    references: List[str] = field(default_factory=list)
    prevention: List[str] = field(default_factory=list)
    detection_patterns: List[str] = field(default_factory=list)


# 漏洞知识库
VULNERABILITY_KB: Dict[str, VulnKnowledge] = {
    "xss": VulnKnowledge(
        name="Cross-Site Scripting (XSS)",
        category="xss",
        description="跨站脚本攻击，攻击者注入恶意脚本到网页中",
        severity="HIGH",
        cvss_score=6.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        cve_ids=["CVE-2023-38433", "CVE-2023-29489"],
        cwe_ids=["CWE-79"],
        fix_guide="""
1. 对所有用户输入进行 HTML 转义
2. 使用 Content Security Policy (CSP)
3. 使用现代框架的自动转义功能
4. 对 DOM 操作使用安全的 API
        """.strip(),
        references=[
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
        prevention=[
            "输入验证和过滤",
            "输出编码和转义",
            "使用 HTTP-only Cookie",
            "实施 CSP 策略",
        ],
        detection_patterns=[
            "<script>",
            "javascript:",
            "onerror=",
            "onload=",
        ],
    ),
    
    "sqli": VulnKnowledge(
        name="SQL Injection",
        category="sqli",
        description="SQL 注入攻击，攻击者在查询中注入恶意 SQL 代码",
        severity="CRITICAL",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cve_ids=["CVE-2023-23397", "CVE-2022-44877"],
        cwe_ids=["CWE-89"],
        fix_guide="""
1. 使用参数化查询（Prepared Statements）
2. 使用 ORM 框架
3. 输入验证和白名单
4. 最小权限数据库账户
5. 禁用危险的数据库功能
        """.strip(),
        references=[
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
        prevention=[
            "使用参数化查询",
            "存储过程",
            "输入验证",
            "最小权限原则",
        ],
        detection_patterns=[
            "' OR '1'='1",
            "UNION SELECT",
            "SLEEP(",
            "sql syntax",
        ],
    ),
    
    "csrf": VulnKnowledge(
        name="Cross-Site Request Forgery (CSRF)",
        category="csrf",
        description="跨站请求伪造，诱导用户在已认证的网站上执行非预期操作",
        severity="MEDIUM",
        cvss_score=6.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        cwe_ids=["CWE-352"],
        fix_guide="""
1. 使用 CSRF Token
2. 验证 Referer/Origin 头
3. 使用 SameSite Cookie 属性
4. 对敏感操作使用二次验证
        """.strip(),
        references=[
            "https://owasp.org/www-community/attacks/csrf",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
        prevention=[
            "CSRF Token",
            "SameSite Cookies",
            "Referer 验证",
            "自定义请求头",
        ],
        detection_patterns=[
            "missing csrf",
            "no token",
        ],
    ),
    
    "info_disclosure": VulnKnowledge(
        name="Information Disclosure",
        category="info",
        description="敏感信息泄露，包括 API 密钥、密码、配置文件等",
        severity="HIGH",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cwe_ids=["CWE-200", "CWE-538"],
        fix_guide="""
1. 从代码中移除敏感信息
2. 使用环境变量或密钥管理服务
3. 限制敏感文件的访问权限
4. 定期轮换密钥和凭证
5. 使用 .gitignore 防止敏感文件提交
        """.strip(),
        references=[
            "https://owasp.org/www-community/vulnerabilities/Information_Disclosure",
        ],
        prevention=[
            "密钥管理服务",
            "环境变量",
            "访问控制",
            "代码审查",
        ],
        detection_patterns=[
            "AKIA",
            "private key",
            "password=",
            "api_key",
        ],
    ),
    
    "dir_traversal": VulnKnowledge(
        name="Directory Traversal",
        category="traversal",
        description="目录遍历攻击，访问服务器上的受限文件",
        severity="HIGH",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cwe_ids=["CWE-22"],
        fix_guide="""
1. 验证和规范化输入路径
2. 使用白名单限制访问路径
3. 禁止 ../ 等遍历字符
4. 使用 chroot 或容器隔离
5. 最小权限运行应用
        """.strip(),
        references=[
            "https://owasp.org/www-community/attacks/Path_Traversal",
        ],
        prevention=[
            "输入验证",
            "路径规范化",
            "白名单",
            "沙箱隔离",
        ],
        detection_patterns=[
            "../",
            "..%2f",
            "/etc/passwd",
            "win.ini",
        ],
    ),
}


class KnowledgeBase:
    """漏洞知识库管理器"""
    
    def __init__(self):
        self.kb = VULNERABILITY_KB
    
    def get(self, category: str) -> Optional[VulnKnowledge]:
        """获取漏洞知识"""
        return self.kb.get(category)
    
    def search(self, keyword: str) -> List[VulnKnowledge]:
        """搜索漏洞知识"""
        results = []
        keyword_lower = keyword.lower()
        
        for knowledge in self.kb.values():
            if (keyword_lower in knowledge.name.lower() or
                keyword_lower in knowledge.description.lower() or
                keyword_lower in knowledge.category.lower()):
                results.append(knowledge)
        
        return results
    
    def get_by_cve(self, cve_id: str) -> Optional[VulnKnowledge]:
        """通过 CVE ID 查找"""
        for knowledge in self.kb.values():
            if cve_id.upper() in [c.upper() for c in knowledge.cve_ids]:
                return knowledge
        return None
    
    def get_by_cwe(self, cwe_id: str) -> Optional[VulnKnowledge]:
        """通过 CWE ID 查找"""
        for knowledge in self.kb.values():
            if cwe_id.upper() in [c.upper() for c in knowledge.cwe_ids]:
                return knowledge
        return None
    
    def list_all(self) -> List[str]:
        """列出所有漏洞类型"""
        return list(self.kb.keys())
    
    def get_fix_guide(self, category: str) -> str:
        """获取修复指南"""
        knowledge = self.kb.get(category)
        return knowledge.fix_guide if knowledge else "暂无修复指南"
    
    def get_prevention(self, category: str) -> List[str]:
        """获取预防措施"""
        knowledge = self.kb.get(category)
        return knowledge.prevention if knowledge else []
    
    def enrich_vulnerability(self, vuln: Dict, category: str) -> Dict:
        """为漏洞信息添加知识库数据"""
        knowledge = self.kb.get(category)
        if not knowledge:
            return vuln
        
        enriched = vuln.copy()
        enriched["knowledge_base"] = {
            "category": knowledge.category,
            "cvss_score": knowledge.cvss_score,
            "cvss_vector": knowledge.cvss_vector,
            "cve_ids": knowledge.cve_ids,
            "cwe_ids": knowledge.cwe_ids,
            "fix_guide": knowledge.fix_guide,
            "references": knowledge.references,
            "prevention": knowledge.prevention,
        }
        return enriched


# 全局知识库实例
kb = KnowledgeBase()
