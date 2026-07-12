"""
Nuclei Template Manager — 12.5w+ PoC 模板管理与智能加载

功能:
1. 发现并索引本地 Nuclei 模板
2. 按技术栈/CVE/严重程度分类
3. 按目标特征智能选择模板
4. 支持多来源 PoC 管理（Nuclei / xray / beebeeto / bugscan）
5. SQLite 索引缓存加速
"""

import json
import logging
import os
import re
import sqlite3
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from datetime import datetime

logger = logging.getLogger("wvs.nuclei_template_manager")

# ── 默认模板搜索路径 ──────────────────────────────────────────
DEFAULT_TEMPLATE_DIRS = [
    "~/.rayscan/nuclei-templates",
    "~/.nuclei/templates",
    os.path.expandvars("%LOCALAPPDATA%\\nuclei\\templates") if os.name == "nt" else None,
    "/opt/nuclei-templates",
    "/usr/share/nuclei-templates",
]

# ── PoC 来源分类 ───────────────────────────────────────────────
POC_SOURCES = {
    "nuclei": {"dir": "nuclei-templates", "ext": ".yaml", "desc": "Nuclei YAML 模板"},
    "xray": {"dir": "xray-pocs", "ext": ".yaml", "desc": "xRay POC 规则"},
    "beebeeto": {"dir": "beebeeto-pocs", "ext": ".py", "desc": "Beebeeto PoC"},
    "bugscan": {"dir": "bugscan-pocs", "ext": ".php", "desc": "BugScan PoC"},
}

# ── 严重程度映射 ──────────────────────────────────────────────
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

# ── 技术栈指纹 → Nuclei 标签映射 ──────────────────────────────
TECH_STACK_TAGS = {
    "thinkphp": ["thinkphp", "thinkphp-rce", "thinkphp-sqli"],
    "laravel": ["laravel"],
    "wordpress": ["wordpress", "wp-plugin", "wp-theme"],
    "joomla": ["joomla"],
    "drupal": ["drupal"],
    "apache": ["apache", "apache-httpd"],
    "nginx": ["nginx"],
    "tomcat": ["tomcat", "apache-tomcat"],
    "jboss": ["jboss", "jbossas"],
    "weblogic": ["weblogic", "oracle-weblogic"],
    "websphere": ["websphere", "ibm-websphere"],
    "spring": ["spring", "springboot", "spring-cloud", "spring-framework"],
    "struts2": ["struts", "struts2", "apache-struts"],
    "shiro": ["shiro", "apache-shiro"],
    "fastjson": ["fastjson", "alibaba-fastjson"],
    "jackson": ["jackson", "fasterxml-jackson"],
    "log4j": ["log4j", "log4shell", "apache-log4j"],
    "jenkins": ["jenkins"],
    "docker": ["docker"],
    "kubernetes": ["kubernetes", "k8s"],
    "nacos": ["nacos"],
    "redis": ["redis"],
    "mysql": ["mysql"],
    "mssql": ["mssql", "sqlserver", "microsoft-sql"],
    "oracle": ["oracle-db"],
    "mongodb": ["mongodb"],
    "phpmyadmin": ["phpmyadmin"],
    "grafana": ["grafana"],
    "prometheus": ["prometheus"],
    "swagger": ["swagger", "swagger-api"],
    "graphql": ["graphql"],
    "weaver": ["weaver", "ecology", "泛微", "e-cology", "e-office"],
    "tongda": ["tongda", "通达", "tongda-oa"],
    "kingdee": ["kingdee", "金蝶"],
    "landray": ["landray", "蓝凌"],
    "coremail": ["coremail"],
    "seeyon": ["seeyon", "致远"],
    "yonyou": ["yonyou", "用友"],
    "feishu": ["feishu", "飞书"],
    "dingtalk": ["dingtalk", "钉钉"],
    "zabbix": ["zabbix"],
    "gitlab": ["gitlab"],
    "jira": ["jira", "atlassian-jira"],
    "confluence": ["confluence", "atlassian-confluence"],
    "smtp": ["smtp", "mail", "email"],
    "ftp": ["ftp", "vsftpd", "proftpd"],
    "ssh": ["ssh", "openssh"],
    "rdp": ["rdp", "windows-rdp"],
    "samba": ["samba"],
    "elasticsearch": ["elasticsearch", "elastic"],
    "kibana": ["kibana"],
    "hadoop": ["hadoop"],
    "activemq": ["activemq"],
    "rabbitmq": ["rabbitmq"],
}

# ── OA 系统指纹特征 ──────────────────────────────────────────
OA_FINGERPRINTS = {
    "泛微": {"paths": ["/weaver/", "/ecology/", "/wui/"], "keywords": ["weaver", "ecology", "e-cology"]},
    "通达": {"paths": ["/ispirit/", "/mac/", "/general/"], "keywords": ["tongda", "通达OA", "/general/"]},
    "金蝶": {"paths": ["/kingdee/", "/k3cloud/"], "keywords": ["kingdee", "金蝶"]},
    "蓝凌": {"paths": ["/landray/", "/sys/"], "keywords": ["landray", "蓝凌"]},
    "致远": {"paths": ["/seeyon/", "/yyoa/"], "keywords": ["seeyon", "致远"]},
    "用友": {"paths": ["/yonyou/", "/ufida/"], "keywords": ["yonyou", "用友", "ufida"]},
    "禅道": {"paths": ["/zentao/", "/chanzhi/"], "keywords": ["zentao", "禅道"]},
    "万户": {"paths": ["/whir/", "/defaultroot/"], "keywords": ["whir", "万户"]},
}

# ── CVE 年份分类 ──────────────────────────────────────────────
CURRENT_YEAR = datetime.now().year


@dataclass
class TemplateInfo:
    """Nuclei 模板元数据"""
    path: str                          # 模板文件路径
    filename: str                      # 文件名
    template_id: str = ""              # template-id
    name: str = ""                     # info.name
    severity: str = "unknown"          # info.severity
    tags: List[str] = field(default_factory=list)  # info.tags
    cve_ids: List[str] = field(default_factory=list)  # 关联 CVE
    cwe_ids: List[str] = field(default_factory=list)  # 关联 CWE
    source: str = "nuclei"             # 来源 (nuclei/xray 等)
    tech_stack: List[str] = field(default_factory=list)  # 关联技术栈
    category: str = "other"            # 分类: cve/misconfig/tech/other
    description: str = ""              # 描述
    remediation: str = ""              # 修复建议
    reference: List[str] = field(default_factory=list)
    matched_at: str = ""               # 匹配路径

    @property
    def year(self) -> Optional[int]:
        """从 CVE ID 提取年份"""
        for cve in self.cve_ids:
            m = re.search(r"CVE-(\d{4})-\d+", cve, re.IGNORECASE)
            if m:
                return int(m.group(1))
        return None

    @property
    def severity_order(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 5)

    def matches_tech(self, tech: str) -> bool:
        """检查是否匹配指定技术栈"""
        tech_lower = tech.lower()
        # 检查 tags 中是否包含技术栈标签
        tags_lower = [t.lower() for t in self.tags]
        mapped_tags = TECH_STACK_TAGS.get(tech_lower, [tech_lower])
        return any(t in tags_lower for t in mapped_tags)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "filename": self.filename,
            "template_id": self.template_id,
            "name": self.name,
            "severity": self.severity,
            "tags": self.tags,
            "cve_ids": self.cve_ids,
            "cwe_ids": self.cwe_ids,
            "source": self.source,
            "tech_stack": self.tech_stack,
            "category": self.category,
            "description": self.description[:200] if self.description else "",
            "year": self.year,
        }


class NucleiTemplateManager:
    """
    Nuclei 模板管理器

    核心功能:
    - 发现本地模板文件并建立索引
    - 按技术栈/CVE/标签分类
    - SQLite 缓存加速
    - 根据目标指纹智能选择模板
    """

    def __init__(self, template_dirs: Optional[List[str]] = None, cache_db: Optional[str] = None):
        self.template_dirs = template_dirs or self._resolve_default_dirs()
        self.cache_db = cache_db or str(Path.home() / ".rayscan" / "template_cache.db")
        self._templates: Dict[str, TemplateInfo] = {}  # path -> TemplateInfo
        self._index_loaded = False
        self._stats = {"total": 0, "by_severity": {}, "by_source": {}, "by_year": {}}

    @staticmethod
    def _resolve_default_dirs() -> List[str]:
        """解析默认模板搜索路径"""
        dirs = []
        for d in DEFAULT_TEMPLATE_DIRS:
            if d is None:
                continue
            expanded = os.path.expanduser(os.path.expandvars(d))
            if os.path.isdir(expanded):
                dirs.append(expanded)
        return dirs

    def add_template_dir(self, directory: str) -> None:
        """添加模板搜索目录"""
        expanded = os.path.expanduser(os.path.expandvars(directory))
        if os.path.isdir(expanded) and expanded not in self.template_dirs:
            self.template_dirs.append(expanded)
            logger.info(f"[TemplateManager] 添加模板目录: {expanded}")

    # ── 索引构建 ──────────────────────────────────────────────

    def build_index(self, force: bool = False) -> int:
        """
        扫描所有模板目录并建立索引

        Args:
            force: 是否强制重建（忽略缓存）

        Returns:
            索引的模板总数
        """
        if not force and self._try_load_cache():
            return len(self._templates)

        self._templates.clear()
        total = 0

        for source_name, source_cfg in POC_SOURCES.items():
            for tdir in self.template_dirs:
                source_dir = os.path.join(tdir, source_cfg["dir"])
                if os.path.isdir(source_dir):
                    count = self._index_directory(source_dir, source_name, source_cfg["ext"])
                    total += count
                    if count > 0:
                        logger.info(f"[TemplateManager] {source_name}: {count} 模板 (from {source_dir})")

        # 也扫描模板目录根目录下的 YAML 文件
        for tdir in self.template_dirs:
            if os.path.isdir(tdir):
                count = self._index_directory(tdir, "nuclei", ".yaml")
                total += count

        self._update_stats()
        self._save_cache()
        self._index_loaded = True
        logger.info(f"[TemplateManager] 索引完成: 共 {total} 个模板")
        return total

    def _index_directory(self, directory: str, source: str, ext: str) -> int:
        """索引单个目录中的模板文件"""
        count = 0
        try:
            for root, _dirs, files in os.walk(directory):
                for fname in files:
                    if not fname.endswith(ext):
                        continue
                    fpath = os.path.join(root, fname)
                    if fpath in self._templates:
                        continue
                    info = self._parse_template(fpath, source)
                    if info:
                        self._templates[fpath] = info
                        count += 1
        except Exception as e:
            logger.warning(f"[TemplateManager] 索引目录失败 {directory}: {e}")
        return count

    def _parse_template(self, fpath: str, source: str) -> Optional[TemplateInfo]:
        """解析单个模板文件，提取元数据"""
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(4096)  # 只读前 4KB 足够解析头部

            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                return None

            info_data = data.get("info", {})
            if not isinstance(info_data, dict):
                return None

            # 提取基本信息
            template_id = data.get("id", "")
            name = info_data.get("name", "") or info_data.get("title", "")
            severity = info_data.get("severity", "unknown")
            tags_raw = info_data.get("tags", [])
            if isinstance(tags_raw, str):
                tags_raw = tags_raw.split(",")
            elif not isinstance(tags_raw, list):
                tags_raw = []
            tags = [t.strip() for t in tags_raw if t.strip()]

            # 提取 CVE/CWE
            classification = info_data.get("classification", {}) or {}
            cve_ids = []
            cwe_ids = []

            cve_raw = classification.get("cve-id", "")
            if isinstance(cve_raw, list):
                cve_ids = cve_raw
            elif isinstance(cve_raw, str) and cve_raw.strip():
                cve_ids = [cve_raw.strip()]

            cwe_raw = classification.get("cwe-id", "")
            if isinstance(cwe_raw, list):
                cwe_ids = cwe_raw
            elif isinstance(cwe_raw, str) and cwe_raw.strip():
                cwe_ids = [cwe_raw.strip()]

            description = info_data.get("description", "")
            remediation = info_data.get("remediation", "")
            references = info_data.get("reference", [])
            if isinstance(references, str):
                references = [references]

            # 识别技术栈
            tech_stack = self._detect_tech_stack(tags, name, fpath)

            # 分类
            category = self._classify_template(cve_ids, tags, severity)

            return TemplateInfo(
                path=fpath,
                filename=os.path.basename(fpath),
                template_id=template_id,
                name=name,
                severity=severity,
                tags=tags,
                cve_ids=cve_ids,
                cwe_ids=cwe_ids,
                source=source,
                tech_stack=tech_stack,
                category=category,
                description=description,
                remediation=remediation,
                reference=references,
            )
        except Exception as e:
            logger.debug(f"[TemplateManager] 解析模板失败 {fpath}: {e}")
            return None

    @staticmethod
    def _detect_tech_stack(tags: List[str], name: str, fpath: str) -> List[str]:
        """从 tags 和路径中识别技术栈"""
        techs = set()
        combined = " ".join(tags).lower() + " " + name.lower() + " " + fpath.lower()

        for tech, aliases in TECH_STACK_TAGS.items():
            for alias in aliases:
                if alias.lower() in combined:
                    techs.add(tech)
                    break
        return list(techs)

    @staticmethod
    def _classify_template(cve_ids: List[str], tags: List[str], severity: str) -> str:
        """对模板进行分类"""
        if cve_ids:
            return "cve"
        tags_lower = [t.lower() for t in tags]
        if any(t in tags_lower for t in ["misconfig", "misconfiguration", "exposure"]):
            return "misconfig"
        if any(t in tags_lower for t in ["tech", "fingerprint", "osint", "waf"]):
            return "tech"
        if severity in ("critical", "high"):
            return "cve"
        return "other"

    def _update_stats(self) -> None:
        """更新统计信息"""
        by_severity: Dict[str, int] = {}
        by_source: Dict[str, int] = {}
        by_year: Dict[str, int] = {}

        for info in self._templates.values():
            by_severity[info.severity] = by_severity.get(info.severity, 0) + 1
            by_source[info.source] = by_source.get(info.source, 0) + 1
            y = info.year
            year_key = str(y) if y else "unknown"
            by_year[year_key] = by_year.get(year_key, 0) + 1

        self._stats = {
            "total": len(self._templates),
            "by_severity": by_severity,
            "by_source": by_source,
            "by_year": by_year,
        }

    # ── 缓存管理 ──────────────────────────────────────────────

    def _save_cache(self) -> None:
        """将模板索引保存到 SQLite 缓存"""
        try:
            cache_dir = os.path.dirname(self.cache_db)
            os.makedirs(cache_dir, exist_ok=True)

            conn = sqlite3.connect(self.cache_db)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS templates (
                    path TEXT PRIMARY KEY,
                    filename TEXT,
                    template_id TEXT,
                    name TEXT,
                    severity TEXT,
                    tags TEXT,
                    cve_ids TEXT,
                    cwe_ids TEXT,
                    source TEXT,
                    tech_stack TEXT,
                    category TEXT,
                    description TEXT,
                    remediation TEXT,
                    updated_at TEXT
                )
            """)
            conn.execute("DELETE FROM templates")

            now = datetime.now().isoformat()
            for info in self._templates.values():
                conn.execute(
                    """INSERT OR REPLACE INTO templates
                    (path, filename, template_id, name, severity, tags, cve_ids, cwe_ids,
                     source, tech_stack, category, description, remediation, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        info.path,
                        info.filename,
                        info.template_id,
                        info.name,
                        info.severity,
                        ",".join(info.tags),
                        ",".join(info.cve_ids),
                        ",".join(info.cwe_ids),
                        info.source,
                        ",".join(info.tech_stack),
                        info.category,
                        info.description[:500],
                        info.remediation[:500],
                        now,
                    ),
                )

            conn.execute(
                """CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY, value TEXT
                )"""
            )
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                ("last_updated", now),
            )
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                ("total_templates", str(len(self._templates))),
            )
            conn.commit()
            conn.close()
            logger.info(f"[TemplateManager] 缓存已保存: {len(self._templates)} 条记录 -> {self.cache_db}")
        except Exception as e:
            logger.warning(f"[TemplateManager] 缓存保存失败: {e}")

    def _try_load_cache(self) -> bool:
        """尝试从 SQLite 加载缓存索引"""
        if not os.path.exists(self.cache_db):
            return False

        try:
            conn = sqlite3.connect(self.cache_db)
            cursor = conn.execute("SELECT COUNT(*) FROM templates")
            count = cursor.fetchone()[0]
            if count == 0:
                conn.close()
                return False

            self._templates.clear()
            cursor = conn.execute("SELECT * FROM templates")
            columns = [desc[0] for desc in cursor.description]

            for row in cursor.fetchall():
                data = dict(zip(columns, row))
                info = TemplateInfo(
                    path=data["path"],
                    filename=data["filename"],
                    template_id=data["template_id"] or "",
                    name=data["name"] or "",
                    severity=data["severity"] or "unknown",
                    tags=data["tags"].split(",") if data["tags"] else [],
                    cve_ids=data["cve_ids"].split(",") if data["cve_ids"] else [],
                    cwe_ids=data["cwe_ids"].split(",") if data["cwe_ids"] else [],
                    source=data["source"] or "nuclei",
                    tech_stack=data["tech_stack"].split(",") if data["tech_stack"] else [],
                    category=data["category"] or "other",
                    description=data["description"] or "",
                    remediation=data["remediation"] or "",
                )
                self._templates[info.path] = info

            conn.close()
            self._update_stats()
            self._index_loaded = True
            logger.info(f"[TemplateManager] 缓存加载: {count} 个模板")
            return True
        except Exception as e:
            logger.warning(f"[TemplateManager] 缓存加载失败: {e}")
            return False

    # ── 模板查询 ──────────────────────────────────────────────

    def get_templates_by_cve(self, cve_id: str) -> List[TemplateInfo]:
        """按 CVE ID 查询模板"""
        cve_upper = cve_id.upper()
        return [t for t in self._templates.values() if cve_upper in [c.upper() for c in t.cve_ids]]

    def get_templates_by_tech(self, tech: str) -> List[TemplateInfo]:
        """按技术栈查询模板"""
        tech_lower = tech.lower()
        return [t for t in self._templates.values() if tech_lower in [ts.lower() for ts in t.tech_stack]]

    def get_templates_by_severity(self, severity: str, min_count: int = 0) -> List[TemplateInfo]:
        """按严重程度查询模板"""
        sev = severity.lower()
        if min_count:
            sev_order = SEVERITY_ORDER.get(sev, 5)
            return [
                t for t in self._templates.values()
                if SEVERITY_ORDER.get(t.severity, 5) <= sev_order
            ]
        return [t for t in self._templates.values() if t.severity == sev]

    def get_templates_by_year(self, year: int) -> List[TemplateInfo]:
        """按年份查询模板"""
        return [t for t in self._templates.values() if t.year == year]

    def get_templates_by_tags(self, tags: List[str], match_all: bool = False) -> List[TemplateInfo]:
        """按标签查询模板"""
        tags_lower = [t.lower() for t in tags]
        results = []
        for t in self._templates.values():
            t_tags_lower = [tt.lower() for tt in t.tags]
            if match_all:
                if all(tag in t_tags_lower for tag in tags_lower):
                    results.append(t)
            else:
                if any(tag in t_tags_lower for tag in tags_lower):
                    results.append(t)
        return results

    def search_templates(self, keyword: str) -> List[TemplateInfo]:
        """搜索模板（按名称/描述/CVE）"""
        kw = keyword.lower()
        results = []
        for t in self._templates.values():
            if kw in t.name.lower() or kw in t.description.lower():
                results.append(t)
                continue
            for cve in t.cve_ids:
                if kw in cve.lower():
                    results.append(t)
                    break
        return results

    def get_templates_for_target(
        self,
        tech_stack: Optional[List[str]] = None,
        cve_hints: Optional[List[str]] = None,
        severities: Optional[List[str]] = None,
        max_templates: int = 500,
        recent_years_only: bool = True,
    ) -> List[str]:
        """
        根据目标特征智能选择最匹配的模板

        Args:
            tech_stack: 目标技术栈列表（如 ["thinkphp", "nginx"]）
            cve_hints: 要重点检测的 CVE
            severities: 要检测的严重程度（默认 critical+high+medium）
            max_templates: 最大模板数
            recent_years_only: 是否只选近5年 CVE

        Returns:
            选中的模板文件路径列表
        """
        candidates: Set[str] = set()
        tech_stack = tech_stack or []
        cve_hints = cve_hints or []
        severities = severities or ["critical", "high", "medium"]

        severity_set = set(s.lower() for s in severities)

        # 1. 按技术栈匹配（最高优先级）
        for tech in tech_stack:
            tech_templates = self.get_templates_by_tech(tech)
            for t in tech_templates:
                if t.severity in severity_set:
                    candidates.add(t.path)

        # 2. 按 CVE 匹配
        for cve in cve_hints:
            cve_templates = self.get_templates_by_cve(cve)
            for t in cve_templates:
                candidates.add(t.path)

        # 3. 按严重程度补充（针对 general 目标）
        if not tech_stack or len(candidates) < max_templates // 2:
            for sev in severities:
                sev_templates = self.get_templates_by_severity(sev)
                for t in sev_templates:
                    if len(candidates) >= max_templates:
                        break
                    # 优先选有 CVE 的
                    if t.category == "cve" and t.severity in severity_set:
                        candidates.add(t.path)

        # 4. 若候选仍不足，补充 recent misconfig 模板
        if len(candidates) < max_templates // 4:
            misconfigs = self.get_templates_by_tags(["misconfig", "exposure", "tech"])
            for t in misconfigs:
                if len(candidates) >= max_templates:
                    break
                candidates.add(t.path)

        # 5. 限制数量并按严重程度排序
        sorted_candidates = sorted(
            candidates,
            key=lambda p: self._templates[p].severity_order if p in self._templates else 99,
        )

        result = list(sorted_candidates[:max_templates])
        logger.info(
            f"[TemplateManager] 为目标选择 {len(result)} 个模板 "
            f"(tech_stack={tech_stack}, severities={severities})"
        )
        return result

    # ── 统计信息 ──────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """获取模板统计信息"""
        return {
            **self._stats,
            "template_dirs": self.template_dirs,
            "cache_db": self.cache_db,
            "index_loaded": self._index_loaded,
        }

    def print_summary(self) -> str:
        """打印模板索引摘要"""
        lines = []
        lines.append(f"📊 Nuclei 模板索引摘要")
        lines.append(f"{'='*50}")
        lines.append(f"  总数: {self._stats['total']}")
        lines.append(f"  按严重程度: {self._stats.get('by_severity', {})}")
        lines.append(f"  按来源: {self._stats.get('by_source', {})}")
        by_year = self._stats.get("by_year", {})
        if by_year:
            top_years = sorted(by_year.items(), key=lambda x: -x[1])[:5]
            lines.append(f"  最近5年: {dict(top_years)}")
        lines.append(f"  模板目录: {self.template_dirs}")
        return "\n".join(lines)

    @property
    def total(self) -> int:
        return len(self._templates)

    @property
    def is_ready(self) -> bool:
        return self._index_loaded and len(self._templates) > 0


# ── OA 指纹识别 ───────────────────────────────────────────────

def detect_oa_fingerprint(url: str, response_text: str) -> Optional[str]:
    """
    从 URL 和响应内容中识别 OA 系统类型

    Returns:
        OA 名称或 None
    """
    url_lower = url.lower()
    text_lower = response_text.lower()

    for oa_name, fingerprint in OA_FINGERPRINTS.items():
        # 路径匹配
        for path in fingerprint["paths"]:
            if path.lower() in url_lower:
                return oa_name
        # 关键词匹配
        for kw in fingerprint["keywords"]:
            if kw.lower() in text_lower or kw.lower() in url_lower:
                return oa_name
    return None


# ── 便捷工厂 ──────────────────────────────────────────────────

_default_manager: Optional[NucleiTemplateManager] = None


def get_template_manager(
    template_dirs: Optional[List[str]] = None,
    cache_db: Optional[str] = None,
) -> NucleiTemplateManager:
    """获取或创建全局模板管理器实例"""
    global _default_manager
    if _default_manager is None:
        _default_manager = NucleiTemplateManager(template_dirs, cache_db)
        # 尝试快速加载缓存，不阻塞
        if not _default_manager._try_load_cache():
            logger.info("[TemplateManager] 缓存未命中，将触发后台索引")
    return _default_manager
