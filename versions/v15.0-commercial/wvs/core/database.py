"""数据库模块 - 扫描历史持久化"""
import sqlite3
import json
from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass


@dataclass
class ScanRecord:
    """扫描记录"""
    scan_id: str
    target: str
    timestamp: str
    duration: float
    vulnerability_count: int
    vulnerabilities: str  # JSON
    profile: str
    status: str


class Database:
    """SQLite 数据库管理"""
    
    def __init__(self, db_path: str = "wvs.db"):
        self.db_path = Path(db_path)
        self._init_db()
    
    def _init_db(self):
        """初始化数据库"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # 扫描记录表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    duration REAL,
                    vulnerability_count INTEGER DEFAULT 0,
                    vulnerabilities TEXT,
                    profile TEXT DEFAULT 'standard',
                    status TEXT DEFAULT 'completed'
                )
            """)
            
            # 漏洞修复跟踪表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS remediation (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    vuln_name TEXT,
                    vuln_url TEXT,
                    severity TEXT,
                    status TEXT DEFAULT 'open',
                    assigned_to TEXT,
                    notes TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                )
            """)
            
            # 扫描统计表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date DATE UNIQUE,
                    scan_count INTEGER DEFAULT 0,
                    vuln_found INTEGER DEFAULT 0,
                    vuln_fixed INTEGER DEFAULT 0
                )
            """)
            
            conn.commit()
    
    def save_scan(self, scan_id: str, target: str, duration: float,
                  vulnerabilities: List[Dict], profile: str = "standard"):
        """保存扫描记录"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO scans 
                (scan_id, target, timestamp, duration, vulnerability_count, vulnerabilities, profile, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                target,
                datetime.now().isoformat(),
                duration,
                len(vulnerabilities),
                json.dumps(vulnerabilities, ensure_ascii=False),
                profile,
                "completed"
            ))
            conn.commit()
        
        # 更新统计
        self._update_statistics(len(vulnerabilities))
    
    def get_scan(self, scan_id: str) -> Optional[Dict]:
        """获取扫描记录"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
            row = cursor.fetchone()
            
            if row:
                return dict(row)
            return None
    
    def list_scans(self, limit: int = 100, offset: int = 0) -> List[Dict]:
        """列出扫描记录"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM scans 
                ORDER BY timestamp DESC 
                LIMIT ? OFFSET ?
            """, (limit, offset))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_scan_count(self) -> int:
        """获取扫描总数"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM scans")
            return cursor.fetchone()[0]
    
    def get_vulnerability_count(self) -> int:
        """获取漏洞总数"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT SUM(vulnerability_count) FROM scans")
            result = cursor.fetchone()[0]
            return result or 0
    
    def get_severity_distribution(self) -> Dict[str, int]:
        """获取严重等级分布"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT vulnerabilities FROM scans")
            
            distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            
            for row in cursor.fetchall():
                try:
                    vulns = json.loads(row[0])
                    for vuln in vulns:
                        sev = vuln.get("severity", "UNKNOWN")
                        if sev in distribution:
                            distribution[sev] += 1
                except:
                    pass
            
            return distribution
    
    def add_remediation(self, scan_id: str, vuln_name: str, vuln_url: str,
                       severity: str, assigned_to: str = None):
        """添加修复记录"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO remediation 
                (scan_id, vuln_name, vuln_url, severity, assigned_to)
                VALUES (?, ?, ?, ?, ?)
            """, (scan_id, vuln_name, vuln_url, severity, assigned_to))
            conn.commit()
    
    def update_remediation_status(self, remediation_id: int, status: str, notes: str = None):
        """更新修复状态"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE remediation 
                SET status = ?, notes = ?, updated_at = ?
                WHERE id = ?
            """, (status, notes, datetime.now().isoformat(), remediation_id))
            conn.commit()
    
    def get_remediations(self, status: str = None) -> List[Dict]:
        """获取修复记录"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            if status:
                cursor.execute("""
                    SELECT * FROM remediation WHERE status = ? ORDER BY created_at DESC
                """, (status,))
            else:
                cursor.execute("SELECT * FROM remediation ORDER BY created_at DESC")
            
            return [dict(row) for row in cursor.fetchall()]
    
    def _update_statistics(self, vuln_count: int):
        """更新统计"""
        today = datetime.now().date().isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # 检查今天是否已有记录
            cursor.execute("SELECT * FROM statistics WHERE date = ?", (today,))
            row = cursor.fetchone()
            
            if row:
                cursor.execute("""
                    UPDATE statistics 
                    SET scan_count = scan_count + 1, vuln_found = vuln_found + ?
                    WHERE date = ?
                """, (vuln_count, today))
            else:
                cursor.execute("""
                    INSERT INTO statistics (date, scan_count, vuln_found)
                    VALUES (?, 1, ?)
                """, (today, vuln_count))
            
            conn.commit()
    
    def get_statistics(self, days: int = 30) -> Dict:
        """获取统计数据"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # 总扫描数
            cursor.execute("SELECT COUNT(*), SUM(vulnerability_count) FROM scans")
            total_scans, total_vulns = cursor.fetchone()
            
            # 最近 N 天统计
            cursor.execute("""
                SELECT date, scan_count, vuln_found 
                FROM statistics 
                ORDER BY date DESC 
                LIMIT ?
            """, (days,))
            daily_stats = cursor.fetchall()
            
            return {
                "total_scans": total_scans or 0,
                "total_vulnerabilities": total_vulns or 0,
                "average_vulns_per_scan": (total_vulns / total_scans) if total_scans else 0,
                "severity_distribution": self.get_severity_distribution(),
                "daily_stats": [
                    {"date": row[0], "scans": row[1], "vulns": row[2]}
                    for row in daily_stats
                ]
            }
    
    def delete_scan(self, scan_id: str):
        """删除扫描记录"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM remediation WHERE scan_id = ?", (scan_id,))
            cursor.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            conn.commit()


# 全局数据库实例
db = Database()
