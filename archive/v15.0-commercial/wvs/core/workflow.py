"""漏洞修复工作流 - 状态管理和跟踪"""
from enum import Enum
from typing import Dict, List, Optional
from datetime import datetime
from dataclasses import dataclass, field

from .database import db


class VulnStatus(Enum):
    """漏洞状态"""
    NEW = "new"              # 新发现
    CONFIRMED = "confirmed"  # 已确认
    ASSIGNED = "assigned"    # 已分配
    IN_PROGRESS = "in_progress"  # 修复中
    PENDING_VERIFY = "pending_verify"  # 待验证
    FIXED = "fixed"          # 已修复
    FALSE_POSITIVE = "false_positive"  # 误报
    RISK_ACCEPTED = "risk_accepted"    # 风险接受


class VulnPriority(Enum):
    """漏洞优先级"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


@dataclass
class VulnerabilityTicket:
    """漏洞工单"""
    ticket_id: str
    scan_id: str
    vuln_name: str
    vuln_url: str
    severity: str
    status: str = "new"
    priority: str = "medium"
    assigned_to: str = ""
    reporter: str = ""
    description: str = ""
    remediation: str = ""
    notes: str = ""
    created_at: str = ""
    updated_at: str = ""
    due_date: str = ""
    verified_by: str = ""
    verified_at: str = ""
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        if not self.updated_at:
            self.updated_at = self.created_at
    
    def to_dict(self) -> Dict:
        return {
            "ticket_id": self.ticket_id,
            "scan_id": self.scan_id,
            "vuln_name": self.vuln_name,
            "vuln_url": self.vuln_url,
            "severity": self.severity,
            "status": self.status,
            "priority": self.priority,
            "assigned_to": self.assigned_to,
            "reporter": self.reporter,
            "description": self.description,
            "remediation": self.remediation,
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "due_date": self.due_date,
            "verified_by": self.verified_by,
            "verified_at": self.verified_at,
        }


class RemediationWorkflow:
    """修复工作流管理"""
    
    # 状态流转规则
    TRANSITIONS = {
        "new": ["confirmed", "false_positive"],
        "confirmed": ["assigned", "risk_accepted"],
        "assigned": ["in_progress"],
        "in_progress": ["pending_verify", "assigned"],
        "pending_verify": ["fixed", "in_progress"],
        "fixed": [],
        "false_positive": ["new"],
        "risk_accepted": [],
    }
    
    def __init__(self):
        self.tickets: Dict[str, VulnerabilityTicket] = {}
    
    def create_ticket(self, scan_id: str, vuln: Dict, reporter: str = "") -> VulnerabilityTicket:
        """从漏洞创建工单"""
        import uuid
        
        ticket_id = f"VULN-{uuid.uuid4().hex[:8].upper()}"
        
        # 根据严重等级设置优先级
        severity = vuln.get("severity", "MEDIUM")
        priority_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
        }
        priority = priority_map.get(severity, "medium")
        
        # 计算截止日期（严重漏洞3天，高危7天，中危30天，低危90天）
        due_days = {"CRITICAL": 3, "HIGH": 7, "MEDIUM": 30, "LOW": 90}.get(severity, 30)
        due_date = (datetime.now() + __import__('datetime').timedelta(days=due_days)).isoformat()
        
        ticket = VulnerabilityTicket(
            ticket_id=ticket_id,
            scan_id=scan_id,
            vuln_name=vuln.get("name", "Unknown"),
            vuln_url=vuln.get("url", ""),
            severity=severity,
            priority=priority,
            reporter=reporter,
            description=vuln.get("description", ""),
            remediation=vuln.get("remediation", ""),
            due_date=due_date,
        )
        
        self.tickets[ticket_id] = ticket
        self._save_ticket(ticket)
        
        return ticket
    
    def transition(self, ticket_id: str, new_status: str, user: str = "", notes: str = "") -> bool:
        """状态流转"""
        ticket = self.tickets.get(ticket_id)
        if not ticket:
            # 从数据库加载
            ticket = self._load_ticket(ticket_id)
            if not ticket:
                return False
            self.tickets[ticket_id] = ticket
        
        current = ticket.status
        if new_status not in self.TRANSITIONS.get(current, []):
            raise ValueError(f"无效的状态流转: {current} -> {new_status}")
        
        ticket.status = new_status
        ticket.updated_at = datetime.now().isoformat()
        
        if notes:
            ticket.notes += f"\n[{datetime.now().isoformat()}] {user}: {notes}"
        
        # 验证完成
        if new_status == "fixed":
            ticket.verified_by = user
            ticket.verified_at = datetime.now().isoformat()
        
        self._save_ticket(ticket)
        return True
    
    def assign(self, ticket_id: str, assignee: str, user: str = ""):
        """分配工单"""
        ticket = self.tickets.get(ticket_id)
        if not ticket:
            return False
        
        ticket.assigned_to = assignee
        ticket.updated_at = datetime.now().isoformat()
        
        # 自动流转到已分配状态
        if ticket.status == "confirmed":
            ticket.status = "assigned"
        
        self._save_ticket(ticket)
        return True
    
    def get_ticket(self, ticket_id: str) -> Optional[VulnerabilityTicket]:
        """获取工单"""
        if ticket_id in self.tickets:
            return self.tickets[ticket_id]
        return self._load_ticket(ticket_id)
    
    def list_tickets(self, status: str = None, assignee: str = None) -> List[VulnerabilityTicket]:
        """列岀工单"""
        # 从数据库查询
        query = "SELECT * FROM remediation WHERE 1=1"
        params = []
        
        if status:
            query += " AND status = ?"
            params.append(status)
        if assignee:
            query += " AND assigned_to = ?"
            params.append(assignee)
        
        query += " ORDER BY created_at DESC"
        
        import sqlite3
        with sqlite3.connect(db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            tickets = []
            for row in rows:
                data = dict(row)
                ticket = VulnerabilityTicket(**data)
                tickets.append(ticket)
                self.tickets[ticket.ticket_id] = ticket
            
            return tickets
    
    def get_statistics(self) -> Dict:
        """获取工单统计"""
        import sqlite3
        with sqlite3.connect(db.db_path) as conn:
            cursor = conn.cursor()
            
            # 各状态数量
            cursor.execute("""
                SELECT status, COUNT(*) FROM remediation GROUP BY status
            """)
            status_counts = dict(cursor.fetchall())
            
            # 各严重等级数量
            cursor.execute("""
                SELECT severity, COUNT(*) FROM remediation GROUP BY severity
            """)
            severity_counts = dict(cursor.fetchall())
            
            # 逾期工单
            cursor.execute("""
                SELECT COUNT(*) FROM remediation 
                WHERE due_date < ? AND status NOT IN ('fixed', 'false_positive', 'risk_accepted')
            """, (datetime.now().isoformat(),))
            overdue = cursor.fetchone()[0]
            
            # 今日到期
            today = datetime.now().date().isoformat()
            cursor.execute("""
                SELECT COUNT(*) FROM remediation 
                WHERE date(due_date) = ? AND status NOT IN ('fixed', 'false_positive', 'risk_accepted')
            """, (today,))
            due_today = cursor.fetchone()[0]
            
            return {
                "status_counts": status_counts,
                "severity_counts": severity_counts,
                "overdue": overdue,
                "due_today": due_today,
                "total": sum(status_counts.values()),
            }
    
    def _save_ticket(self, ticket: VulnerabilityTicket):
        """保存工单到数据库"""
        import sqlite3
        with sqlite3.connect(db.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO remediation 
                (id, scan_id, vuln_name, vuln_url, severity, status, priority,
                 assigned_to, reporter, description, remediation, notes,
                 created_at, updated_at, due_date, verified_by, verified_at)
                VALUES (
                    (SELECT id FROM remediation WHERE ticket_id = ?),
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            """, (
                ticket.ticket_id, ticket.scan_id, ticket.vuln_name, ticket.vuln_url,
                ticket.severity, ticket.status, ticket.priority,
                ticket.assigned_to, ticket.reporter, ticket.description,
                ticket.remediation, ticket.notes, ticket.created_at,
                ticket.updated_at, ticket.due_date, ticket.verified_by,
                ticket.verified_at,
            ))
            conn.commit()
    
    def _load_ticket(self, ticket_id: str) -> Optional[VulnerabilityTicket]:
        """从数据库加载工单"""
        import sqlite3
        with sqlite3.connect(db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM remediation WHERE ticket_id = ?", (ticket_id,))
            row = cursor.fetchone()
            
            if row:
                return VulnerabilityTicket(**dict(row))
            return None


# 全局工作流实例
workflow = RemediationWorkflow()
