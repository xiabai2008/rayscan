import uuid
import asyncio
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import desc

from core.database import ScanTask, ScanLog, Vulnerability, User
from core.redis import redis_client
from websocket.manager import websocket_manager
from schemas.scans import ScanTaskCreate, ScanTaskUpdate, ScanStatus
from core.config import settings

class ScanService:
    """扫描服务"""

    @staticmethod
    def generate_task_id() -> str:
        """生成任务ID"""
        return f"wvs_scan_{uuid.uuid4().hex[:8]}"

    def get_scan_tasks(
        self,
        db: Session,
        skip: int = 0,
        limit: int = 100,
        status: Optional[str] = None,
        user_id: Optional[int] = None
    ) -> List[ScanTask]:
        """获取扫描任务列表"""
        query = db.query(ScanTask)

        if status:
            query = query.filter(ScanTask.status == status)

        if user_id is not None:
            query = query.filter(ScanTask.user_id == user_id)

        query = query.order_by(desc(ScanTask.created_at))
        tasks = query.offset(skip).limit(limit).all()
        return tasks

    def get_scan_task_by_id(self, db: Session, task_id: int) -> Optional[ScanTask]:
        """通过ID获取扫描任务"""
        return db.query(ScanTask).filter(ScanTask.id == task_id).first()

    def get_scan_task_by_task_id(self, db: Session, task_uuid: str) -> Optional[ScanTask]:
        """通过任务UUID获取扫描任务"""
        return db.query(ScanTask).filter(ScanTask.task_id == task_uuid).first()

    def create_scan_task(self, db: Session, task_data: ScanTaskCreate, user_id: int) -> ScanTask:
        """创建扫描任务"""
        task_id = self.generate_task_id()

        db_task = ScanTask(
            task_id=task_id,
            name=task_data.name,
            description=task_data.description,
            target_url=str(task_data.target_url),
            scan_config=task_data.scan_config,
            status=ScanStatus.PENDING,
            progress=0.0,
            user_id=user_id
        )

        db.add(db_task)
        db.commit()
        db.refresh(db_task)

        # 记录日志
        self.add_scan_log(db, db_task.id, "info", f"扫描任务 '{task_data.name}' 已创建")

        # 发送WebSocket通知
        asyncio.create_task(websocket_manager.notify_scan_status(task_id, ScanStatus.PENDING))

        return db_task

    def update_scan_task(self, db: Session, task_id: int, task_update: ScanTaskUpdate) -> ScanTask:
        """更新扫描任务"""
        db_task = self.get_scan_task_by_id(db, task_id)
        if not db_task:
            return None

        update_data = task_update.dict(exclude_unset=True)

        for key, value in update_data.items():
            if hasattr(db_task, key) and value is not None:
                setattr(db_task, key, value)

        db.commit()
        db.refresh(db_task)

        # 记录日志
        self.add_scan_log(db, task_id, "info", f"扫描任务已更新: {update_data}")

        return db_task

    def delete_scan_task(self, db: Session, task_id: int):
        """删除扫描任务"""
        db_task = self.get_scan_task_by_id(db, task_id)
        if not db_task:
            return

        # 清理Redis数据
        asyncio.create_task(redis_client.clear_scan_data(db_task.task_id))

        db.delete(db_task)
        db.commit()

        # 记录日志
        self.add_scan_log(db, task_id, "info", "扫描任务已删除")

    async def start_scan_task(self, db: Session, task_id: int) -> bool:
        """启动扫描任务"""
        db_task = self.get_scan_task_by_id(db, task_id)
        if not db_task:
            return False

        if db_task.status not in [ScanStatus.PENDING, ScanStatus.PAUSED]:
            return False

        # 更新任务状态
        db_task.status = ScanStatus.RUNNING
        db_task.started_at = datetime.now()
        db_task.progress = 0.0
        db.commit()

        # 记录日志
        self.add_scan_log(db, task_id, "info", "扫描任务已启动")

        # 发送WebSocket通知
        await websocket_manager.notify_scan_status(db_task.task_id, ScanStatus.RUNNING)

        # 启动后台扫描任务
        asyncio.create_task(self.execute_scan(db_task))

        return True

    def pause_scan_task(self, db: Session, task_id: int) -> bool:
        """暂停扫描任务"""
        db_task = self.get_scan_task_by_id(db, task_id)
        if not db_task:
            return False

        if db_task.status != ScanStatus.RUNNING:
            return False

        db_task.status = ScanStatus.PAUSED
        db.commit()

        # 记录日志
        self.add_scan_log(db, task_id, "info", "扫描任务已暂停")

        # 发送WebSocket通知
        asyncio.create_task(websocket_manager.notify_scan_status(db_task.task_id, ScanStatus.PAUSED))

        return True

    def resume_scan_task(self, db: Session, task_id: int) -> bool:
        """恢复扫描任务"""
        db_task = self.get_scan_task_by_id(db, task_id)
        if not db_task:
            return False

        if db_task.status != ScanStatus.PAUSED:
            return False

        db_task.status = ScanStatus.RUNNING
        db.commit()

        # 记录日志
        self.add_scan_log(db, task_id, "info", "扫描任务已恢复")

        # 发送WebSocket通知
        asyncio.create_task(websocket_manager.notify_scan_status(db_task.task_id, ScanStatus.RUNNING))

        return True

    def stop_scan_task(self, db: Session, task_id: int) -> bool:
        """停止扫描任务"""
        db_task = self.get_scan_task_by_id(db, task_id)
        if not db_task:
            return False

        if db_task.status not in [ScanStatus.RUNNING, ScanStatus.PAUSED]:
            return False

        db_task.status = ScanStatus.CANCELLED
        db_task.completed_at = datetime.now()
        db.commit()

        # 记录日志
        self.add_scan_log(db, task_id, "info", "扫描任务已停止")

        # 发送WebSocket通知
        asyncio.create_task(websocket_manager.notify_scan_status(db_task.task_id, ScanStatus.CANCELLED))

        return True

    async def get_scan_progress(self, task_uuid: str) -> float:
        """获取扫描进度"""
        progress = await redis_client.get_scan_progress(task_uuid)
        return progress

    def get_scan_logs(
        self,
        db: Session,
        task_id: int,
        skip: int = 0,
        limit: int = 100,
        log_level: Optional[str] = None
    ) -> List[ScanLog]:
        """获取扫描日志"""
        query = db.query(ScanLog).filter(ScanLog.scan_task_id == task_id)

        if log_level:
            query = query.filter(ScanLog.log_level == log_level)

        query = query.order_by(desc(ScanLog.timestamp))
        logs = query.offset(skip).limit(limit).all()
        return logs

    def get_scan_statistics(self, db: Session, task_id: int) -> Dict[str, Any]:
        """获取扫描统计信息"""
        db_task = self.get_scan_task_by_id(db, task_id)
        if not db_task:
            return {}

        # 计算漏洞统计
        vulnerabilities = db.query(Vulnerability).filter(Vulnerability.scan_task_id == task_id).all()

        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }

        for vuln in vulnerabilities:
            if vuln.severity in severity_counts:
                severity_counts[vuln.severity] += 1

        # 计算扫描时长
        scan_duration = None
        if db_task.started_at and db_task.completed_at:
            scan_duration = (db_task.completed_at - db_task.started_at).total_seconds()

        statistics = {
            "task_id": db_task.task_id,
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities_by_severity": severity_counts,
            "scan_duration": scan_duration,
            "scan_status": db_task.status,
            "progress": db_task.progress,
            "started_at": db_task.started_at,
            "completed_at": db_task.completed_at
        }

        return statistics

    def add_scan_log(
        self,
        db: Session,
        task_id: int,
        log_level: str,
        message: str,
        details: Optional[Dict[str, Any]] = None
    ):
        """添加扫描日志"""
        if details is None:
            details = {}

        db_log = ScanLog(
            scan_task_id=task_id,
            log_level=log_level,
            message=message,
            details=details,
            timestamp=datetime.now()
        )

        db.add(db_log)
        db.commit()

    def add_vulnerability(
        self,
        db: Session,
        task_id: int,
        vulnerability_data: Dict[str, Any]
    ) -> Vulnerability:
        """添加漏洞"""
        db_vuln = Vulnerability(
            scan_task_id=task_id,
            vulnerability_id=vulnerability_data.get("id", f"vuln_{uuid.uuid4().hex[:8]}"),
            title=vulnerability_data.get("title", "未命名漏洞"),
            description=vulnerability_data.get("description", ""),
            severity=vulnerability_data.get("severity", "medium"),
            cvss_score=vulnerability_data.get("cvss_score"),
            cvss_vector=vulnerability_data.get("cvss_vector"),
            affected_url=vulnerability_data.get("affected_url"),
            parameter=vulnerability_data.get("parameter"),
            http_method=vulnerability_data.get("http_method"),
            request_data=vulnerability_data.get("request_data"),
            response_data=vulnerability_data.get("response_data"),
            evidence=vulnerability_data.get("evidence"),
            remediation=vulnerability_data.get("remediation"),
            references=vulnerability_data.get("references", []),
            status="new",
            discovered_at=datetime.now()
        )

        db.add(db_vuln)
        db.commit()
        db.refresh(db_vuln)

        return db_vuln

    async def execute_scan(self, task: ScanTask):
        """执行扫描任务"""
        try:
            # 这里应该调用实际的WVS扫描器
            # 暂时模拟扫描过程
            await self.simulate_scan(task)
        except Exception as e:
            # 记录错误
            db = SessionLocal()
            try:
                self.add_scan_log(db, task.id, "error", f"扫描执行失败: {str(e)}")
                task.status = ScanStatus.FAILED
                task.completed_at = datetime.now()
                db.commit()

                # 发送WebSocket通知
                await websocket_manager.notify_scan_status(task.task_id, ScanStatus.FAILED)
            finally:
                db.close()

    async def simulate_scan(self, task: ScanTask):
        """模拟扫描过程（实际项目中应替换为真正的WVS扫描器调用）"""
        db = SessionLocal()
        try:
            # 模拟扫描阶段
            stages = [
                ("目标识别", 10),
                ("爬虫爬取", 30),
                ("漏洞检测", 80),
                ("结果分析", 95),
                ("生成报告", 100)
            ]

            for stage_name, stage_progress in stages:
                # 更新当前阶段
                task.current_stage = stage_name
                db.commit()

                # 更新进度
                task.progress = stage_progress
                await redis_client.set_scan_progress(task.task_id, stage_progress)
                db.commit()

                # 发送WebSocket通知
                await websocket_manager.notify_scan_progress(task.task_id, stage_progress, stage_name)

                # 记录日志
                self.add_scan_log(db, task.id, "info", f"进入扫描阶段: {stage_name}")

                # 模拟阶段执行时间
                await asyncio.sleep(5)

                # 模拟发现漏洞
                if stage_name == "漏洞检测":
                    await self.simulate_vulnerability_discovery(db, task)

            # 扫描完成
            task.status = ScanStatus.COMPLETED
            task.progress = 100.0
            task.completed_at = datetime.now()

            # 生成模拟结果
            task.result_summary = {
                "total_pages": 150,
                "total_requests": 1200,
                "scan_duration": 45.5,
                "vulnerabilities_found": 8
            }

            # 更新漏洞计数
            vulnerabilities = db.query(Vulnerability).filter(Vulnerability.scan_task_id == task.id).all()
            task.vulnerabilities_found = len(vulnerabilities)

            # 按严重程度计数
            for vuln in vulnerabilities:
                if vuln.severity == "critical":
                    task.critical_count += 1
                elif vuln.severity == "high":
                    task.high_count += 1
                elif vuln.severity == "medium":
                    task.medium_count += 1
                elif vuln.severity == "low":
                    task.low_count += 1
                else:
                    task.info_count += 1

            db.commit()

            # 记录日志
            self.add_scan_log(db, task.id, "info", "扫描任务已完成")

            # 发送WebSocket通知
            await websocket_manager.notify_scan_status(task.task_id, ScanStatus.COMPLETED)

        except Exception as e:
            raise e
        finally:
            db.close()

    async def simulate_vulnerability_discovery(self, db: Session, task: ScanTask):
        """模拟漏洞发现"""
        vulnerabilities = [
            {
                "id": "sql_injection_1",
                "title": "SQL注入漏洞",
                "description": "在登录表单中发现SQL注入漏洞",
                "severity": "high",
                "cvss_score": 8.5,
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "affected_url": f"{task.target_url}/login",
                "parameter": "username",
                "http_method": "POST",
                "remediation": "使用参数化查询或预编译语句",
                "references": ["https://owasp.org/www-community/attacks/SQL_Injection"]
            },
            {
                "id": "xss_1",
                "title": "跨站脚本攻击漏洞",
                "description": "在搜索功能中发现反射型XSS漏洞",
                "severity": "medium",
                "cvss_score": 6.1,
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "affected_url": f"{task.target_url}/search",
                "parameter": "q",
                "http_method": "GET",
                "remediation": "对用户输入进行适当的编码和验证",
                "references": ["https://owasp.org/www-community/attacks/xss/"]
            }
        ]

        for vuln_data in vulnerabilities:
            # 添加到数据库
            vulnerability = self.add_vulnerability(db, task.id, vuln_data)

            # 添加到Redis
            await redis_client.add_scan_vulnerability(task.task_id, vuln_data)

            # 发送WebSocket通知
            await websocket_manager.notify_vulnerability_found(task.task_id, vuln_data)

            # 记录日志
            self.add_scan_log(db, task.id, "warning", f"发现漏洞: {vuln_data['title']}")

            # 模拟发现间隔
            await asyncio.sleep(1)

# 创建数据库会话本地实例（用于模拟扫描）
from core.database import SessionLocal