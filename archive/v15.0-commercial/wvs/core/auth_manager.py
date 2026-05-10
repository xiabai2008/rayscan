"""用户管理和权限系统"""
from enum import Enum
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from datetime import datetime
import hashlib


class Role(Enum):
    """用户角色"""
    ADMIN = "admin"           # 管理员 - 全部权限
    SCANNER = "scanner"       # 扫描员 - 执行扫描
    REMEDIATOR = "remediator" # 修复员 - 处理漏洞
    VIEWER = "viewer"         # 查看者 - 只读


class Permission(Enum):
    """权限列表"""
    SCAN_CREATE = "scan:create"
    SCAN_DELETE = "scan:delete"
    SCAN_VIEW = "scan:view"
    VULN_MANAGE = "vuln:manage"
    VULN_VERIFY = "vuln:verify"
    TEMPLATE_MANAGE = "template:manage"
    USER_MANAGE = "user:manage"
    SYSTEM_CONFIG = "system:config"
    REPORT_EXPORT = "report:export"


# 角色权限映射
ROLE_PERMISSIONS = {
    Role.ADMIN: [
        Permission.SCAN_CREATE, Permission.SCAN_DELETE, Permission.SCAN_VIEW,
        Permission.VULN_MANAGE, Permission.VULN_VERIFY,
        Permission.TEMPLATE_MANAGE, Permission.USER_MANAGE,
        Permission.SYSTEM_CONFIG, Permission.REPORT_EXPORT,
    ],
    Role.SCANNER: [
        Permission.SCAN_CREATE, Permission.SCAN_VIEW,
        Permission.VULN_MANAGE, Permission.REPORT_EXPORT,
    ],
    Role.REMEDIATOR: [
        Permission.SCAN_VIEW, Permission.VULN_MANAGE, Permission.VULN_VERIFY,
        Permission.REPORT_EXPORT,
    ],
    Role.VIEWER: [
        Permission.SCAN_VIEW, Permission.REPORT_EXPORT,
    ],
}


@dataclass
class User:
    """用户"""
    user_id: str
    username: str
    email: str
    role: Role
    password_hash: str = ""
    created_at: str = ""
    last_login: str = ""
    is_active: bool = True
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
    
    def has_permission(self, permission: Permission) -> bool:
        """检查权限"""
        return permission in ROLE_PERMISSIONS.get(self.role, [])
    
    def to_dict(self) -> Dict:
        return {
            "user_id": self.user_id,
            "username": self.username,
            "email": self.email,
            "role": self.role.value,
            "created_at": self.created_at,
            "last_login": self.last_login,
            "is_active": self.is_active,
        }


class UserManager:
    """用户管理器"""
    
    def __init__(self):
        self.users: Dict[str, User] = {}
        self._current_user: Optional[User] = None
        self._load_users()
    
    def _load_users(self):
        """加载用户"""
        # 创建默认管理员
        admin = User(
            user_id="admin",
            username="admin",
            email="admin@wvs.local",
            role=Role.ADMIN,
            password_hash=self._hash_password("admin"),
        )
        self.users[admin.user_id] = admin
    
    def _hash_password(self, password: str) -> str:
        """密码哈希"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def authenticate(self, username: str, password: str) -> Optional[User]:
        """用户认证"""
        for user in self.users.values():
            if user.username == username:
                if user.password_hash == self._hash_password(password):
                    user.last_login = datetime.now().isoformat()
                    self._current_user = user
                    return user
        return None
    
    def create_user(self, username: str, email: str, password: str, 
                   role: Role = Role.VIEWER, created_by: str = "") -> User:
        """创建用户"""
        import uuid
        
        user_id = f"user_{uuid.uuid4().hex[:8]}"
        
        user = User(
            user_id=user_id,
            username=username,
            email=email,
            role=role,
            password_hash=self._hash_password(password),
        )
        
        self.users[user_id] = user
        return user
    
    def delete_user(self, user_id: str) -> bool:
        """删除用户"""
        if user_id in self.users and user_id != "admin":
            del self.users[user_id]
            return True
        return False
    
    def get_user(self, user_id: str) -> Optional[User]:
        """获取用户"""
        return self.users.get(user_id)
    
    def list_users(self) -> List[Dict]:
        """列出用户"""
        return [user.to_dict() for user in self.users.values()]
    
    def update_user_role(self, user_id: str, new_role: Role) -> bool:
        """更新用户角色"""
        user = self.users.get(user_id)
        if user:
            user.role = new_role
            return True
        return False
    
    def change_password(self, user_id: str, old_password: str, new_password: str) -> bool:
        """修改密码"""
        user = self.users.get(user_id)
        if not user:
            return False
        
        if user.password_hash != self._hash_password(old_password):
            return False
        
        user.password_hash = self._hash_password(new_password)
        return True
    
    def get_current_user(self) -> Optional[User]:
        """获取当前用户"""
        return self._current_user
    
    def check_permission(self, permission: Permission) -> bool:
        """检查当前用户权限"""
        if not self._current_user:
            return False
        return self._current_user.has_permission(permission)
    
    def require_permission(self, permission: Permission):
        """要求权限装饰器"""
        def decorator(func):
            def wrapper(*args, **kwargs):
                if not self.check_permission(permission):
                    raise PermissionError(f"需要权限: {permission.value}")
                return func(*args, **kwargs)
            return wrapper
        return decorator


# 全局用户管理器
user_manager = UserManager()
