"""认证配置模块"""
from dataclasses import dataclass
from typing import Optional, Dict


@dataclass
class AuthConfig:
    """认证配置类"""
    auth_type: str = "none"  # none, cookie, bearer, basic, form
    
    # Cookie 认证
    cookie: Optional[str] = None
    
    # Token 认证 (Bearer/JWT)
    token: Optional[str] = None
    
    # Basic 认证
    username: Optional[str] = None
    password: Optional[str] = None
    
    # 表单认证
    login_url: Optional[str] = None
    form_data: Optional[Dict] = None
    
    def get_headers(self) -> Dict[str, str]:
        """获取认证请求头"""
        headers = {}
        
        if self.auth_type == "cookie" and self.cookie:
            headers["Cookie"] = self.cookie
        
        elif self.auth_type == "bearer" and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        
        elif self.auth_type == "basic" and self.username and self.password:
            import base64
            credentials = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            headers["Authorization"] = f"Basic {credentials}"
        
        return headers
    
    def is_authenticated(self) -> bool:
        """检查是否配置了认证"""
        if self.auth_type == "none":
            return False
        if self.auth_type == "cookie" and self.cookie:
            return True
        if self.auth_type == "bearer" and self.token:
            return True
        if self.auth_type == "basic" and self.username and self.password:
            return True
        return False
    
    @classmethod
    def from_string(cls, auth_str: str) -> "AuthConfig":
        """从字符串解析认证配置
        
        格式:
            cookie:sessionid=xxx
            bearer:tokenxxx
            basic:user:pass
        """
        if not auth_str or auth_str == "none":
            return cls(auth_type="none")
        
        parts = auth_str.split(":", 1)
        if len(parts) != 2:
            return cls(auth_type="none")
        
        auth_type, value = parts
        auth_type = auth_type.lower()
        
        if auth_type == "cookie":
            return cls(auth_type="cookie", cookie=value)
        
        elif auth_type == "bearer":
            return cls(auth_type="bearer", token=value)
        
        elif auth_type == "basic":
            cred_parts = value.split(":", 1)
            if len(cred_parts) == 2:
                return cls(auth_type="basic", username=cred_parts[0], password=cred_parts[1])
        
        return cls(auth_type="none")
