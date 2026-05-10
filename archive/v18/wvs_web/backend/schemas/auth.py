from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime

class Token(BaseModel):
    """令牌响应模型"""
    access_token: str
    refresh_token: str
    token_type: str

class TokenData(BaseModel):
    """令牌数据模型"""
    username: Optional[str] = None
    user_id: Optional[int] = None

class UserBase(BaseModel):
    """用户基础模型"""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    full_name: Optional[str] = Field(None, max_length=100)

class UserCreate(UserBase):
    """用户创建模型"""
    password: str = Field(..., min_length=6)

class UserUpdate(BaseModel):
    """用户更新模型"""
    email: Optional[EmailStr] = None
    full_name: Optional[str] = Field(None, max_length=100)
    is_active: Optional[bool] = None

class UserResponse(UserBase):
    """用户响应模型"""
    id: int
    is_active: bool
    is_superuser: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class LoginRequest(BaseModel):
    """登录请求模型"""
    username: str
    password: str

class PasswordChange(BaseModel):
    """密码修改模型"""
    old_password: str
    new_password: str = Field(..., min_length=6)