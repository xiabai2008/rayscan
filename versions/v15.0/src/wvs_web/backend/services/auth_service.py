from datetime import datetime, timedelta
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from core.config import settings
from core.database import User
from schemas.auth import UserCreate, UserUpdate

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class AuthService:
    """认证服务"""

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """验证密码"""
        return pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def get_password_hash(password: str) -> str:
        """生成密码哈希"""
        return pwd_context.hash(password)

    @staticmethod
    def get_user_by_username(db: Session, username: str) -> Optional[User]:
        """通过用户名获取用户"""
        return db.query(User).filter(User.username == username).first()

    @staticmethod
    def get_user_by_email(db: Session, email: str) -> Optional[User]:
        """通过邮箱获取用户"""
        return db.query(User).filter(User.email == email).first()

    @staticmethod
    def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
        """通过ID获取用户"""
        return db.query(User).filter(User.id == user_id).first()

    def create_user(self, db: Session, user_data: UserCreate) -> User:
        """创建用户"""
        hashed_password = self.get_password_hash(user_data.password)
        db_user = User(
            username=user_data.username,
            email=user_data.email,
            full_name=user_data.full_name,
            hashed_password=hashed_password,
            is_active=True,
            is_superuser=False
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user

    def update_user(self, db: Session, user_id: int, user_data: dict) -> User:
        """更新用户信息"""
        db_user = self.get_user_by_id(db, user_id)
        if not db_user:
            return None

        for key, value in user_data.items():
            if hasattr(db_user, key) and value is not None:
                setattr(db_user, key, value)

        db.commit()
        db.refresh(db_user)
        return db_user

    def update_password(self, db: Session, user_id: int, new_password: str):
        """更新用户密码"""
        db_user = self.get_user_by_id(db, user_id)
        if not db_user:
            return None

        db_user.hashed_password = self.get_password_hash(new_password)
        db.commit()

    def authenticate_user(self, db: Session, username: str, password: str) -> Optional[User]:
        """认证用户"""
        user = self.get_user_by_username(db, username)
        if not user:
            # 尝试通过邮箱查找
            user = self.get_user_by_email(db, username)

        if not user:
            return None

        if not self.verify_password(password, user.hashed_password):
            return None

        return user

    def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """创建访问令牌"""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)

        to_encode.update({"exp": expire, "type": "access"})
        encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        return encoded_jwt

    def create_refresh_token(self, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """创建刷新令牌"""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(days=7)

        to_encode.update({"exp": expire, "type": "refresh"})
        encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        return encoded_jwt

    def verify_token(self, token: str, token_type: str = "access") -> Optional[dict]:
        """验证令牌"""
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            if payload.get("type") != token_type:
                return None
            return payload
        except JWTError:
            return None

    def verify_access_token(self, token: str) -> Optional[dict]:
        """验证访问令牌"""
        return self.verify_token(token, "access")

    def verify_refresh_token(self, token: str) -> Optional[dict]:
        """验证刷新令牌"""
        return self.verify_token(token, "refresh")

    def get_current_user(self, db: Session, token: str) -> Optional[User]:
        """获取当前用户"""
        payload = self.verify_access_token(token)
        if not payload:
            return None

        username: str = payload.get("sub")
        if username is None:
            return None

        user = self.get_user_by_username(db, username)
        return user

    def is_active_user(self, user: User) -> bool:
        """检查用户是否激活"""
        return user.is_active

    def is_superuser(self, user: User) -> bool:
        """检查用户是否为超级用户"""
        return user.is_superuser