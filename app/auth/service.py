from datetime import datetime, timedelta
from typing import Optional, Dict
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends
from sqlalchemy.orm import Session
from email_validator import validate_email, EmailNotValidError
from app.schemas.auth import UserResponse, Token, VerificationRequest
from app.models.user import User
from app.database import get_db
from app.services.sms import SMSService
from app.config import get_settings

settings = get_settings()

# Конфигурация
SECRET_KEY = settings.secret_key
ALGORITHM = settings.algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = settings.access_token_expire_minutes
MAX_LOGIN_ATTEMPTS = 5
LOGIN_BLOCK_TIME_MINUTES = 30

# Хранение попыток входа (временное решение)
login_attempts: Dict[str, dict] = {}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
sms_service = SMSService()

class AuthService:
    def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt

    def check_login_attempts(self, username: str) -> None:
        """Проверка попыток входа и блокировки аккаунта"""
        if username not in login_attempts:
            login_attempts[username] = {
                "attempts": 0,
                "last_attempt": None,
                "blocked_until": None
            }
        
        user_attempts = login_attempts[username]
        
        # Проверка блокировки
        if user_attempts["blocked_until"]:
            if datetime.utcnow() < user_attempts["blocked_until"]:
                remaining_time = (user_attempts["blocked_until"] - datetime.utcnow()).total_seconds() / 60
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Account is blocked. Try again in {int(remaining_time)} minutes"
                )
            else:
                # Сброс блокировки если время истекло
                user_attempts["blocked_until"] = None
                user_attempts["attempts"] = 0

    def update_login_attempts(self, username: str, success: bool) -> None:
        """Обновление информации о попытках входа"""
        if username not in login_attempts:
            login_attempts[username] = {
                "attempts": 0,
                "last_attempt": None,
                "blocked_until": None
            }
        
        user_attempts = login_attempts[username]
        user_attempts["last_attempt"] = datetime.utcnow()
        
        if success:
            user_attempts["attempts"] = 0
            user_attempts["blocked_until"] = None
        else:
            user_attempts["attempts"] += 1
            if user_attempts["attempts"] >= MAX_LOGIN_ATTEMPTS:
                user_attempts["blocked_until"] = datetime.utcnow() + timedelta(minutes=LOGIN_BLOCK_TIME_MINUTES)

    def validate_email_address(self, email: str) -> str:
        """Валидация email адреса"""
        try:
            # Валидация и нормализация email
            validation = validate_email(email, check_deliverability=False)
            return validation.email
        except EmailNotValidError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid email address: {str(e)}"
            )

    def check_user_exists(self, db: Session, username: str, phone: str) -> None:
        """Проверка существования пользователя"""
        # Проверка по username
        if db.query(User).filter(User.username == username).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already registered"
            )
        
        # Проверка по телефону
        if db.query(User).filter(User.phone == phone).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Phone number already registered"
            )

    async def register_user(self, username: str, phone: str, password: str, db: Session) -> UserResponse:
        # Проверка существования пользователя
        self.check_user_exists(db, username, phone)
        
        # Генерация кода верификации
        verification_code = sms_service.generate_verification_code()
        verification_expires = sms_service.get_code_expiration()
        
        # Хеширование пароля
        hashed_password = pwd_context.hash(password)
        
        # Создание пользователя
        db_user = User(
            username=username,
            phone=phone,
            hashed_password=hashed_password,
            verification_code=verification_code,
            verification_code_expires=verification_expires,
            is_verified=False
        )
        
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        
        # Отправка кода верификации
        sms_service.send_verification_code(phone, verification_code)
        
        return UserResponse.from_orm(db_user)

    async def verify_phone(self, verification_data: VerificationRequest, db: Session) -> UserResponse:
        user = db.query(User).filter(User.phone == verification_data.phone).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        if user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Phone already verified"
            )
        
        if not user.verification_code or not user.verification_code_expires:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No verification code found"
            )
        
        if datetime.utcnow() > user.verification_code_expires:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Verification code expired"
            )
        
        if user.verification_code != verification_data.code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid verification code"
            )
        
        # Обновление статуса верификации
        user.is_verified = True
        user.verification_code = None
        user.verification_code_expires = None
        
        db.commit()
        db.refresh(user)
        
        return UserResponse.from_orm(user)

    async def authenticate_user(self, username: str, password: str, db: Session) -> Token:
        # Проверка попыток входа
        self.check_login_attempts(username)
        
        user = db.query(User).filter(User.username == username).first()
        if not user:
            self.update_login_attempts(username, False)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        if not user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Phone number not verified"
            )
        
        if not pwd_context.verify(password, user.hashed_password):
            self.update_login_attempts(username, False)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Успешный вход
        self.update_login_attempts(username, True)
        user.last_login = datetime.utcnow()
        db.commit()

        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = self.create_access_token(
            data={"sub": username}, expires_delta=access_token_expires
        )
        return Token(access_token=access_token, token_type="bearer")

    async def get_current_user(self, token: str, db: Session) -> UserResponse:
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username: str = payload.get("sub")
            if username is None:
                raise credentials_exception
        except JWTError:
            raise credentials_exception
            
        user = db.query(User).filter(User.username == username).first()
        if user is None:
            raise credentials_exception
            
        return UserResponse.from_orm(user) 