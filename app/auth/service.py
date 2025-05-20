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
from app.config import settings

MAX_LOGIN_ATTEMPTS = 5
LOGIN_BLOCK_TIME_MINUTES = 30

# Хранение попыток входа (временное решение)
login_attempts: Dict[str, dict] = {}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
sms_service = SMSService()

class AuthService:
    def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None):
        to_encode = data.copy()
        expire = datetime.utcnow() + (expires_delta or timedelta(minutes=5))
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        return encoded_jwt

    def create_refresh_token(self, data: dict, expires_delta: Optional[timedelta] = None):
        to_encode = data.copy()
        expire = datetime.utcnow() + (expires_delta or timedelta(days=7))
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

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

    def check_user_exists(self, db: Session, email: str, phone: str) -> None:
        """Проверка существования пользователя"""
        # Проверка по email
        if db.query(User).filter(User.email == email).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        # Проверка по телефону
        if db.query(User).filter(User.phone == phone).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Phone number already registered"
            )

    async def register_user(self, email: str, phone: str, password: str, db: Session) -> UserResponse:
        # Валидация email
        validated_email = self.validate_email_address(email)
        # Валидация и нормализация телефона
        validated_phone = SMSService().validate_phone_number(phone)
        # Проверка существования пользователя
        self.check_user_exists(db, validated_email, validated_phone)
        
        # Генерация кода верификации
        verification_code = sms_service.generate_verification_code()
        verification_expires = sms_service.get_code_expiration()
        
        # Хеширование пароля
        hashed_password = pwd_context.hash(password)
        
        # Создание пользователя
        db_user = User(
            email=validated_email,
            phone=validated_phone,
            hashed_password=hashed_password,
            verification_code=verification_code,
            verification_code_expires=verification_expires,
            is_verified=False
        )
        
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        
        # Отправка кода верификации
        await sms_service.send_verification_code(validated_phone, verification_code)
        
        return UserResponse.model_validate(db_user)

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
        
        return UserResponse.model_validate(user)

    async def authenticate_user(self, email: str, password: str, db: Session) -> Token:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Phone number not verified"
            )
        if not pwd_context.verify(password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user.last_login = datetime.utcnow()
        db.commit()
        access_token = self.create_access_token({"sub": user.email})
        refresh_token = self.create_refresh_token({"sub": user.email})
        return Token(access_token=access_token, refresh_token=refresh_token, token_type="bearer")

    async def get_current_user(self, token: str, db: Session) -> UserResponse:
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            email: str = payload.get("sub")
            if email is None:
                raise credentials_exception
        except JWTError:
            raise credentials_exception
        user = db.query(User).filter(User.email == email).first()
        if user is None:
            raise credentials_exception
        return UserResponse.model_validate(user)

    async def resend_verification_code(self, phone: str, db: Session):
        user = db.query(User).filter(User.phone == phone).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if user.is_verified:
            raise HTTPException(status_code=400, detail="Phone already verified")
        verification_code = sms_service.generate_verification_code()
        verification_expires = sms_service.get_code_expiration()
        user.verification_code = verification_code
        user.verification_code_expires = verification_expires
        db.commit()
        await sms_service.send_verification_code(phone, verification_code)
        return {"detail": "Verification code resent"}

    async def authenticate_user_by_phone(self, phone: str, password: str, db: Session) -> Token:
        user = db.query(User).filter(User.phone == phone).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect phone or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Phone number not verified"
            )
        if not pwd_context.verify(password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect phone or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user.last_login = datetime.utcnow()
        db.commit()
        access_token = self.create_access_token({"sub": user.email})
        refresh_token = self.create_refresh_token({"sub": user.email})
        return Token(access_token=access_token, refresh_token=refresh_token, token_type="bearer")

    async def send_login_sms(self, phone: str, db: Session):
        user = db.query(User).filter(User.phone == phone).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if not user.is_verified:
            raise HTTPException(status_code=403, detail="Phone number not verified")
        code = sms_service.generate_verification_code()
        expires = sms_service.get_code_expiration()
        user.verification_code = code
        user.verification_code_expires = expires
        db.commit()
        await sms_service.send_verification_code(phone, code)
        return {"detail": "Login code sent"}

    async def login_by_sms(self, phone: str, code: str, db: Session) -> Token:
        user = db.query(User).filter(User.phone == phone).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if not user.is_verified:
            raise HTTPException(status_code=403, detail="Phone number not verified")
        if not user.verification_code or not user.verification_code_expires:
            raise HTTPException(status_code=400, detail="No code sent")
        if datetime.utcnow() > user.verification_code_expires:
            raise HTTPException(status_code=400, detail="Code expired")
        if user.verification_code != code:
            raise HTTPException(status_code=400, detail="Invalid code")
        user.last_login = datetime.utcnow()
        user.verification_code = None
        user.verification_code_expires = None
        db.commit()
        access_token = self.create_access_token({"sub": user.email})
        refresh_token = self.create_refresh_token({"sub": user.email})
        return Token(access_token=access_token, refresh_token=refresh_token, token_type="bearer")

    async def send_recovery_code(self, email: str, db: Session):
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        # Здесь можно реализовать отправку email (заглушка)
        # Например, с помощью внешнего сервиса или SMTP
        # Пока просто сгенерируем код и "отправим"
        code = sms_service.generate_verification_code()
        expires = sms_service.get_code_expiration()
        user.verification_code = code
        user.verification_code_expires = expires
        db.commit()
        print(f"Recovery code for {email}: {code}")
        return {"detail": "Recovery code sent to email (stub)"} 