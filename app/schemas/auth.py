from datetime import datetime
from pydantic import BaseModel, Field, EmailStr
from typing import Optional
from app.constants import PHONE_REGEX

class UserBase(BaseModel):
    email: EmailStr = Field(..., description="Valid email address")
    phone: str = Field(..., pattern=PHONE_REGEX, description="Российский номер телефона в формате +79XXXXXXXXX")

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)

class UserResponse(UserBase):
    id: int
    is_verified: bool
    created_at: datetime
    last_login: Optional[datetime] = None

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class VerificationRequest(BaseModel):
    phone: str = Field(..., pattern=PHONE_REGEX, description="Российский номер телефона в формате +79XXXXXXXXX")
    code: str = Field(..., min_length=6, max_length=6)

class LoginAttempts(BaseModel):
    attempts: int
    last_attempt: datetime | None
    blocked_until: datetime | None

class PhoneLoginRequest(BaseModel):
    phone: str = Field(..., pattern=PHONE_REGEX, description="Российский номер телефона в формате +79XXXXXXXXX")
    password: str = Field(..., min_length=8)

class ErrorResponse(BaseModel):
    detail: str

class SendLoginSMSRequest(BaseModel):
    phone: str = Field(..., pattern=PHONE_REGEX, description="Российский номер телефона в формате +79XXXXXXXXX")

class LoginBySMSRequest(BaseModel):
    phone: str = Field(..., pattern=PHONE_REGEX, description="Российский номер телефона в формате +79XXXXXXXXX")
    code: str = Field(..., min_length=6, max_length=6)

class SendRecoveryCodeRequest(BaseModel):
    email: EmailStr 