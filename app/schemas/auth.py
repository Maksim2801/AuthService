from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional

# Регулярное выражение для валидации российских номеров
PHONE_REGEX = r'^\+?7\d{10}$'

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
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
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class VerificationRequest(BaseModel):
    phone: str = Field(..., pattern=PHONE_REGEX, description="Российский номер телефона в формате +79XXXXXXXXX")
    code: str = Field(..., min_length=6, max_length=6)

class LoginAttempts(BaseModel):
    attempts: int
    last_attempt: datetime | None
    blocked_until: datetime | None 