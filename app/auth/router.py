from fastapi import APIRouter, Depends, HTTPException, status, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app.database import get_db
from app.schemas.auth import UserCreate, UserResponse, Token, VerificationRequest, PhoneLoginRequest, ErrorResponse, SendLoginSMSRequest, LoginBySMSRequest, SendRecoveryCodeRequest
from app.auth.service import AuthService
from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi import Request
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt, JWTError
from app.config import settings

router = APIRouter()
auth_service = AuthService()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")
limiter = Limiter(key_func=get_remote_address)

@router.post("/register", response_model=UserResponse)
@limiter.limit("5/minute")
async def register(user_data: UserCreate, request: Request, db: Session = Depends(get_db)):
    return await auth_service.register_user(
        email=user_data.email,
        phone=user_data.phone,
        password=user_data.password,
        db=db
    )

@router.post("/verify", response_model=UserResponse)
@limiter.limit("10/minute")
async def verify_phone(verification_data: VerificationRequest, request: Request, db: Session = Depends(get_db)):
    return await auth_service.verify_phone(verification_data, db)

@router.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    return await auth_service.authenticate_user(form_data.username, form_data.password, db)

@router.get("/me", response_model=UserResponse)
async def read_users_me(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    return await auth_service.get_current_user(token, db)

@router.post("/refresh", response_model=Token)
async def refresh_token(refresh_token: str):
    try:
        payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id = payload.get("sub")
        # (опционально) проверить, не отозван ли refresh token
        access_token = auth_service.create_access_token({"sub": user_id})
        new_refresh_token = auth_service.create_refresh_token({"sub": user_id})
        return {"access_token": access_token, "refresh_token": new_refresh_token, "token_type": "bearer"}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

@router.post("/resend-code")
async def resend_code(phone: str = Body(...), db: Session = Depends(get_db)):
    return await auth_service.resend_verification_code(phone, db)

@router.post(
    "/login-phone",
    response_model=Token,
    responses={
        401: {"model": ErrorResponse, "description": "Incorrect phone or password"},
        403: {"model": ErrorResponse, "description": "Phone number not verified"},
        422: {"model": ErrorResponse, "description": "Validation error"},
    },
)
async def login_by_phone(data: PhoneLoginRequest, db: Session = Depends(get_db)):
    return await auth_service.authenticate_user_by_phone(data.phone, data.password, db)

@router.post(
    "/send-login-sms",
    response_model=ErrorResponse,
    responses={
        404: {"model": ErrorResponse, "description": "User not found"},
        403: {"model": ErrorResponse, "description": "Phone number not verified"},
        429: {"description": "Too Many Requests"},
    },
)
@limiter.limit("1/30seconds")
async def send_login_sms(data: SendLoginSMSRequest, db: Session = Depends(get_db)):
    return await auth_service.send_login_sms(data.phone, db)

@router.post(
    "/login-by-sms",
    response_model=Token,
    responses={
        404: {"model": ErrorResponse, "description": "User not found"},
        403: {"model": ErrorResponse, "description": "Phone number not verified"},
        400: {"model": ErrorResponse, "description": "Invalid or expired code"},
        429: {"description": "Too Many Requests"},
    },
)
@limiter.limit("5/minute")
async def login_by_sms(data: LoginBySMSRequest, db: Session = Depends(get_db)):
    return await auth_service.login_by_sms(data.phone, data.code, db)

@router.post(
    "/send-recovery-code",
    response_model=ErrorResponse,
    responses={
        404: {"model": ErrorResponse, "description": "User not found"},
        429: {"description": "Too Many Requests"},
    },
)
@limiter.limit("1/30seconds")
async def send_recovery_code(data: SendRecoveryCodeRequest, db: Session = Depends(get_db)):
    return await auth_service.send_recovery_code(data.email, db) 