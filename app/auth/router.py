from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app.database import get_db
from app.schemas.auth import UserCreate, UserResponse, Token, VerificationRequest
from app.auth.service import AuthService
from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi import Request

router = APIRouter()
auth_service = AuthService()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")
limiter = Limiter(key_func=get_remote_address)

@router.post("/register", response_model=UserResponse)
@limiter.limit("5/minute")
async def register(user_data: UserCreate, request: Request, db: Session = Depends(get_db)):
    return await auth_service.register_user(
        username=user_data.username,
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