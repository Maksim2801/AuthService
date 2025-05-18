from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    # JWT settings
    secret_key: str = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    # MTS Exolve settings
    exolve_api_key: str | None = None
    exolve_sender_name: str | None = None

    # SMS.ru settings
    smsru_api_id: str

    class Config:
        env_file = ".env"

@lru_cache()
def get_settings():
    return Settings() 