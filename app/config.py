from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    class Config:
        env_file = ".env"
    DOMAIN: str = "yourdomain.com"
    IS_DEV_ENV: bool = True  # или False для продакшена

settings = Settings() 