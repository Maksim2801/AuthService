import random
import aiohttp
from datetime import datetime, timedelta
from fastapi import HTTPException, status
from app.config import settings
from app.constants import PHONE_REGEX

class SMSService:
    @staticmethod
    def generate_verification_code() -> str:
        """Генерация 6-значного кода верификации"""
        return str(random.randint(100000, 999999))

    @staticmethod
    def get_code_expiration() -> datetime:
        """Получение времени истечения кода (10 минут)"""
        return datetime.utcnow() + timedelta(minutes=10)

    def validate_phone_number(self, phone: str) -> str:
        """
        Валидация и форматирование номера телефона
        
        Args:
            phone: Номер телефона в любом формате
            
        Returns:
            str: Номер телефона в формате 79XXXXXXXXX
            
        Raises:
            HTTPException: Если номер телефона невалидный
        """
        digits = ''.join(filter(str.isdigit, phone))
        if len(digits) != 11 or not digits.startswith('7'):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Phone number must be in format 79XXXXXXXXX"
            )
        return digits

    async def send_verification_code(self, phone: str, code: str) -> None:
        """
        Отправка кода верификации на телефон через SMS.ru
        
        Args:
            phone: Номер телефона получателя
            code: Код верификации
            
        Raises:
            HTTPException: Если произошла ошибка при отправке SMS
        """
        formatted_phone = self.validate_phone_number(phone)
        url = "https://sms.ru/sms/send"
        params = {
            "api_id": settings.SMSRU_API_ID,
            "to": formatted_phone,
            "msg": f"Ваш код подтверждения: {code}",
            "json": 1
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    data = await response.json()
                    if data.get("status") != "OK":
                        raise Exception(data.get("status_text", "Unknown error"))
                    print(f"SMS sent successfully to {formatted_phone}")
        except Exception as e:
            print(f"Error sending SMS: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send verification code. Please try again later."
            ) 