# Authentication Service

Простой сервис аутентификации на FastAPI с верификацией телефона через SMS.ru и защитой от DoS-атак (rate limiting).

## Особенности

- Регистрация пользователей с верификацией телефона (через SMS.ru)
- Аутентификация с JWT токенами
- Защита от брутфорса (блокировка после 5 неудачных попыток)
- Rate limiting (ограничение частоты запросов) для защиты от DoS-атак
- Поддержка только российских номеров телефона
- Масштабируемая структура проекта

## Установка

1. Клонируйте репозиторий:
```bash
git clone <repository-url>
cd authserver
```

2. Создайте виртуальное окружение и установите зависимости:
```bash
python -m venv venv
venv\Scripts\activate     # для Windows
pip install -r requirements.txt
```

3. Настройка SMS.ru:
   - Зарегистрируйтесь на [SMS.ru](https://sms.ru/)
   - Получите API ID в личном кабинете
   - Создайте файл `.env` в корне проекта и добавьте:
     ```
     SMSRU_API_ID=ваш_api_id_от_smsru
     ```

4. Запустите сервер:
```bash
uvicorn main:app --reload
```

## API Endpoints

### Регистрация
```http
POST /auth/register
Content-Type: application/json

{
    "username": "user123",
    "phone": "+79001234567",
    "password": "password123"
}
```

### Верификация телефона
```http
POST /auth/verify
Content-Type: application/json

{
    "phone": "+79001234567",
    "code": "123456"
}
```

### Вход
```http
POST /auth/token
Content-Type: application/x-www-form-urlencoded

username=user123&password=password123
```

### Получение информации о текущем пользователе
```http
GET /auth/me
Authorization: Bearer <token>
```

## Rate limiting (ограничение частоты запросов)

- Регистрация: не более 5 запросов в минуту с одного IP
- Верификация: не более 10 запросов в минуту с одного IP
- Можно легко настроить лимиты для других эндпоинтов
- При превышении лимита возвращается ошибка 429

## Безопасность

- Пароли хешируются с использованием bcrypt
- JWT токены с ограниченным временем жизни
- Защита от брутфорса (блокировка после 5 неудачных попыток)
- Верификация телефона через SMS.ru
- Rate limiting для защиты от DoS-атак
- Безопасное хранение конфигурации в переменных окружения