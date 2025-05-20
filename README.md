# Authentication Service

Простой сервис аутентификации на FastAPI

## Особенности

- Регистрация пользователей по email и телефону
- Верификация телефона через SMS.ru
- Вход по email+пароль, телефону+пароль, телефону+код из SMS
- Refresh токены (обновление access токена)
- Восстановление доступа по email (отправка кода)
- Повторная отправка кода (resend)
- OpenAPI-описание ошибок (400, 401, 403, 404, 429)
- Rate limiting для всех чувствительных endpoint'ов
- Пароли хешируются через bcrypt
- JWT токены с ограниченным временем жизни

## Установка

1. Клонируйте репозиторий:
```bash
git clone https://github.com/Maksim2801/AuthService.git
cd authserver
```

2. Создайте виртуальное окружение и установите зависимости:
```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

3. Настройка SMS.ru и переменных окружения:
   - Зарегистрируйтесь на [SMS.ru](https://sms.ru/)
   - Получите API ID в личном кабинете
   - Создайте файл `.env` в корне проекта и добавьте:
     ```
     SMSRU_API_ID=ваш_api_id_от_smsru
     DOMAIN=yourdomain.com
     IS_DEV_ENV=True
     SECRET_KEY=your_secret_key
     ALGORITHM=HS256
     ACCESS_TOKEN_EXPIRE_MINUTES=5
     DATABASE_URL=sqlite:///./app.db
     ```

4. Запустите сервер:
```bash
uvicorn main:app --reload
```

## API Endpoints (основные)

### Регистрация
```http
POST /auth/register
Content-Type: application/json

{
    "email": "user@example.com",
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

### Вход по email
```http
POST /auth/token
Content-Type: application/x-www-form-urlencoded
email=user@example.com&password=password123
```

### Вход по телефону
```http
POST /auth/login-phone
Content-Type: application/json
{
    "phone": "+79001234567",
    "password": "password123"
}
```

### Вход по коду из SMS
```http
POST /auth/send-login-sms
Content-Type: application/json
{
    "phone": "+79001234567"
}
```
(Пользователь получает код, далее)
```http
POST /auth/login-by-sms
Content-Type: application/json
{
    "phone": "+79001234567",
    "code": "123456"
}
```

### Повторная отправка кода (resend)
```http
POST /auth/resend-code
Content-Type: application/json
{
    "phone": "+79001234567"
}
```

### Восстановление по email
```http
POST /auth/send-recovery-code
Content-Type: application/json
{
    "email": "user@example.com"
}
```

### Обновление токенов
```http
POST /auth/refresh
Content-Type: application/json
{
    "refresh_token": "<refresh_token>"
}
```

### Получение информации о текущем пользователе
```http
GET /auth/me
Authorization: Bearer <access_token>
```

## Примеры ответов

**Успешная авторизация:**
```json
{
  "access_token": "jwt...",
  "refresh_token": "jwt...",
  "token_type": "bearer"
}
```

**Ошибка:**
```json
{
  "detail": "Incorrect email or password"
}
```

## Возможные ошибки
- 400: Некорректные данные (например, неверный формат email/телефона, неверный код)
- 401: Неверный логин/пароль
- 403: Телефон не верифицирован
- 404: Пользователь не найден
- 429: Превышен лимит запросов

---
