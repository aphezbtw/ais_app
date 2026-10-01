"""
Константы АИС «Заявки» v2.
Централизованное хранение ролей, статусов, приоритетов, SLA и параметров безопасности.
"""

# Роли пользователей
ROLE_USER = "user"
ROLE_AGENT = "agent"
ALL_ROLES = (ROLE_USER, ROLE_AGENT)

# Статусы заявок
STATUS_NEW = "new"
STATUS_IN_PROGRESS = "in_progress"
STATUS_RESOLVED = "resolved"
STATUS_CLOSED = "closed"
ALL_STATUSES = (STATUS_NEW, STATUS_IN_PROGRESS, STATUS_RESOLVED, STATUS_CLOSED)

STATUS_LABELS = {
    STATUS_NEW: "Новая",
    STATUS_IN_PROGRESS: "В работе",
    STATUS_RESOLVED: "Решена",
    STATUS_CLOSED: "Закрыта",
}

# Приоритеты заявок
PRIORITY_LOW = "low"
PRIORITY_NORMAL = "normal"
PRIORITY_HIGH = "high"
PRIORITY_CRITICAL = "critical"
ALL_PRIORITIES = (PRIORITY_LOW, PRIORITY_NORMAL, PRIORITY_HIGH, PRIORITY_CRITICAL)

PRIORITY_LABELS = {
    PRIORITY_LOW: "Низкий",
    PRIORITY_NORMAL: "Обычный",
    PRIORITY_HIGH: "Высокий",
    PRIORITY_CRITICAL: "Критический",
}

# Нормативы SLA в часах по приоритету
SLA_HOURS = {
    PRIORITY_LOW: 72,
    PRIORITY_NORMAL: 24,
    PRIORITY_HIGH: 8,
    PRIORITY_CRITICAL: 4,
}

# Ограничения валидации входных данных
SUBJECT_MIN_LEN = 3
SUBJECT_MAX_LEN = 200
DESCRIPTION_MIN_LEN = 5
DESCRIPTION_MAX_LEN = 4000
COMMENT_MIN_LEN = 1
COMMENT_MAX_LEN = 2000
USERNAME_MIN_LEN = 3
USERNAME_MAX_LEN = 50
PASSWORD_MIN_LEN = 6
PASSWORD_MAX_LEN = 128

# Пагинация
DEFAULT_PAGE_SIZE = 10
MAX_PAGE_SIZE = 100

# Лимиты rate-limit (попытки / окно в секундах)
RATE_LIMIT_LOGIN = (5, 300)        # 5 попыток за 5 минут
RATE_LIMIT_REGISTER = (3, 600)     # 3 попытки за 10 минут
RATE_LIMIT_TICKET = (10, 60)       # 10 заявок за 1 минуту
RATE_LIMIT_COMMENT = (20, 60)      # 20 комментариев за 1 минуту

# Заголовки безопасности
SERVER_HEADER = "AIS-Zayavki/2.0"
PERMISSIONS_POLICY = "geolocation=(), camera=(), microphone=()"
CSP_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "frame-ancestors 'none'; "
    "form-action 'self';"
)

# Защита от тайминг-атак (фиктивный хеш)
DUMMY_PASSWORD_HASH = "scrypt:32768:8:1$0000000000000000$" + "0" * 128
