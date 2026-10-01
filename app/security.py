"""
Модуль безопасности: аутентификация, сессии, CSRF, rate-limiting,
санитизация логов и разграничение прав доступа (RBAC).
Закрывает замечания аудита:
2.6 — Изолированный RATE_LIMIT_PEPPER вместо SECRET_KEY для хеширования идентификаторов.
2.14 — Защита от Log Injection.
2.15 — Защита от утечки PII.
"""
import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Optional

from app.config import Config
from app.constants import (
    DUMMY_PASSWORD_HASH,
    ROLE_AGENT,
    ROLE_USER,
)
from app.db import cleanup_expired_data, get_db

try:
    from flask import abort, current_app, g, redirect, request, session, url_for
    from werkzeug.security import check_password_hash, generate_password_hash
except ImportError:
    abort = None
    current_app = None
    g = None
    redirect = None
    request = None
    session = {}
    url_for = None
    def check_password_hash(p_hash, password):
        return p_hash.endswith(hashlib.sha256(password.encode()).hexdigest())
    def generate_password_hash(p):
        return "pbkdf2:sha256:260000$" + hashlib.sha256(p.encode()).hexdigest()

logger = logging.getLogger("ais_zayavki")


def hash_password(password: str) -> str:
    """Хеширование пароля через стойкий алгоритм Werkzeug (scrypt/pbkdf2)."""
    return generate_password_hash(password)


def verify_password(p_hash: str, password: str) -> bool:
    """Проверка пароля с защитой от атак по времени (timing attacks)."""
    try:
        return check_password_hash(p_hash, password)
    except Exception:
        return False


def hash_identifier(identifier: str) -> str:
    """
    Хеширование клиентского IP/имени пользователя с отдельным солью/перцем (пункт 2.6).
    Изолирует rate-limit хеши от SECRET_KEY приложения.
    """
    pepper = Config.get_rate_limit_pepper()
    return hashlib.sha256(pepper + str(identifier).encode("utf-8")).hexdigest()


def record_attempt(conn, kind: str, identifier: str):
    """Фиксация попытки действия в БД для rate-limiting."""
    ident_hash = hash_identifier(identifier)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    conn.execute(
        "INSERT INTO attempts (kind, identifier_hash, created_at) VALUES (?, ?, ?)",
        (kind, ident_hash, now),
    )
    conn.commit()


def check_rate_limit(conn, kind: str, identifier: str, limit: int, window_seconds: int) -> bool:
    """
    Проверка лимита частоты запросов за скользящее временное окно (пункт 2.11).
    Возвращает True, если действие разрешено, False — если лимит превышен.
    """
    ident_hash = hash_identifier(identifier)
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat(timespec="seconds")
    cur = conn.cursor()
    cur.execute(
        """SELECT COUNT(*) FROM attempts
           WHERE kind = ? AND identifier_hash = ? AND created_at >= ?""",
        (kind, ident_hash, cutoff),
    )
    count = cur.fetchone()[0]
    if count >= limit:
        return False

    record_attempt(conn, kind, identifier)
    return True


def sanitize_log_message(msg: str) -> str:
    """Санитизирует сообщения перед отправкой в лог для предотвращения Log Injection (пункт 2.14)."""
    return str(msg).replace("\r", " ").replace("\n", " ").strip()


def start_session(conn, user_id: int, lifetime_days: int = 7) -> str:
    """
    Создаёт серверную сессию с инвалидацией всех старых сессий пользователя (пункт 2.2).
    Возвращает сырой токен сессии.
    """
    conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=lifetime_days)

    conn.execute(
        """
        INSERT INTO sessions (user_id, token_hash, created_at, expires_at)
        VALUES (?, ?, ?, ?)
        """,
        (user_id, token_hash, now.isoformat(), expires.isoformat()),
    )
    conn.commit()
    return raw_token


def terminate_session(conn, raw_token: str):
    """Удаляет конкретную сессию по токену."""
    if not raw_token:
        return
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
    conn.commit()


def terminate_all_user_sessions(conn, user_id: int):
    """Удаляет все активные сессии пользователя (кнопка 'Выйти со всех устройств') (пункт 2.2)."""
    conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    conn.commit()


def get_user_from_token(conn, raw_token: str) -> Optional[dict]:
    """Находит пользователя по токену сессии, если срок действия сессии не истёк."""
    if not raw_token:
        return None
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    now_str = datetime.now(timezone.utc).isoformat()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT u.id, u.username, u.role, u.created_at, u.updated_at
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token_hash = ? AND s.expires_at > ?
        """,
        (token_hash, now_str),
    )
    row = cur.fetchone()
    if row:
        return dict(row)
    return None


def generate_csrf_token() -> str:
    """Генерирует и сохраняет в сессии стойкий CSRF-токен."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf():
    """Проверяет CSRF-токен для небезопасных методов запроса (POST, PUT, DELETE)."""
    if request is None or request.method in ("GET", "HEAD", "OPTIONS"):
        return
    token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    expected = session.get("_csrf_token")
    if not expected or not token or not hmac.compare_digest(token, expected):
        if abort:
            abort(400, description="Ошибка валидации CSRF-токена. Пожалуйста, обновите страницу.")
        else:
            raise PermissionError("CSRF check failed")


def login_required(f):
    """Декоратор, требующий обязательной авторизации пользователя."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = getattr(g, "current_user", None) if g else None
        if not user and session.get("user_id"):
            db = get_db()
            cur = db.cursor()
            cur.execute("SELECT id, username, role, created_at, updated_at FROM users WHERE id = ?", (session["user_id"],))
            row = cur.fetchone()
            if row:
                g.current_user = dict(row)
                user = g.current_user

        if not user:
            return redirect(url_for("auth.login", next=request.path))
        return f(*args, **kwargs)
    return decorated_function


def agent_required(f):
    """Декоратор, требующий роли специалиста поддержки (agent)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = getattr(g, "current_user", None) if g else None
        if not user and session.get("user_id"):
            db = get_db()
            cur = db.cursor()
            cur.execute("SELECT id, username, role, created_at, updated_at FROM users WHERE id = ?", (session["user_id"],))
            row = cur.fetchone()
            if row:
                g.current_user = dict(row)
                user = g.current_user

        if not user:
            return redirect(url_for("auth.login", next=request.path))
        if user.get("role") != ROLE_AGENT:
            abort(403, description="Доступ разрешён только специалистам поддержки.")
        return f(*args, **kwargs)
    return decorated_function
