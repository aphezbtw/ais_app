"""
Модуль конфигурации АИС «Заявки» v2.
Поддерживает профили Development, Production, Testing.
Закрывает замечания аудита:
1.1 — COOKIE_SECURE=1 по умолчанию для ProdConfig (отключение только через ALLOW_INSECURE_COOKIES=1).
2.6 — Изолированный RATE_LIMIT_PEPPER для защиты IP-хешей.
5.1 — Обязательный SECRET_KEY в ProdConfig (fail-fast при отсутствии).
"""
import os
import secrets
from datetime import timedelta
from pathlib import Path


class Config:
    """Базовый класс конфигурации."""

    BASE_DIR = Path(__file__).resolve().parent.parent
    INSTANCE_DIR = Path(os.environ.get("INSTANCE_DIR", BASE_DIR / "instance"))

    # Сетевые настройки (порт по умолчанию 5000)
    HOST = os.environ.get("HOST", "0.0.0.0")
    PORT = int(os.environ.get("PORT", "5000"))

    # Доверенные хосты
    _raw_trusted = os.environ.get("TRUSTED_HOSTS", "")
    TRUSTED_HOSTS = [h.strip() for h in _raw_trusted.split(",") if h.strip()]

    # База данных
    DATABASE = os.environ.get("DATABASE_PATH", str(INSTANCE_DIR / "zayavki.db"))

    # Секретный ключ приложения
    SECRET_KEY = os.environ.get("SECRET_KEY")

    # Переключатель принудительного отключения безопасных куки для локальной отладки
    ALLOW_INSECURE_COOKIES = os.environ.get("ALLOW_INSECURE_COOKIES", "0").strip().lower() in ("1", "true", "yes")

    # Сессии Flask
    COOKIE_SECURE = not ALLOW_INSECURE_COOKIES
    SESSION_COOKIE_SECURE = COOKIE_SECURE
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_LIFETIME_DAYS = int(os.environ.get("SESSION_LIFETIME_DAYS", "7"))
    PERMANENT_SESSION_LIFETIME = timedelta(days=SESSION_LIFETIME_DAYS)

    # Демо-данные (по умолчанию выключено, включается ТОЛЬКО явно SEED_DEMO=1)
    SEED_DEMO = os.environ.get("SEED_DEMO", "0").strip().lower() in ("1", "true", "yes")

    # Обратный прокси (ProxyFix)
    BEHIND_PROXY = os.environ.get("BEHIND_PROXY", "0").strip().lower() in ("1", "true", "yes")
    NUM_PROXIES = int(os.environ.get("NUM_PROXIES", "1"))

    # Максимальный размер тела запроса (2 МБ)
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024

    # Логирование и алертинг (пункт 5.5)
    LOG_FILE = os.environ.get("LOG_FILE", str(INSTANCE_DIR / "app.log"))
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    ALERT_WEBHOOK_URL = os.environ.get("ALERT_WEBHOOK_URL")

    # 2.6: Отдельный перец (pepper) для rate-limit хешей
    _pepper = None

    @classmethod
    def get_rate_limit_pepper(cls) -> bytes:
        """Возвращает или генерирует изолированный pepper для rate-limit хешей (0o600)."""
        if cls._pepper:
            return cls._pepper

        cls.INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(cls.INSTANCE_DIR, 0o700)
        except OSError:
            pass

        pepper_file = cls.INSTANCE_DIR / "rate_limit.pepper"
        if pepper_file.exists():
            try:
                os.chmod(pepper_file, 0o600)
            except OSError:
                pass
            cls._pepper = pepper_file.read_bytes().strip()
            return cls._pepper

        new_pepper = secrets.token_bytes(32)
        pepper_file.write_bytes(new_pepper)
        try:
            os.chmod(pepper_file, 0o600)
        except OSError:
            pass
        cls._pepper = new_pepper
        return new_pepper

    @classmethod
    def ensure_secret_key(cls) -> str:
        """Гарантирует наличие секретного ключа с безопасными правами доступа 0o600."""
        if cls.SECRET_KEY:
            return cls.SECRET_KEY

        cls.INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(cls.INSTANCE_DIR, 0o700)
        except OSError:
            pass

        key_file = cls.INSTANCE_DIR / "secret.key"
        if key_file.exists():
            try:
                os.chmod(key_file, 0o600)
            except OSError:
                pass
            cls.SECRET_KEY = key_file.read_text(encoding="utf-8").strip()
            return cls.SECRET_KEY

        new_key = secrets.token_hex(32)
        key_file.write_text(new_key, encoding="utf-8")
        try:
            os.chmod(key_file, 0o600)
        except OSError:
            pass
        cls.SECRET_KEY = new_key
        return new_key


class ProdConfig(Config):
    """
    Конфигурация для продуктивной среды.
    1.1: COOKIE_SECURE=True по умолчанию.
    5.1: Fail-fast при отсутствии SECRET_KEY.
    """
    DEBUG = False
    TESTING = False

    # 1.1: Безопасные куки всегда True, отключение только через ALLOW_INSECURE_COOKIES=1
    COOKIE_SECURE = not Config.ALLOW_INSECURE_COOKIES
    SESSION_COOKIE_SECURE = COOKIE_SECURE

    @classmethod
    def ensure_secret_key(cls) -> str:
        if cls.SECRET_KEY:
            return cls.SECRET_KEY

        key_file = cls.INSTANCE_DIR / "secret.key"
        if key_file.exists():
            cls.SECRET_KEY = key_file.read_text(encoding="utf-8").strip()
            return cls.SECRET_KEY

        raise RuntimeError(
            "КРИТИЧЕСКАЯ ОШИБКА БЕЗОПАСНОСТИ (пункт 5.1): "
            "В продуктивной конфигурации ProdConfig требуется явно задать переменную окружения SECRET_KEY!"
        )


class DevConfig(Config):
    """Конфигурация для локальной разработки."""
    DEBUG = True
    TESTING = False
    # В dev-режиме куки по HTTP разрешены
    COOKIE_SECURE = False
    SESSION_COOKIE_SECURE = False


class TestConfig(Config):
    """Конфигурация для изолированных автоматических тестов."""
    DEBUG = False
    TESTING = True
    DATABASE = ":memory:"
    SECRET_KEY = "test-static-secret-key-32-bytes-long!!"
    SEED_DEMO = False
    TRUSTED_HOSTS = []
    COOKIE_SECURE = False
    SESSION_COOKIE_SECURE = False
