"""
Фабрика приложений Flask АИС «Заявки» v2 (пункты 3.1, 3.4).
Чистая модульная композиция сервисов, middleware, обработчиков и маршрутов.
"""
try:
    from flask import Flask
    FLASK_AVAILABLE = True
except ImportError:
    Flask = None
    FLASK_AVAILABLE = False

from app.config import Config, ProdConfig
from app.db import close_db, init_db


def create_app(config_class=None):
    """
    Фабрика приложения (Application Factory) (пункты 3.1, 3.4).
    """
    if not FLASK_AVAILABLE:
        raise RuntimeError("Пакет Flask не установлен. Установите зависимости: pip install -r requirements.txt")

    from app.errors import register_error_handlers
    from app.jinja import register_jinja
    from app.logging_setup import configure_logging
    from app.middleware import register_middleware
    from app.routes import auth_bp, reports_bp, system_bp, tickets_bp

    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static",
    )

    if config_class is None:
        config_class = ProdConfig
    app.config.from_object(config_class)

    # Гарантируем наличие SECRET_KEY с безопасными правами доступа
    app.secret_key = app.config.get("SECRET_KEY") or config_class.ensure_secret_key()
    app.config["SECRET_KEY"] = app.secret_key

    # Пункт 1.1: Проверка безопасности COOKIE_SECURE в продакшене (fail-fast)
    if issubclass(config_class, ProdConfig) and not app.config.get("COOKIE_SECURE") and not app.config.get("ALLOW_INSECURE_COOKIES") and not app.config.get("TESTING"):
        raise RuntimeError(
            "КРИТИЧЕСКАЯ ОШИБКА БЕЗОПАСНОСТИ (пункт 1.1): "
            "В ProdConfig COOKIE_SECURE=1 обязателен! Для локальной отладки без HTTPS используйте ALLOW_INSECURE_COOKIES=1 или DevConfig."
        )

    # Централизованные модули конфигурации приложения (пункт 3.4)
    configure_logging(app)
    app.teardown_appcontext(close_db)

    with app.app_context():
        init_db(app)

    register_middleware(app)
    register_error_handlers(app)
    register_jinja(app)

    # Регистрация Blueprints
    app.register_blueprint(system_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(tickets_bp)
    app.register_blueprint(reports_bp)

    return app
