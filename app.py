"""
Точка входа приложения АИС «Заявки» v2.
Поддерживает запуск напрямую (python app.py) и через WSGI-серверы (gunicorn, uwsgi).
Закрывает замечания аудита:
1.1 — Поддержка ProdConfig и DevConfig с безопасными параметрами.
1.4 — Сетевые настройки (порт 5000 по умолчанию).
"""
import os
from app import create_app
from app.config import DevConfig, ProdConfig

is_prod = os.environ.get("FLASK_ENV") == "production" or os.environ.get("ENV") == "production"
selected_config = ProdConfig if is_prod else DevConfig

# Экземпляр WSGI-приложения
app = create_app(selected_config)

if __name__ == "__main__":
    host = app.config.get("HOST", "0.0.0.0")
    port = app.config.get("PORT", 5000)
    debug = app.config.get("DEBUG", False)
    print(f"[*] Запуск АИС «Заявки» v2 на http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)
