"""
Системные эндпоинты (healthcheck, готовность сервиса к оркестрации).
Закрывает замечания аудита:
2.2 — Безопасный /healthz без утечки текста исключений клиенту.
"""
from datetime import datetime, timezone
import logging
from flask import Blueprint, jsonify
from app.db import get_db

logger = logging.getLogger("ais_zayavki")
system_bp = Blueprint("system", __name__)


@system_bp.route("/healthz")
def healthz():
    """
    Проверка жизнеспособности сервиса для оркестраторов (systemd, Docker, Kubernetes).
    Проверяет доступность базы данных SQLite.
    Пункт 2.2: Не отдаёт текст ошибки в HTTP-ответе (только в лог).
    """
    db = get_db()
    try:
        db.execute("SELECT 1").fetchone()
        return jsonify(
            {
                "status": "ok",
                "database": "healthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ), 200
    except Exception as err:
        logger.error(f"Healthcheck failed: {err}", exc_info=True)
        return jsonify(
            {
                "status": "error",
                "database": "unhealthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ), 503
