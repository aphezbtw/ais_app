"""
Пакет маршрутов АИС «Заявки» v2.
"""
from app.routes.auth import auth_bp
from app.routes.tickets import tickets_bp
from app.routes.reports import reports_bp
from app.routes.system import system_bp

__all__ = ["auth_bp", "tickets_bp", "reports_bp", "system_bp"]
