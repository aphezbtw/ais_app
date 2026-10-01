"""
Регистрация централизованных обработчиков ошибок HTTP и СУБД (пункты 2.6, 3.4, 5.6).
"""
import sqlite3
from flask import render_template

def register_error_handlers(app):
    @app.errorhandler(400)
    def bad_request(error):
        return render_template("errors/400.html", error=error), 400

    @app.errorhandler(403)
    def forbidden(error):
        return render_template("errors/403.html", error=error), 403

    @app.errorhandler(404)
    def not_found(error):
        return render_template("errors/404.html", error=error), 404

    @app.errorhandler(sqlite3.OperationalError)
    def db_operational_error(error):
        app.logger.error(f"Ошибка СУБД SQLite (OperationalError): {error}", exc_info=True)
        return render_template("errors/500.html", error="База данных временно недоступна. Попробуйте позже."), 500

    @app.errorhandler(Exception)
    def internal_error(error):
        app.logger.error(f"Необработанное исключение приложения: {error}", exc_info=True)
        return render_template("errors/500.html", error="Внутренняя ошибка сервера. Администраторы уведомлены."), 500
