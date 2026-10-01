"""
Модуль централизованной настройки логирования АИС «Заявки» v2 (пункты 1.3, 5.5).
"""
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

def configure_logging(app):
    log_level_name = app.config.get("LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_name, logging.INFO)
    formatter = logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s")

    handlers = []
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)
    handlers.append(console_handler)

    try:
        log_path = Path(app.config["LOG_FILE"])
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(str(log_path), maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
        file_handler.setFormatter(formatter)
        file_handler.setLevel(log_level)
        handlers.append(file_handler)
    except Exception as e:
        sys.stderr.write(f"Предупреждение: Не удалось инициализировать лог-файл: {e}\n")

    for log_obj in [logging.getLogger(), logging.getLogger("ais_zayavki"), app.logger]:
        log_obj.setLevel(log_level)
        log_obj.handlers.clear()
        for h in handlers:
            log_obj.addHandler(h)
