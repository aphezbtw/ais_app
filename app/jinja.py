"""
Регистрация глобальных переменных контекста и фильтров шаблонизатора Jinja2 (пункты 3.4, 8.2).
"""
from flask import g
from app.constants import ALL_PRIORITIES, ALL_STATUSES, PRIORITY_LABELS, STATUS_LABELS
from app.security import generate_csrf_token
from app.services import is_overdue, parse_iso_dt, sla_deadline

def register_jinja(app):
    @app.template_filter("format_dt")
    def format_dt_filter(dt_val) -> str:
        if not dt_val:
            return ""
        dt = parse_iso_dt(dt_val)
        if dt is None:
            return str(dt_val)[:16]
        return dt.strftime("%d.%m.%Y %H:%M")

    app.jinja_env.filters["is_overdue"] = is_overdue
    app.jinja_env.filters["deadline_of"] = sla_deadline

    @app.context_processor
    def inject_template_globals():
        return {
            "current_user": getattr(g, "current_user", None),
            "csrf_token": generate_csrf_token,
            "seed_demo_enabled": app.config.get("SEED_DEMO", False),
            "all_statuses": ALL_STATUSES,
            "all_priorities": ALL_PRIORITIES,
            "status_labels": STATUS_LABELS,
            "priority_labels": PRIORITY_LABELS,
        }
