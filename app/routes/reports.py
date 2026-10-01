"""
Маршруты аналитических отчётов для специалистов поддержки.
"""
from flask import Blueprint, g, render_template
from app.constants import PRIORITY_LABELS, STATUS_LABELS
from app.db import get_db
from app.security import agent_required
from app.services import get_report_statistics

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/report")
@agent_required
def report():
    """Сводный отчёт по нагрузке, статусам и соблюдению регламента SLA."""
    db = get_db()
    stats = get_report_statistics(db)
    return render_template(
        "reports/report.html",
        stats=stats,
        status_labels=STATUS_LABELS,
        priority_labels=PRIORITY_LABELS,
    )
