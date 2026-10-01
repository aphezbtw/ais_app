"""
Маршруты управления заявками: реестр, создание, просмотр,
смена статуса, назначение исполнителя, комментирование, удаление.
Закрывает замечания аудита:
1.4 & 1.5 — 404 вместо 403 при доступе к чужой заявке (get_ticket_for_user_or_404).
2.1 — Безопасный поиск с экранированием LIKE.
3.2 — Поддержка шаблонов примеров TICKET_EXAMPLES в add.html.
3.5 — Чистые импорты без лишних зависимостей.
3.7 — Soft delete и корзина удалённых заявок для специалистов поддержки.
"""
import math
from flask import (
    Blueprint,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)
from app.constants import (
    ALL_PRIORITIES,
    ALL_STATUSES,
    DEFAULT_PAGE_SIZE,
    PRIORITY_LABELS,
    PRIORITY_NORMAL,
    RATE_LIMIT_COMMENT,
    RATE_LIMIT_TICKET,
    ROLE_AGENT,
    STATUS_LABELS,
)
from app.db import get_db
from app.security import (
    agent_required,
    check_rate_limit,
    login_required,
)
from app.services import (
    add_ticket_comment,
    assign_ticket,
    create_ticket,
    delete_ticket,
    get_support_agents,
    get_ticket_events,
    get_ticket_for_user_or_404,
    list_tickets,
    update_ticket_status,
)

try:
    from examples import TICKET_EXAMPLES
except ImportError:
    TICKET_EXAMPLES = []

tickets_bp = Blueprint("tickets", __name__)


@tickets_bp.route("/")
@login_required
def index():
    """
    Реестр заявок с серверной фильтрацией и пагинацией (пункт 2.10).
    """
    db = get_db()
    search_q = request.args.get("q", "").strip()
    status_filter = request.args.get("status", "").strip()
    priority_filter = request.args.get("priority", "").strip()

    try:
        page = int(request.args.get("page", 1))
    except ValueError:
        page = 1

    page_size = DEFAULT_PAGE_SIZE
    tickets, total_count = list_tickets(
        db,
        current_user=g.current_user,
        search_query=search_q,
        status_filter=status_filter,
        priority_filter=priority_filter,
        page=page,
        page_size=page_size,
    )

    total_pages = max(1, math.ceil(total_count / page_size))

    return render_template(
        "tickets/index.html",
        tickets=tickets,
        total_count=total_count,
        page=page,
        total_pages=total_pages,
        search_query=search_q,
        selected_status=status_filter,
        selected_priority=priority_filter,
        status_labels=STATUS_LABELS,
        priority_labels=PRIORITY_LABELS,
        all_statuses=ALL_STATUSES,
        all_priorities=ALL_PRIORITIES,
    )


@tickets_bp.route("/zayavka/add", methods=["GET", "POST"])
@tickets_bp.route("/add", methods=["GET", "POST"])
@login_required
def add():
    """
    Создание новой заявки с защитой от флуда (2.11), серверной валидацией (2.9)
    и поддержкой шаблонов примеров (3.2).
    """
    db = get_db()
    if request.method == "POST":
        limit, window = RATE_LIMIT_TICKET
        user_ident = f"user_{g.current_user['id']}"
        if not check_rate_limit(db, "ticket", user_ident, limit, window):
            flash("Слишком много заявок за короткий промежуток времени. Пожалуйста, подождите минуту.", "danger")
            return render_template(
                "tickets/add.html",
                all_priorities=ALL_PRIORITIES,
                priority_labels=PRIORITY_LABELS,
                ticket_examples=TICKET_EXAMPLES,
            ), 429

        subject = request.form.get("subject", "")
        description = request.form.get("description", "")
        priority = request.form.get("priority", PRIORITY_NORMAL)

        try:
            ticket_id = create_ticket(
                db,
                author_id=g.current_user["id"],
                subject=subject,
                description=description,
                priority=priority,
            )
            flash("Заявка успешно зарегистрирована.", "success")
            return redirect(url_for("tickets.view", ticket_id=ticket_id))
        except ValueError as err:
            flash(str(err), "danger")
            return render_template(
                "tickets/add.html",
                all_priorities=ALL_PRIORITIES,
                priority_labels=PRIORITY_LABELS,
                form_subject=subject,
                form_description=description,
                form_priority=priority,
                ticket_examples=TICKET_EXAMPLES,
            ), 400

    return render_template(
        "tickets/add.html",
        all_priorities=ALL_PRIORITIES,
        priority_labels=PRIORITY_LABELS,
        ticket_examples=TICKET_EXAMPLES,
    )


@tickets_bp.route("/zayavka/<int:ticket_id>")
@tickets_bp.route("/ticket/<int:ticket_id>")
@login_required
def view(ticket_id: int):
    """
    Просмотр деталей заявки с защитой от перечисления ID (пункты 1.4, 1.5).
    Чужая или удалённая заявка всегда возвращает 404.
    """
    db = get_db()
    ticket = get_ticket_for_user_or_404(db, ticket_id, g.current_user, write=False)

    is_agent = g.current_user["role"] == ROLE_AGENT
    events = get_ticket_events(db, ticket_id)
    agents = get_support_agents(db) if is_agent else []

    return render_template(
        "tickets/view.html",
        ticket=ticket,
        events=events,
        agents=agents,
        is_agent=is_agent,
        status_labels=STATUS_LABELS,
        priority_labels=PRIORITY_LABELS,
        all_statuses=ALL_STATUSES,
    )


@tickets_bp.route("/zayavka/<int:ticket_id>/status", methods=["POST"])
@tickets_bp.route("/ticket/<int:ticket_id>/status", methods=["POST"])
@login_required
def update_status(ticket_id: int):
    """Смена статуса заявки с проверкой прав доступа (1.4, 1.5)."""
    db = get_db()
    # Проверяем доступ к заявке: чужая заявка отдаст 404 (пункт 1.4)
    get_ticket_for_user_or_404(db, ticket_id, g.current_user, write=True)

    new_status = request.form.get("status", "")
    is_agent = g.current_user["role"] == ROLE_AGENT

    try:
        update_ticket_status(db, ticket_id, new_status, g.current_user["id"], is_agent)
        flash("Статус заявки обновлён.", "success")
    except (ValueError, KeyError) as err:
        flash(str(err), "danger")
    except PermissionError as err:
        flash(str(err), "danger")
        abort(403)

    return redirect(url_for("tickets.view", ticket_id=ticket_id))


@tickets_bp.route("/zayavka/<int:ticket_id>/assign", methods=["POST"])
@tickets_bp.route("/ticket/<int:ticket_id>/assign", methods=["POST"])
@agent_required
def assign(ticket_id: int):
    """Назначение ответственного специалиста поддержки (доступно только агентам)."""
    db = get_db()
    get_ticket_for_user_or_404(db, ticket_id, g.current_user, write=True)

    raw_assignee = request.form.get("assignee_id")
    assignee_id = int(raw_assignee) if raw_assignee and raw_assignee.isdigit() else None

    try:
        assign_ticket(db, ticket_id, assignee_id, g.current_user["id"])
        flash("Исполнитель успешно назначен.", "success")
    except (ValueError, KeyError) as err:
        flash(str(err), "danger")

    return redirect(url_for("tickets.view", ticket_id=ticket_id))


@tickets_bp.route("/zayavka/<int:ticket_id>/comment", methods=["POST"])
@tickets_bp.route("/ticket/<int:ticket_id>/comment", methods=["POST"])
@login_required
def add_comment(ticket_id: int):
    """Добавление комментария к заявке с защитой от спама и контролем владения (1.4, 2.11)."""
    db = get_db()
    # Чужая заявка отдаёт 404 (пункт 1.4)
    get_ticket_for_user_or_404(db, ticket_id, g.current_user, write=True)

    limit, window = RATE_LIMIT_COMMENT
    user_ident = f"user_{g.current_user['id']}"
    if not check_rate_limit(db, "comment", user_ident, limit, window):
        flash("Слишком много комментариев. Пожалуйста, подождите перед следующим сообщением.", "danger")
        return redirect(url_for("tickets.view", ticket_id=ticket_id))

    comment_text = request.form.get("comment", "")
    try:
        add_ticket_comment(db, ticket_id, g.current_user["id"], comment_text)
        flash("Комментарий успешно добавлен.", "success")
    except ValueError as err:
        flash(str(err), "danger")

    return redirect(url_for("tickets.view", ticket_id=ticket_id))


@tickets_bp.route("/zayavka/<int:ticket_id>/delete", methods=["GET", "POST"])
@tickets_bp.route("/ticket/<int:ticket_id>/delete", methods=["GET", "POST"])
@agent_required
def delete(ticket_id: int):
    """Удаление заявки (soft delete) с подтверждением и записью в аудит-журнал (пункты 3.7, 6.4)."""
    db = get_db()
    ticket = get_ticket_for_user_or_404(db, ticket_id, g.current_user, write=True)

    if request.method == "POST":
        confirm = request.form.get("confirm")
        if confirm not in ("yes", "1", "true", "on"):
            flash("Подтвердите удаление заявки, установив флажок.", "warning")
            return render_template("tickets/delete_confirm.html", ticket=ticket), 200

        delete_ticket(db, ticket_id, g.current_user["id"])
        flash(f"Заявка #{ticket_id} перемещена в архив удалённых.", "info")
        return redirect(url_for("tickets.index"))

    return render_template("tickets/delete_confirm.html", ticket=ticket)
