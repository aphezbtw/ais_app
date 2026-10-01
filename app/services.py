"""
Сервисный слой бизнес-логики АИС «Заявки» v2.
Изолированные функции без привязки к HTTP-контексту (пункт 3.2).
Закрывает замечания аудита:
1.2 — log_auth_event для аудита аутентификации.
1.4 & 1.5 — get_ticket_for_user и get_ticket_for_user_or_404 для защиты от перечисления ID (404).
1.6 — Транзакционность write-операций (BEGIN IMMEDIATE).
2.1 — Экранирование LIKE-wildcard'ов (_escape_like).
3.3 — Бизнес-логика register_user и authenticate в сервисном слое.
3.7 — Soft delete (пометка deleted_at) и ведение deleted_log.
3.8 — Безопасный парсинг дат parse_iso_dt без широкого except Exception.
"""
import logging
import math
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.constants import (
    ALL_PRIORITIES,
    ALL_STATUSES,
    COMMENT_MAX_LEN,
    COMMENT_MIN_LEN,
    DEFAULT_PAGE_SIZE,
    DESCRIPTION_MAX_LEN,
    DESCRIPTION_MIN_LEN,
    DUMMY_PASSWORD_HASH,
    MAX_PAGE_SIZE,
    PASSWORD_MAX_LEN,
    PASSWORD_MIN_LEN,
    PRIORITY_LABELS,
    PRIORITY_NORMAL,
    ROLE_AGENT,
    ROLE_USER,
    SLA_HOURS,
    STATUS_CLOSED,
    STATUS_IN_PROGRESS,
    STATUS_LABELS,
    STATUS_NEW,
    STATUS_RESOLVED,
    SUBJECT_MAX_LEN,
    SUBJECT_MIN_LEN,
    USERNAME_MAX_LEN,
    USERNAME_MIN_LEN,
)
from app.db import get_db
from app.security import (
    hash_identifier,
    hash_password,
    sanitize_log_message,
    verify_password,
)

logger = logging.getLogger("ais_zayavki")

try:
    from flask import abort
except ImportError:
    def abort(code, description=""):
        if code == 404:
            raise KeyError(description or "Not found")
        elif code == 403:
            raise PermissionError(description or "Forbidden")
        raise RuntimeError(f"HTTP {code}: {description}")


# 1.2: Аудит событий авторизации
def log_auth_event(action: str, user_id: Optional[int] = None, ip_hash: Optional[str] = None, username_hash: Optional[str] = None):
    """
    Записывает аудит-события аутентификации (пункт 1.2).
    Не сохраняет логины в открытом виде при неудачах (защита PII).
    """
    u_part = f"user_id={user_id}" if user_id is not None else f"user_hash={username_hash}"
    ip_part = f"ip_hash={ip_hash}" if ip_hash is not None else ""
    msg = sanitize_log_message(f"AUTH_AUDIT | Action: {action} | {u_part} | {ip_part}")
    logger.info(msg)


# 2.1: Экранирование спецсимволов LIKE
def _escape_like(val: str) -> str:
    """Экранирует специальные символы %, _ и обратный слеш для SQL LIKE (пункт 2.1)."""
    return val.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# 3.8: Безопасный парсинг дат
def parse_iso_dt(dt_val: Any) -> Optional[datetime]:
    """Парсит ISO-строку даты. При ошибке формата логирует warning и возвращает None."""
    if not dt_val:
        return None
    if isinstance(dt_val, datetime):
        return dt_val
    try:
        s = str(dt_val).replace("Z", "+00:00")
        return datetime.fromisoformat(s)
    except (ValueError, TypeError) as err:
        logger.warning(f"Ошибка парсинга даты '{dt_val}': {err}")
        return None


# 3.4: Расчёт SLA
def sla_deadline(ticket_row: dict) -> datetime:
    """
    Канонический расчёт дедлайна заявки по SLA (пункт 3.4).
    Дедлайн = created_at + норматив часов по приоритету.
    """
    created_val = ticket_row.get("created_at")
    created = parse_iso_dt(created_val)
    if created is None:
        created = datetime.now(timezone.utc)

    prio = ticket_row.get("priority", PRIORITY_NORMAL)
    hours = SLA_HOURS.get(prio)
    if hours is None:
        # Fallback для русских наименований
        hours = {"Высокий": 24, "Средний": 72, "Низкий": 168}.get(prio, 72)

    return created + timedelta(hours=hours)


def is_overdue(ticket_row: dict) -> bool:
    """
    Проверяет, просрочена ли заявка по SLA (пункт 3.4).
    Завершённые заявки (resolved, closed, Закрыта) не считаются просроченными.
    """
    status = ticket_row.get("status")
    if status in (STATUS_RESOLVED, STATUS_CLOSED, "resolved", "closed", "Закрыта"):
        return False

    deadline = sla_deadline(ticket_row)
    now = datetime.now(timezone.utc) if deadline.tzinfo is not None else datetime.now()
    return now > deadline


def get_sla_info(ticket_row: dict) -> dict:
    """Возвращает структурированную информацию об SLA для шаблона."""
    status = ticket_row.get("status")
    is_completed = status in (STATUS_RESOLVED, STATUS_CLOSED, "resolved", "closed", "Закрыта")
    deadline = sla_deadline(ticket_row)
    now = datetime.now(timezone.utc) if deadline.tzinfo is not None else datetime.now()

    if is_completed:
        return {
            "deadline": deadline,
            "is_completed": True,
            "is_overdue": False,
            "formatted_text": "Решено",
        }

    overdue = now > deadline
    if overdue:
        diff = now - deadline
        hrs = int(diff.total_seconds() // 3600)
        text = f"Просрочено на {hrs} ч."
    else:
        diff = deadline - now
        hrs = max(0, int(diff.total_seconds() // 3600))
        text = f"Осталось {hrs} ч."

    return {
        "deadline": deadline,
        "is_completed": False,
        "is_overdue": overdue,
        "formatted_text": text,
    }


def _enrich_ticket(row: dict) -> dict:
    """Добавляет SLA-структуру к словарю заявки."""
    d = dict(row)
    d["sla"] = get_sla_info(d)
    return d


# 3.3: Регистрация и аутентификация в сервисном слое
def register_user(conn, username: str, password: str) -> int:
    """
    Бизнес-логика создания пользователя (пункт 3.3).
    Все новые пользователи получают роль 'user' (1.1).
    """
    username = (username or "").strip()
    password = password or ""

    if not (USERNAME_MIN_LEN <= len(username) <= USERNAME_MAX_LEN):
        raise ValueError(f"Имя пользователя должно содержать от {USERNAME_MIN_LEN} до {USERNAME_MAX_LEN} символов.")
    if not (PASSWORD_MIN_LEN <= len(password) <= PASSWORD_MAX_LEN):
        raise ValueError(f"Пароль должен содержать от {PASSWORD_MIN_LEN} до {PASSWORD_MAX_LEN} символов.")

    p_hash = hash_password(password)
    now_str = datetime.now(timezone.utc).isoformat()

    conn.execute("BEGIN IMMEDIATE;")
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO users (username, password_hash, role, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?)""",
            (username, p_hash, ROLE_USER, now_str, now_str),
        )
        user_id = cur.lastrowid
        conn.commit()
        logger.info(f"USER_REGISTERED | user_id={user_id} | role={ROLE_USER}")
        return user_id
    except sqlite3.IntegrityError:
        conn.rollback()
        raise


def authenticate(conn, username: str, password: str) -> Optional[dict]:
    """
    Проверяет учётные данные пользователя с защитой от тайминг-атак (пункт 3.3).
    """
    username = (username or "").strip()
    password = password or ""

    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cur.fetchone()

    stored_hash = user["password_hash"] if user else DUMMY_PASSWORD_HASH
    is_valid = verify_password(stored_hash, password)

    if not user or not is_valid:
        return None

    return dict(user)


# 1.4 & 1.5: Единая точка доступа к заявке с защитой от перечисления ID (404)
def get_ticket_for_user(conn, ticket_id: int, user: dict, write: bool = False) -> Optional[dict]:
    """
    Единая точка проверки владения заявкой (пункт 1.5).
    Если заявка не найдена, удалена или принадлежит другому пользователю — возвращает None.
    Специалистам поддержки доступны все не удалённые заявки.
    """
    if not ticket_id or not user:
        return None

    cur = conn.cursor()
    cur.execute(
        """SELECT z.*,
                  u_author.username AS author_name,
                  u_assignee.username AS assignee_name
           FROM zayavki z
           JOIN users u_author ON z.author_id = u_author.id
           LEFT JOIN users u_assignee ON z.assignee_id = u_assignee.id
           WHERE z.id = ? AND z.deleted_at IS NULL""",
        (ticket_id,),
    )
    row = cur.fetchone()
    if not row:
        return None

    ticket = _enrich_ticket(row)

    # Агент видит всё
    if user.get("role") == ROLE_AGENT:
        return ticket

    # Обычный пользователь видит только свои
    if ticket["author_id"] == user.get("id"):
        return ticket

    # Для чужой заявки — None (защита от enumeration 1.4)
    return None


def get_ticket_for_user_or_404(conn, ticket_id: int, user: dict, write: bool = False) -> dict:
    """Возвращает заявку либо вызывает abort(404) (пункты 1.4, 1.5)."""
    ticket = get_ticket_for_user(conn, ticket_id, user, write=write)
    if not ticket:
        abort(404, description="Заявка не найдена.")
    return ticket


def get_ticket_by_id(conn, ticket_id: int, include_deleted: bool = False) -> Optional[dict]:
    """Получает заявку по ID (для тестов и внутреннего использования)."""
    cur = conn.cursor()
    where_del = "" if include_deleted else "AND z.deleted_at IS NULL"
    cur.execute(
        f"""SELECT z.*,
                  u_author.username AS author_name,
                  u_assignee.username AS assignee_name
           FROM zayavki z
           JOIN users u_author ON z.author_id = u_author.id
           LEFT JOIN users u_assignee ON z.assignee_id = u_assignee.id
           WHERE z.id = ? {where_del}""",
        (ticket_id,),
    )
    row = cur.fetchone()
    if row:
        return _enrich_ticket(row)
    return None


def list_tickets(
    conn,
    current_user: Dict[str, Any],
    search_query: str = "",
    status_filter: str = "",
    priority_filter: str = "",
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Выборка заявок с серверной фильтрацией, пагинацией и экранированием LIKE (пункты 2.1, 2.10, 3.7).
    """
    page = max(1, page)
    page_size = max(1, min(page_size, MAX_PAGE_SIZE))
    offset = (page - 1) * page_size

    where_clauses = ["z.deleted_at IS NULL"]
    params: List[Any] = []

    if current_user.get("role") != ROLE_AGENT:
        where_clauses.append("z.author_id = ?")
        params.append(current_user["id"])

    if status_filter and status_filter in ALL_STATUSES:
        where_clauses.append("z.status = ?")
        params.append(status_filter)

    if priority_filter and priority_filter in ALL_PRIORITIES:
        where_clauses.append("z.priority = ?")
        params.append(priority_filter)

    # 2.1: Экранирование LIKE с явным указанием ESCAPE '\'
    if search_query:
        escaped_q = f"%{_escape_like(search_query.strip())}%"
        where_clauses.append("(z.subject LIKE ? ESCAPE '\\' OR z.description LIKE ? ESCAPE '\\')")
        params.extend([escaped_q, escaped_q])

    where_str = "WHERE " + " AND ".join(where_clauses)

    count_sql = f"SELECT COUNT(*) FROM zayavki z {where_str}"
    cur = conn.cursor()
    cur.execute(count_sql, params)
    total_count = cur.fetchone()[0]

    select_sql = f"""
        SELECT z.*,
               u_author.username AS author_name,
               u_assignee.username AS assignee_name
        FROM zayavki z
        JOIN users u_author ON z.author_id = u_author.id
        LEFT JOIN users u_assignee ON z.assignee_id = u_assignee.id
        {where_str}
        ORDER BY z.id DESC
        LIMIT ? OFFSET ?
    """
    cur.execute(select_sql, list(params) + [page_size, offset])
    rows = cur.fetchall()

    return [_enrich_ticket(r) for r in rows], total_count


# 1.6: Транзакционное создание заявки
def create_ticket(
    conn,
    author_id: int,
    subject: str,
    description: str,
    priority: str = PRIORITY_NORMAL,
) -> int:
    """Создаёт новую заявку с валидацией и единой транзакцией (пункты 1.6, 2.9)."""
    subject = (subject or "").strip()
    description = (description or "").strip()

    if not (SUBJECT_MIN_LEN <= len(subject) <= SUBJECT_MAX_LEN):
        raise ValueError(f"Тема заявки должна содержать от {SUBJECT_MIN_LEN} до {SUBJECT_MAX_LEN} символов.")
    if not (DESCRIPTION_MIN_LEN <= len(description) <= DESCRIPTION_MAX_LEN):
        raise ValueError(f"Описание должно содержать от {DESCRIPTION_MIN_LEN} до {DESCRIPTION_MAX_LEN} символов.")
    if priority not in ALL_PRIORITIES:
        raise ValueError("Недопустимый приоритет заявки.")

    now_str = datetime.now(timezone.utc).isoformat()

    conn.execute("BEGIN IMMEDIATE;")
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO zayavki (subject, description, priority, status, author_id, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (subject, description, priority, STATUS_NEW, author_id, now_str, now_str),
        )
        ticket_id = cur.lastrowid

        cur.execute(
            """INSERT INTO events (zayavka_id, user_id, kind, text, created_at)
               VALUES (?, ?, 'created', 'Заявка зарегистрирована в системе', ?)""",
            (ticket_id, author_id, now_str),
        )
        conn.commit()
        logger.info(f"ACTION=CREATE_TICKET | ticket_id={ticket_id} | author_id={author_id}")
        return ticket_id
    except Exception:
        conn.rollback()
        raise


# 1.6 & 3.7: Транзакционное удаление (soft delete)
def delete_ticket(conn, ticket_id: int, user_id: int):
    """
    Soft delete заявки с записью в deleted_log в единой транзакции (пункты 1.6, 3.7).
    """
    cur = conn.cursor()
    cur.execute("SELECT subject, description FROM zayavki WHERE id = ? AND deleted_at IS NULL", (ticket_id,))
    ticket = cur.fetchone()
    if not ticket:
        raise KeyError("Заявка не найдена или уже удалена.")

    now_str = datetime.now(timezone.utc).isoformat()

    conn.execute("BEGIN IMMEDIATE;")
    try:
        # Устанавливаем soft delete флаг
        cur.execute(
            "UPDATE zayavki SET deleted_at = ?, deleted_by = ?, updated_at = ? WHERE id = ?",
            (now_str, user_id, now_str, ticket_id),
        )
        # Запись в аудит-журнал удалений
        cur.execute(
            """INSERT INTO deleted_log (zayavka_id, ticket_subject, ticket_description, deleted_by, deleted_at)
               VALUES (?, ?, ?, ?, ?)""",
            (ticket_id, ticket["subject"], ticket["description"], user_id, now_str),
        )
        conn.commit()
        logger.info(f"ACTION=DELETE_TICKET | ticket_id={ticket_id} | deleted_by={user_id}")
    except Exception:
        conn.rollback()
        raise


def update_ticket_status(conn, ticket_id: int, new_status: str, user_id: int, is_agent: bool):
    """Обновляет статус заявки с фиксацией в истории events."""
    if new_status not in ALL_STATUSES:
        raise ValueError("Недопустимый статус заявки.")

    # Обычный пользователь может только подтвердить закрытие
    if not is_agent and new_status not in (STATUS_CLOSED, STATUS_RESOLVED, "closed", "resolved", "Закрыта"):
        raise PermissionError("Пользователь может только подтвердить закрытие заявки.")

    cur = conn.cursor()
    cur.execute("SELECT status FROM zayavki WHERE id = ? AND deleted_at IS NULL", (ticket_id,))
    ticket = cur.fetchone()
    if not ticket:
        raise KeyError("Заявка не найдена.")

    old_status = ticket["status"]
    if old_status == new_status:
        return

    now_str = datetime.now(timezone.utc).isoformat()
    conn.execute("BEGIN IMMEDIATE;")
    try:
        cur.execute(
            "UPDATE zayavki SET status = ?, updated_at = ? WHERE id = ?",
            (new_status, now_str, ticket_id),
        )
        status_label = STATUS_LABELS.get(new_status, new_status)
        cur.execute(
            """INSERT INTO events (zayavka_id, user_id, kind, text, created_at)
               VALUES (?, ?, 'status', ?, ?)""",
            (ticket_id, user_id, f"Статус изменён на: {status_label}", now_str),
        )
        conn.commit()
        logger.info(f"ACTION=UPDATE_STATUS | ticket_id={ticket_id} | old={old_status} | new={new_status} | user_id={user_id}")
    except Exception:
        conn.rollback()
        raise


def assign_ticket(conn, ticket_id: int, assignee_id: Optional[int], user_id: int):
    """Назначает ответственного специалиста поддержки."""
    cur = conn.cursor()
    if assignee_id is not None:
        cur.execute("SELECT id, username, role FROM users WHERE id = ?", (assignee_id,))
        agent = cur.fetchone()
        if not agent or agent["role"] != ROLE_AGENT:
            raise ValueError("Назначить можно только специалиста поддержки.")
        assignee_name = agent["username"]
        details = f"Назначен исполнитель: {assignee_name}"
    else:
        details = "Исполнитель снят с заявки"

    now_str = datetime.now(timezone.utc).isoformat()
    conn.execute("BEGIN IMMEDIATE;")
    try:
        cur.execute(
            "UPDATE zayavki SET assignee_id = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL",
            (assignee_id, now_str, ticket_id),
        )
        if cur.rowcount == 0:
            raise KeyError("Заявка не найдена.")

        cur.execute(
            """INSERT INTO events (zayavka_id, user_id, kind, text, created_at)
               VALUES (?, ?, 'assign', ?, ?)""",
            (ticket_id, user_id, details, now_str),
        )
        conn.commit()
        logger.info(f"ACTION=ASSIGN_TICKET | ticket_id={ticket_id} | assignee_id={assignee_id} | by={user_id}")
    except Exception:
        conn.rollback()
        raise


def add_ticket_comment(conn, ticket_id: int, user_id: int, comment_text: str):
    """Добавляет комментарий к заявке с валидацией длины."""
    comment_text = (comment_text or "").strip()
    if not (COMMENT_MIN_LEN <= len(comment_text) <= COMMENT_MAX_LEN):
        raise ValueError(f"Комментарий должен содержать от {COMMENT_MIN_LEN} до {COMMENT_MAX_LEN} символов.")

    now_str = datetime.now(timezone.utc).isoformat()
    conn.execute("BEGIN IMMEDIATE;")
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM zayavki WHERE id = ? AND deleted_at IS NULL", (ticket_id,))
        if not cur.fetchone():
            raise KeyError("Заявка не найдена.")

        cur.execute(
            """INSERT INTO events (zayavka_id, user_id, kind, text, created_at)
               VALUES (?, ?, 'comment', ?, ?)""",
            (ticket_id, user_id, comment_text, now_str),
        )
        cur.execute("UPDATE zayavki SET updated_at = ? WHERE id = ?", (now_str, ticket_id))
        conn.commit()
        logger.info(f"ACTION=ADD_COMMENT | ticket_id={ticket_id} | user_id={user_id}")
    except Exception:
        conn.rollback()
        raise


def get_ticket_events(conn, ticket_id: int) -> List[dict]:
    """Возвращает хронологическую историю изменений и комментариев заявки."""
    cur = conn.cursor()
    cur.execute(
        """SELECT e.*, u.username, u.role, e.text AS details
           FROM events e
           JOIN users u ON e.user_id = u.id
           WHERE e.zayavka_id = ?
           ORDER BY e.id ASC""",
        (ticket_id,),
    )
    return [dict(r) for r in cur.fetchall()]


def get_support_agents(conn) -> List[dict]:
    """Возвращает список всех специалистов поддержки."""
    cur = conn.cursor()
    cur.execute("SELECT id, username FROM users WHERE role = ? ORDER BY username ASC", (ROLE_AGENT,))
    return [dict(r) for r in cur.fetchall()]


def get_report_statistics(conn) -> dict:
    """Формирует статистику для сводного отчёта специалистов поддержки."""
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM zayavki WHERE deleted_at IS NULL")
    total_tickets = cur.fetchone()[0]

    cur.execute(
        """SELECT status, COUNT(*) AS count
           FROM zayavki WHERE deleted_at IS NULL
           GROUP BY status"""
    )
    status_counts = {r["status"]: r["count"] for r in cur.fetchall()}

    cur.execute(
        """SELECT priority, COUNT(*) AS count
           FROM zayavki WHERE deleted_at IS NULL
           GROUP BY priority"""
    )
    priority_counts = {r["priority"]: r["count"] for r in cur.fetchall()}

    cur.execute("SELECT priority, status, created_at FROM zayavki WHERE deleted_at IS NULL")
    all_tickets = [dict(r) for r in cur.fetchall()]
    overdue_count = sum(1 for t in all_tickets if is_overdue(t))

    return {
        "total_tickets": total_tickets,
        "status_counts": status_counts,
        "priority_counts": priority_counts,
        "overdue_count": overdue_count,
    }
