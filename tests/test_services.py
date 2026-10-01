"""
Модульные тесты сервисного слоя и бизнес-логики (пункт 4.1).
Тестирует CRUD заявок, разграничение прав доступа, фильтрацию,
пагинацию в SQL (2.10), экранирование LIKE (2.1), soft delete (3.7) и аудит-лог (6.4).
"""
import sqlite3
import unittest
from datetime import datetime, timezone

from app.constants import (
    COMMENT_MAX_LEN,
    PRIORITY_CRITICAL,
    PRIORITY_HIGH,
    PRIORITY_LOW,
    PRIORITY_NORMAL,
    ROLE_AGENT,
    ROLE_USER,
    STATUS_CLOSED,
    STATUS_IN_PROGRESS,
    STATUS_NEW,
    STATUS_RESOLVED,
)
from app.db import run_migrations
from app.security import hash_password
from app.services import (
    add_ticket_comment,
    assign_ticket,
    create_ticket,
    delete_ticket,
    get_report_statistics,
    get_ticket_by_id,
    get_ticket_events,
    get_ticket_for_user,
    list_tickets,
    update_ticket_status,
)


class TestServices(unittest.TestCase):
    """Тестирование бизнес-логики в app.services."""

    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON;")
        run_migrations(self.conn)

        now_str = datetime.now(timezone.utc).isoformat()
        cur = self.conn.cursor()
        p_hash = hash_password("pass123")

        cur.execute(
            """INSERT INTO users (username, password_hash, role, created_at, updated_at)
               VALUES ('user1', ?, ?, ?, ?)""",
            (p_hash, ROLE_USER, now_str, now_str),
        )
        self.user1 = {"id": cur.lastrowid, "username": "user1", "role": ROLE_USER}

        cur.execute(
            """INSERT INTO users (username, password_hash, role, created_at, updated_at)
               VALUES ('user2', ?, ?, ?, ?)""",
            (p_hash, ROLE_USER, now_str, now_str),
        )
        self.user2 = {"id": cur.lastrowid, "username": "user2", "role": ROLE_USER}

        cur.execute(
            """INSERT INTO users (username, password_hash, role, created_at, updated_at)
               VALUES ('agent1', ?, ?, ?, ?)""",
            (p_hash, ROLE_AGENT, now_str, now_str),
        )
        self.agent1 = {"id": cur.lastrowid, "username": "agent1", "role": ROLE_AGENT}
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def test_create_ticket_validation(self):
        # Проверка минимальной длины темы (<3)
        with self.assertRaises(ValueError):
            create_ticket(self.conn, self.user1["id"], "AB", "Подробное описание проблемы")

        # Проверка максимальной длины темы (>200)
        with self.assertRaises(ValueError):
            create_ticket(self.conn, self.user1["id"], "A" * 201, "Подробное описание проблемы")

        # Проверка максимальной длины описания (>4000)
        with self.assertRaises(ValueError):
            create_ticket(self.conn, self.user1["id"], "Корректная тема", "A" * 4001)

        # Успешное создание
        t_id = create_ticket(
            self.conn, self.user1["id"], "Проблема с печатью", "Принтер не реагирует на команды", PRIORITY_HIGH
        )
        self.assertIsInstance(t_id, int)
        ticket = get_ticket_by_id(self.conn, t_id)
        self.assertEqual(ticket["subject"], "Проблема с печатью")
        self.assertEqual(ticket["priority"], PRIORITY_HIGH)
        self.assertEqual(ticket["status"], STATUS_NEW)

    def test_list_tickets_rbac_and_sql_search(self):
        t1 = create_ticket(self.conn, self.user1["id"], "Почта не отправляет", "Текст 1", PRIORITY_NORMAL)
        t2 = create_ticket(self.conn, self.user1["id"], "Сеть недоступна", "Текст 2", PRIORITY_LOW)
        t3 = create_ticket(self.conn, self.user2["id"], "1С зависает", "Текст 3", PRIORITY_HIGH)

        user1_tickets, count1 = list_tickets(self.conn, self.user1)
        self.assertEqual(count1, 2)
        ticket_ids_user1 = {t["id"] for t in user1_tickets}
        self.assertIn(t1, ticket_ids_user1)
        self.assertIn(t2, ticket_ids_user1)
        self.assertNotIn(t3, ticket_ids_user1)

        agent_tickets, count_all = list_tickets(self.conn, self.agent1)
        self.assertEqual(count_all, 3)

        # Поиск по SQL (q='Почта')
        search_res, s_count = list_tickets(self.conn, self.agent1, search_query="Почта")
        self.assertEqual(s_count, 1)
        self.assertEqual(search_res[0]["id"], t1)

    def test_like_escaping(self):
        # 2.1: Проверка экранирования специальных символов LIKE (%, _)
        t1 = create_ticket(self.conn, self.user1["id"], "100% скидка", "Описание 1")
        t2 = create_ticket(self.conn, self.user1["id"], "1000 скидка", "Описание 2")

        # Поиск по точному значению '100%' должен вернуть только t1, а не t2!
        results, count = list_tickets(self.conn, self.agent1, search_query="100%")
        self.assertEqual(count, 1)
        self.assertEqual(results[0]["id"], t1)

    def test_list_tickets_pagination_boundaries(self):
        # Граничные значения пагинации: page=0, page=999
        create_ticket(self.conn, self.user1["id"], "Заявка 1", "Описание 1")
        rows_p0, count = list_tickets(self.conn, self.agent1, page=0)
        self.assertEqual(len(rows_p0), 1)

        rows_p999, count999 = list_tickets(self.conn, self.agent1, page=999)
        self.assertEqual(len(rows_p999), 0)
        self.assertEqual(count999, 1)

    def test_update_ticket_status_permissions(self):
        t_id = create_ticket(self.conn, self.user1["id"], "Тестовая заявка", "Описание заявки")

        update_ticket_status(self.conn, t_id, STATUS_IN_PROGRESS, self.agent1["id"], is_agent=True)
        ticket = get_ticket_by_id(self.conn, t_id)
        self.assertEqual(ticket["status"], STATUS_IN_PROGRESS)

        with self.assertRaises(PermissionError):
            update_ticket_status(self.conn, t_id, STATUS_NEW, self.user1["id"], is_agent=False)

        update_ticket_status(self.conn, t_id, STATUS_CLOSED, self.user1["id"], is_agent=False)
        ticket = get_ticket_by_id(self.conn, t_id)
        self.assertEqual(ticket["status"], STATUS_CLOSED)

    def test_assign_ticket_only_agent(self):
        t_id = create_ticket(self.conn, self.user1["id"], "Тестовая заявка", "Описание заявки")

        # Назначение на обычного пользователя должно вызывать ошибку
        with self.assertRaises(ValueError):
            assign_ticket(self.conn, t_id, self.user2["id"], self.agent1["id"])

        assign_ticket(self.conn, t_id, self.agent1["id"], self.agent1["id"])
        ticket = get_ticket_by_id(self.conn, t_id)
        self.assertEqual(ticket["assignee_id"], self.agent1["id"])

    def test_add_comment_validation(self):
        t_id = create_ticket(self.conn, self.user1["id"], "Тестовая заявка", "Описание заявки")

        # Пустой комментарий
        with self.assertRaises(ValueError):
            add_ticket_comment(self.conn, t_id, self.user1["id"], "")

        # Превышение лимита символов (>2000)
        with self.assertRaises(ValueError):
            add_ticket_comment(self.conn, t_id, self.user1["id"], "X" * (COMMENT_MAX_LEN + 1))

        # Корректный комментарий
        add_ticket_comment(self.conn, t_id, self.user1["id"], "Уточняю детали проблемы.")
        events = get_ticket_events(self.conn, t_id)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[1]["details"], "Уточняю детали проблемы.")

    def test_soft_delete_and_audit_log(self):
        # 3.7: Soft delete заявки
        t_id = create_ticket(self.conn, self.user1["id"], "Удаляемая заявка", "Описание для восстановления")
        delete_ticket(self.conn, t_id, self.agent1["id"])

        # Заявка не возвращается обычными выборками
        self.assertIsNone(get_ticket_by_id(self.conn, t_id))
        self.assertIsNone(get_ticket_for_user(self.conn, t_id, self.agent1))

        # Заявка присутствует с флагом deleted_at
        cur = self.conn.cursor()
        cur.execute("SELECT deleted_at, deleted_by FROM zayavki WHERE id = ?", (t_id,))
        row = cur.fetchone()
        self.assertIsNotNone(row["deleted_at"])
        self.assertEqual(row["deleted_by"], self.agent1["id"])

        # Запись в аудит-журнале deleted_log
        cur.execute("SELECT * FROM deleted_log WHERE zayavka_id = ?", (t_id,))
        log_entry = cur.fetchone()
        self.assertIsNotNone(log_entry)
        self.assertEqual(log_entry["ticket_subject"], "Удаляемая заявка")
        self.assertEqual(log_entry["deleted_by"], self.agent1["id"])

    def test_get_ticket_for_user_enumeration_protection(self):
        # 1.4 & 1.5: Защита от перечисления ID
        t_user1 = create_ticket(self.conn, self.user1["id"], "Заявка 1", "Описание")

        # user1 видит свою заявку
        self.assertIsNotNone(get_ticket_for_user(self.conn, t_user1, self.user1))

        # user2 НЕ видит заявку user1 (получает None -> 404, а не 403)
        self.assertIsNone(get_ticket_for_user(self.conn, t_user1, self.user2))

        # agent видит любую заявку
        self.assertIsNotNone(get_ticket_for_user(self.conn, t_user1, self.agent1))


if __name__ == "__main__":
    unittest.main()
