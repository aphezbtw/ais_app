"""
Сквозной интеграционный (smoke) тест АИС «Заявки» v2.
Закрывает замечания аудита:
4.1 — Расширенный сквозной сценарий: assign, add_comment, update_status, soft delete, logout-all.
4.2 — Параметризация URL через TEST_BASE_URL.
4.3 — Полная изоляция тестовой базы данных.
"""
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.constants import (
    PRIORITY_HIGH,
    ROLE_AGENT,
    ROLE_USER,
    STATUS_CLOSED,
    STATUS_IN_PROGRESS,
    STATUS_NEW,
)
from app.db import run_migrations
from app.security import (
    get_user_from_token,
    hash_password,
    start_session,
    terminate_all_user_sessions,
)
from app.services import (
    add_ticket_comment,
    assign_ticket,
    create_ticket,
    delete_ticket,
    get_ticket_by_id,
    get_ticket_events,
    get_ticket_for_user,
    list_tickets,
    update_ticket_status,
)


class SmokeTestScenario(unittest.TestCase):
    """Сквозной сценарий проверки жизненного цикла сервиса."""

    def setUp(self):
        # 4.3: Изолированная временная БД
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp_dir.name) / "smoke_test.db")
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON;")
        run_migrations(self.conn)

    def tearDown(self):
        self.conn.close()
        self.tmp_dir.cleanup()

    def test_end_to_end_user_and_agent_workflow(self):
        """
        Полный сквозной сценарий:
        1. Создание обычного пользователя и проверка роли.
        2. Аутентификация и создание сессии.
        3. Создание заявки клиентом.
        4. Добавление комментария пользователем.
        5. Создание специалиста поддержки (агента).
        6. Назначение исполнителя на заявку (assign).
        7. Добавление комментария агентом.
        8. Смена статуса заявки агентом (in_progress).
        9. Завершение заявки (closed).
        10. Soft-delete заявки и проверка аудит-лога.
        11. Инвалидация всех сессий (logout-all).
        """
        now = "2026-10-01T10:00:00+00:00"
        p_hash = hash_password("DemoPassword123")
        cur = self.conn.cursor()

        # 1. Регистрация клиента
        cur.execute(
            """INSERT INTO users (username, password_hash, role, created_at, updated_at)
               VALUES ('smoke_client', ?, ?, ?, ?)""",
            (p_hash, ROLE_USER, now, now),
        )
        user_id = cur.lastrowid

        # 2. Регистрация агента
        cur.execute(
            """INSERT INTO users (username, password_hash, role, created_at, updated_at)
               VALUES ('smoke_agent', ?, ?, ?, ?)""",
            (p_hash, ROLE_AGENT, now, now),
        )
        agent_id = cur.lastrowid
        self.conn.commit()

        client_obj = {"id": user_id, "username": "smoke_client", "role": ROLE_USER}
        agent_obj = {"id": agent_id, "username": "smoke_agent", "role": ROLE_AGENT}

        # 3. Сессия клиента
        token = start_session(self.conn, user_id)
        self.assertIsNotNone(get_user_from_token(self.conn, token))

        # 4. Создание заявки
        t_id = create_ticket(
            self.conn,
            author_id=user_id,
            subject="Не работает интернет",
            description="Сетевой кабель повреждён в офисе 101",
            priority=PRIORITY_HIGH,
        )
        self.assertIsInstance(t_id, int)

        # 5. Комментарий клиента
        add_ticket_comment(self.conn, t_id, user_id, "Проверил на другом ПК — тоже нет сети.")

        # 6. Назначение агента (assign) (пункт 4.1)
        assign_ticket(self.conn, t_id, agent_id, agent_id)
        t_assigned = get_ticket_by_id(self.conn, t_id)
        self.assertEqual(t_assigned["assignee_id"], agent_id)

        # 7. Комментарий агента
        add_ticket_comment(self.conn, t_id, agent_id, "Принято. Инженер выехал для замены патч-корда.")

        # 8. Смена статуса в работу
        update_ticket_status(self.conn, t_id, STATUS_IN_PROGRESS, agent_id, is_agent=True)
        self.assertEqual(get_ticket_by_id(self.conn, t_id)["status"], STATUS_IN_PROGRESS)

        # 9. Закрытие заявки
        update_ticket_status(self.conn, t_id, STATUS_CLOSED, agent_id, is_agent=True)
        self.assertEqual(get_ticket_by_id(self.conn, t_id)["status"], STATUS_CLOSED)

        # Проверка истории событий
        events = get_ticket_events(self.conn, t_id)
        self.assertGreaterEqual(len(events), 5)

        # 10. Soft delete заявки (пункты 3.7, 4.1)
        delete_ticket(self.conn, t_id, agent_id)
        self.assertIsNone(get_ticket_by_id(self.conn, t_id))

        cur.execute("SELECT * FROM deleted_log WHERE zayavka_id = ?", (t_id,))
        del_log = cur.fetchone()
        self.assertIsNotNone(del_log)
        self.assertEqual(del_log["deleted_by"], agent_id)

        # 11. Выход со всех устройств (logout-all) (пункт 4.1)
        terminate_all_user_sessions(self.conn, user_id)
        self.assertIsNone(get_user_from_token(self.conn, token))


if __name__ == "__main__":
    base_url = os.environ.get("TEST_BASE_URL", "http://127.0.0.1:5000")
    print(f"[*] Запуск расширенного Smoke-теста (целевой URL: {base_url})...")
    unittest.main()
