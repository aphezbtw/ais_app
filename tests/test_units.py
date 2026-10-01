"""
Модульные тесты изолированных функций (пункт 4.1).
Покрывает SLA-расчёты (3.4), rate limiting (2.11), хеширование паролей,
санитизацию логов (2.14), pepper-изоляцию (2.6, 4.3) и валидацию данных.
"""
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone

from app.config import Config
from app.constants import (
    PRIORITY_CRITICAL,
    PRIORITY_HIGH,
    PRIORITY_LOW,
    PRIORITY_NORMAL,
    ROLE_AGENT,
    ROLE_USER,
    SLA_HOURS,
    STATUS_CLOSED,
    STATUS_IN_PROGRESS,
    STATUS_NEW,
    STATUS_RESOLVED,
)
from app.db import cleanup_expired_data, run_migrations
from app.security import (
    check_rate_limit,
    hash_identifier,
    hash_password,
    sanitize_log_message,
    verify_password,
)
from app.services import get_sla_info, is_overdue, sla_deadline


class TestUnitSecurity(unittest.TestCase):
    """Тестирование механизмов безопасности и хеширования."""

    def test_password_hash_and_verify(self):
        password = "SecretPassword123!"
        hashed = hash_password(password)
        self.assertNotEqual(hashed, password)
        self.assertTrue(verify_password(hashed, password))
        self.assertFalse(verify_password(hashed, "WrongPassword"))

    def test_hash_identifier_and_pepper_isolation(self):
        # Пункты 2.6, 4.3: Хеш должен быть детерминированным в рамках pepper
        ident1 = "192.168.1.1"
        ident2 = "192.168.1.1"
        ident3 = "192.168.1.2"
        h1 = hash_identifier(ident1)
        h2 = hash_identifier(ident2)
        h3 = hash_identifier(ident3)
        self.assertEqual(h1, h2)
        self.assertNotEqual(h1, h3)
        self.assertEqual(len(h1), 64)

        # Проверка изоляции от SECRET_KEY: pepper является отдельным набором байт
        pepper = Config.get_rate_limit_pepper()
        self.assertIsInstance(pepper, bytes)
        self.assertEqual(len(pepper), 32)

    def test_sanitize_log_message_prevents_injection(self):
        # Пункт 2.14: предотвращение Log Injection
        malicious_input = "Normal text\r\n[2026-10-01] FAKE_LOG_ENTRY admin logged in\n"
        sanitized = sanitize_log_message(malicious_input)
        self.assertNotIn("\n", sanitized)
        self.assertNotIn("\r", sanitized)
        self.assertIn("Normal text  [2026-10-01] FAKE_LOG_ENTRY", sanitized)


class TestUnitSLA(unittest.TestCase):
    """Тестирование расчёта SLA нормативов (пункт 3.4)."""

    def test_sla_deadlines_by_priority(self):
        base_time = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
        base_str = base_time.isoformat()

        priorities_and_expected_hours = [
            (PRIORITY_LOW, 72),
            (PRIORITY_NORMAL, 24),
            (PRIORITY_HIGH, 8),
            (PRIORITY_CRITICAL, 4),
        ]

        for prio, expected_h in priorities_and_expected_hours:
            ticket = {
                "created_at": base_str,
                "priority": prio,
                "status": STATUS_NEW,
            }
            deadline = sla_deadline(ticket)
            expected_deadline = base_time + timedelta(hours=expected_h)
            self.assertEqual(deadline, expected_deadline, f"Ошибка расчёта для приоритета {prio}")

    def test_is_overdue(self):
        now = datetime.now(timezone.utc)

        fresh_critical = {
            "created_at": (now - timedelta(hours=2)).isoformat(),
            "priority": PRIORITY_CRITICAL,
            "status": STATUS_NEW,
        }
        self.assertFalse(is_overdue(fresh_critical))

        old_critical = {
            "created_at": (now - timedelta(hours=5)).isoformat(),
            "priority": PRIORITY_CRITICAL,
            "status": STATUS_NEW,
        }
        self.assertTrue(is_overdue(old_critical))

        old_resolved = dict(old_critical)
        old_resolved["status"] = STATUS_RESOLVED
        self.assertFalse(is_overdue(old_resolved))

        old_closed = dict(old_critical)
        old_closed["status"] = STATUS_CLOSED
        self.assertFalse(is_overdue(old_closed))


class TestUnitRateLimit(unittest.TestCase):
    """Тестирование ограничителя частоты запросов в SQLite (пункт 2.11)."""

    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON;")
        run_migrations(self.conn)

    def tearDown(self):
        self.conn.close()

    def test_rate_limit_allows_under_threshold(self):
        ident = "10.0.0.1"
        for _ in range(5):
            self.assertTrue(check_rate_limit(self.conn, "test_action", ident, limit=5, window_seconds=60))

        # 6-я попытка должна быть отклонена
        self.assertFalse(check_rate_limit(self.conn, "test_action", ident, limit=5, window_seconds=60))

    def test_rate_limit_resets_after_window(self):
        ident = "10.0.0.2"
        # Заполняем 3 попытки старыми датами (2 часа назад)
        old_time = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(timespec="seconds")
        ident_hash = hash_identifier(ident)
        for _ in range(3):
            self.conn.execute(
                "INSERT INTO attempts (kind, identifier_hash, created_at) VALUES ('action_win', ?, ?)",
                (ident_hash, old_time),
            )
        self.conn.commit()

        # Лимит 3 на 60 секунд. Так как попытки старые, новая попытка должна разрешиться
        self.assertTrue(check_rate_limit(self.conn, "action_win", ident, limit=3, window_seconds=60))


class TestUnitDBCleanup(unittest.TestCase):
    """Тестирование очистки истёкших данных (пункт 2.3)."""

    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON;")
        run_migrations(self.conn)

    def tearDown(self):
        self.conn.close()

    def test_cleanup_expired_sessions_and_attempts(self):
        cur = self.conn.cursor()
        now = datetime.now(timezone.utc)

        # Создаём тестового пользователя
        cur.execute(
            """INSERT INTO users (username, password_hash, role, created_at, updated_at)
               VALUES ('cleanup_user', 'hash', 'user', ?, ?)""",
            (now.isoformat(), now.isoformat()),
        )
        uid = cur.lastrowid

        # 1. Сессия, истёкшая вчера
        cur.execute(
            """INSERT INTO sessions (user_id, token_hash, created_at, expires_at)
               VALUES (?, 'expired_tok', ?, ?)""",
            (uid, (now - timedelta(days=2)).isoformat(), (now - timedelta(days=1)).isoformat()),
        )
        # 2. Сессия, действующая до завтра
        cur.execute(
            """INSERT INTO sessions (user_id, token_hash, created_at, expires_at)
               VALUES (?, 'valid_tok', ?, ?)""",
            (uid, now.isoformat(), (now + timedelta(days=1)).isoformat()),
        )
        # 3. Попытка старше 24 часов
        cur.execute(
            """INSERT INTO attempts (kind, identifier_hash, created_at)
               VALUES ('test', 'old_ident', ?)""",
            ((now - timedelta(hours=30)).isoformat(),),
        )
        self.conn.commit()

        cleanup_expired_data(self.conn)

        cur.execute("SELECT token_hash FROM sessions")
        remaining_sessions = [r[0] for r in cur.fetchall()]
        self.assertEqual(remaining_sessions, ["valid_tok"])

        cur.execute("SELECT identifier_hash FROM attempts WHERE identifier_hash = 'old_ident'")
        self.assertIsNone(cur.fetchone())


if __name__ == "__main__":
    unittest.main()
