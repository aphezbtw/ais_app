"""
Модуль работы с базой данных SQLite.
Реализует управление соединениями через teardown_appcontext (2.5),
миграции с версионированием и CHECK-ограничениями (2.3, 2.13, 3.6),
soft delete поля и аудит (3.7), составные индексы (2.12, 6.5),
транзакционность (1.6) и очистку сессий (2.3).
"""
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from app.config import Config

try:
    from flask import current_app, g, has_app_context
except ImportError:
    has_app_context = lambda: False
    g = None
    current_app = None

# Пункт 3.6: Актуальная версия схемы базы данных
CURRENT_SCHEMA_VERSION = 2


def get_db():
    """Возвращает соединение с SQLite. В контексте Flask сохраняет в g.db."""
    if has_app_context() and g is not None:
        if not hasattr(g, "db") or g.db is None:
            db_path = current_app.config.get("DATABASE", Config.DATABASE) if current_app else Config.DATABASE
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA journal_mode = WAL;")
            g.db = conn
        return g.db

    conn = sqlite3.connect(Config.DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn


def close_db(e=None):
    """Закрывает соединение с базой данных по завершении запроса (пункт 2.5)."""
    if has_app_context() and g is not None:
        db = getattr(g, "db", None)
        if db is not None:
            db.close()
            g.db = None


def cleanup_expired_data(conn=None):
    """Очищает истёкшие сессии и старые записи попыток (attempts) (пункт 2.3)."""
    close_after = False
    if conn is None:
        conn = get_db()
        close_after = not (has_app_context() and g is not None)

    now_iso = datetime.now(timezone.utc).isoformat()
    attempts_cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

    try:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now_iso,))
        conn.execute("DELETE FROM attempts WHERE created_at < ?", (attempts_cutoff,))
        conn.commit()
    except sqlite3.OperationalError:
        pass
    finally:
        if close_after:
            conn.close()


def run_migrations(conn: sqlite3.Connection):
    """
    Идемпотентные миграции схемы базы данных с версионированием (пункты 1.6, 2.3, 3.6, 3.7).
    Оборачиваются в строгие транзакции.
    """
    conn.execute(
        """CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        );"""
    )
    conn.commit()

    cur = conn.cursor()
    cur.execute("SELECT MAX(version) FROM schema_version")
    row = cur.fetchone()
    current_ver = row[0] if (row and row[0] is not None) else 0

    now_str = datetime.now(timezone.utc).isoformat()

    # Миграция 1: Основная схема с CHECK-ограничениями (2.3)
    if current_ver < 1:
        conn.execute("BEGIN IMMEDIATE;")
        try:
            # 1. Таблица пользователей
            conn.execute(
                """CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'agent')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );"""
            )

            # 2. Таблица заявок с CHECK ограничениями
            conn.execute(
                """CREATE TABLE IF NOT EXISTS zayavki (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subject TEXT NOT NULL,
                    description TEXT NOT NULL,
                    priority TEXT NOT NULL CHECK (priority IN ('low','normal','high','critical','Низкий','Средний','Высокий')),
                    status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','in_progress','resolved','closed','Новая','В работе','Ожидает уточнения','Закрыта')),
                    author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
                    assignee_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    deleted_at TEXT,
                    deleted_by INTEGER REFERENCES users(id) ON DELETE SET NULL
                );"""
            )

            # 3. Таблица истории и комментариев
            conn.execute(
                """CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    zayavka_id INTEGER NOT NULL REFERENCES zayavki(id) ON DELETE CASCADE,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL CHECK (kind IN ('comment','status','assign','create','created','status_change','assignment')),
                    text TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );"""
            )

            # 4. Таблица серверных сессий
            conn.execute(
                """CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    token_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );"""
            )

            # 5. Таблица учёта попыток (rate limiting)
            conn.execute(
                """CREATE TABLE IF NOT EXISTS attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL,
                    identifier_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );"""
            )

            # 6. Журнал удалений (пункты 3.7, 6.4)
            conn.execute(
                """CREATE TABLE IF NOT EXISTS deleted_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    zayavka_id INTEGER NOT NULL,
                    ticket_subject TEXT,
                    ticket_description TEXT,
                    deleted_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    deleted_at TEXT NOT NULL
                );"""
            )

            # Индексы (2.12, 6.5)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_zayavki_author ON zayavki(author_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_zayavki_assignee ON zayavki(assignee_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_zayavki_status ON zayavki(status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_zayavki_priority ON zayavki(priority);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_zayavki_created ON zayavki(created_at);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_zayavki_deleted ON zayavki(deleted_at);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_zayavka ON events(zayavka_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_attempts_lookup ON attempts(kind, identifier_hash, created_at);")

            conn.execute("INSERT OR REPLACE INTO schema_version (version, applied_at) VALUES (1, ?);", (now_str,))
            conn.commit()
            current_ver = 1
        except Exception:
            conn.rollback()
            raise

    # Миграция 2: Поддержка soft delete (3.7) и расширенных полей аудит-лога
    if current_ver < 2:
        conn.execute("BEGIN IMMEDIATE;")
        try:
            # Проверяем наличие колонок deleted_at и deleted_by в zayavki
            col_info = conn.execute("PRAGMA table_info(zayavki)").fetchall()
            col_names = [c["name"] if isinstance(c, sqlite3.Row) else c[1] for c in col_info]
            if "deleted_at" not in col_names:
                conn.execute("ALTER TABLE zayavki ADD COLUMN deleted_at TEXT;")
            if "deleted_by" not in col_names:
                conn.execute("ALTER TABLE zayavki ADD COLUMN deleted_by INTEGER REFERENCES users(id) ON DELETE SET NULL;")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_zayavki_deleted ON zayavki(deleted_at);")

            del_col_info = conn.execute("PRAGMA table_info(deleted_log)").fetchall()
            del_cols = [c["name"] if isinstance(c, sqlite3.Row) else c[1] for c in del_col_info]
            if "ticket_description" not in del_cols:
                conn.execute("ALTER TABLE deleted_log ADD COLUMN ticket_description TEXT;")

            conn.execute("INSERT OR REPLACE INTO schema_version (version, applied_at) VALUES (2, ?);", (now_str,))
            conn.commit()
            current_ver = 2
        except Exception:
            conn.rollback()
            raise

    if current_ver < CURRENT_SCHEMA_VERSION:
        raise RuntimeError(
            f"Несоответствие схемы базы данных: в БД версия {current_ver}, требуется {CURRENT_SCHEMA_VERSION}"
        )


def init_db(app=None):
    """Инициализация базы данных SQLite с проверкой прав доступа и сидом при SEED_DEMO=1."""
    cfg = app.config if (app and hasattr(app, "config")) else Config
    seed_demo = cfg.get("SEED_DEMO", False) if isinstance(cfg, dict) else getattr(cfg, "SEED_DEMO", False)
    db_path = cfg.get("DATABASE", Config.DATABASE) if isinstance(cfg, dict) else getattr(cfg, "DATABASE", Config.DATABASE)
    is_memory = str(db_path) == ":memory:"

    if not is_memory:
        p = Path(db_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(p.parent, 0o700)
        except OSError:
            pass

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")

    try:
        run_migrations(conn)
        cleanup_expired_data(conn)

        if seed_demo:
            from app.seed import seed_demo_data
            seed_demo_data(conn)

        conn.commit()
    finally:
        conn.close()

    if not is_memory and os.path.exists(db_path):
        try:
            os.chmod(db_path, 0o600)
        except OSError:
            pass
