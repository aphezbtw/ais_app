"""
Pytest фикстуры для тестирования АИС «Заявки» v2.
Обеспечивает полную изоляцию от продуктивной базы данных (пункт 4.3).
"""
import os
import sqlite3
import tempfile
from pathlib import Path
import pytest

from app import create_app
from app.config import TestConfig
from app.constants import ROLE_AGENT, ROLE_USER
from app.db import init_db, run_migrations
from app.security import hash_password


@pytest.fixture
def temp_db_dir():
    """Создаёт изолированную временную директорию для базы данных тестов."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield Path(tmp_dir)


@pytest.fixture
def app(temp_db_dir):
    """Создаёт приложение Flask с изолированной временной тестовой базой."""
    class CustomTestConfig(TestConfig):
        INSTANCE_DIR = temp_db_dir
        DATABASE = str(temp_db_dir / "test_zayavki.db")
        LOG_FILE = str(temp_db_dir / "test.log")
        SEED_DEMO = False
        WTF_CSRF_ENABLED = False

    test_app = create_app(CustomTestConfig)
    test_app.config["TESTING"] = True

    with test_app.app_context():
        init_db(test_app)
        yield test_app


@pytest.fixture
def client(app):
    """Тестовый HTTP-клиент."""
    return app.test_client()


@pytest.fixture
def db_conn(app):
    """Прямое соединение с тестовой базой данных для проверки таблиц."""
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    yield conn
    conn.close()


@pytest.fixture
def sample_user(db_conn):
    """Создаёт тестового пользователя с ролью 'user'."""
    p_hash = hash_password("password123")
    cur = db_conn.cursor()
    cur.execute(
        """
        INSERT INTO users (username, password_hash, role, created_at, updated_at)
        VALUES (?, ?, ?, '2026-01-01T10:00:00+00:00', '2026-01-01T10:00:00+00:00')
        """,
        ("testuser", p_hash, ROLE_USER),
    )
    db_conn.commit()
    return {"id": cur.lastrowid, "username": "testuser", "role": ROLE_USER}


@pytest.fixture
def sample_agent(db_conn):
    """Создаёт тестового специалиста поддержки с ролью 'agent'."""
    p_hash = hash_password("agentpass123")
    cur = db_conn.cursor()
    cur.execute(
        """
        INSERT INTO users (username, password_hash, role, created_at, updated_at)
        VALUES (?, ?, ?, '2026-01-01T10:00:00+00:00', '2026-01-01T10:00:00+00:00')
        """,
        ("testagent", p_hash, ROLE_AGENT),
    )
    db_conn.commit()
    return {"id": cur.lastrowid, "username": "testagent", "role": ROLE_AGENT}
