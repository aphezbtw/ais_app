#!/usr/bin/env python3
"""
Административный скрипт для создания или повышения роли пользователя до специалиста поддержки (agent).
Решает проблему 1.1 аудита — безопасное назначение роли 'agent' без веб-интерфейса.
Использование:
    python scripts/create_agent.py <username> [password]
"""
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Добавляем родительскую директорию в sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import Config
from app.constants import ROLE_AGENT
from app.db import get_db, init_db
from app.security import hash_password
import sqlite3

def main():
    if len(sys.argv) < 2:
        print("Использование: python scripts/create_agent.py <username> [password]")
        sys.exit(1)

    username = sys.argv[1].strip()
    password = sys.argv[2] if len(sys.argv) > 2 else None

    db_path = Config.DATABASE
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")

    now_str = datetime.now(timezone.utc).isoformat()
    cur = conn.cursor()
    cur.execute("SELECT id, username, role FROM users WHERE username = ?", (username,))
    user = cur.fetchone()

    if user:
        # Обновление роли существующего пользователя
        if password:
            p_hash = hash_password(password)
            conn.execute(
                "UPDATE users SET role = ?, password_hash = ?, updated_at = ? WHERE id = ?",
                (ROLE_AGENT, p_hash, now_str, user["id"]),
            )
            print(f"[+] Пользователь '{username}' успешно назначен специалистом поддержки (пароль обновлён).")
        else:
            conn.execute(
                "UPDATE users SET role = ?, updated_at = ? WHERE id = ?",
                (ROLE_AGENT, now_str, user["id"]),
            )
            print(f"[+] Пользователю '{username}' успешно присвоена роль специалиста поддержки (agent).")
    else:
        # Создание нового пользователя
        if not password:
            print(f"[-] Ошибка: Для создания нового пользователя '{username}' необходимо указать пароль.")
            sys.exit(1)
        p_hash = hash_password(password)
        conn.execute(
            """
            INSERT INTO users (username, password_hash, role, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, p_hash, ROLE_AGENT, now_str, now_str),
        )
        print(f"[+] Создан новый специалист поддержки: {username} (роль: {ROLE_AGENT}).")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    main()
