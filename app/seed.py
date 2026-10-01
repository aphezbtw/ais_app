"""
Модуль инициализации демонстрационных данных (пункты 1.2 и 2.8).
Загружается и выполняется ТОЛЬКО при установленной переменной SEED_DEMO=1.
"""
from datetime import datetime, timedelta, timezone
from app.constants import (
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
from app.security import hash_password

DEMO_USERS = [
    ("ivanova", "demo1234", ROLE_USER),
    ("petrov", "demo1234", ROLE_USER),
    ("support", "demo1234", ROLE_AGENT),
]

SAMPLE_TICKETS = [
    ("Не работает корпоративная почта", "При отправке писем выдает ошибку SMTP 550. Прошу восстановить доступ.", PRIORITY_HIGH, STATUS_NEW),
    ("Замена картриджа в бухгалтерии", "Принтер HP LaserJet в кабинете 204 печатает с полосами.", PRIORITY_LOW, STATUS_IN_PROGRESS),
    ("Доступ к сетевой папке Проекты", "Новый сотрудник отдела маркетинга, необходим доступ на чтение и запись.", PRIORITY_NORMAL, STATUS_RESOLVED),
    ("Сбой в 1С при закрытии месяца", "Вылетает ошибка при формировании книги покупок. Срочно!", PRIORITY_CRITICAL, STATUS_NEW),
    ("Настройка VPN на рабочем ноутбуке", "Для удаленной работы требуется настроить WireGuard клиент.", PRIORITY_NORMAL, STATUS_CLOSED),
    ("Тормозит рабочий компьютер", "Windows долго загружается, диспетчер задач показывает 100% загрузку диска.", PRIORITY_LOW, STATUS_IN_PROGRESS),
    ("Установка архиватора 7-Zip", "Не открываются файлы формата .rar и .7z.", PRIORITY_LOW, STATUS_RESOLVED),
    ("Не включается монитор", "Индикатор мигает желтым, сигнала нет. Кабель проверял.", PRIORITY_NORMAL, STATUS_NEW),
    ("Отказ сервера телефонии", "Входящие звонки не поступают на операторов колл-центра.", PRIORITY_CRITICAL, STATUS_IN_PROGRESS),
    ("Сброс пароля в Active Directory", "Заблокировалась учетная запись после 3 неверных попыток.", PRIORITY_NORMAL, STATUS_RESOLVED),
    ("Запрос гарнитуры для Zoom", "Старые наушники фонят и трещат во время планерок.", PRIORITY_LOW, STATUS_NEW),
    ("Проблема с Wi-Fi на 3 этаже", "Постоянно обрывается подключение к сети Office-Staff.", PRIORITY_HIGH, STATUS_IN_PROGRESS),
    ("Подключение сетевого сканера", "Сканы не приходят в папку Сканы_Отдел.", PRIORITY_NORMAL, STATUS_RESOLVED),
    ("Ошибка лицензии MS Excel", "Появилась красная плашка о необходимости активации продукта.", PRIORITY_NORMAL, STATUS_NEW),
    ("Обновление сертификата ЭЦП", "Истекает срок действия ЭЦП для работы на портале закупок.", PRIORITY_HIGH, STATUS_IN_PROGRESS),
    ("Пролив кофе на клавиатуру", "Залипают пробел и клавиши Enter. Нужна замена.", PRIORITY_NORMAL, STATUS_RESOLVED),
    ("Медленный интернет в переговорке", "Во время видеозвонков с клиентами заикается видео.", PRIORITY_NORMAL, STATUS_NEW),
    ("Установка среды Python", "Требуется Python 3.11 и VS Code для аналитики данных.", PRIORITY_LOW, STATUS_CLOSED),
    ("Падение СУБД в тестовом контуре", "База PostgreSQL в dev-среде не отвечает на порту 5432.", PRIORITY_HIGH, STATUS_IN_PROGRESS),
    ("Замена ИБП у сервера", "Батарея ИБП в серверной пищит каждые 15 минут.", PRIORITY_HIGH, STATUS_NEW),
    ("Консультация по настройке почтового клиента", "Как настроить подпись с логотипом компании в Outlook?", PRIORITY_LOW, STATUS_RESOLVED),
    ("Блокировка подозрительного файла антивирусом", "Kaspersky заблокировал вложение от контрагента.", PRIORITY_NORMAL, STATUS_IN_PROGRESS),
    ("Не работает лифт (передано в АХО)", "Застряла дверь на 2 этаже. Просьба вызвать аварийную службу.", PRIORITY_NORMAL, STATUS_CLOSED),
    ("Взлом аккаунта сотрудника (Угроза ИБ)", "От имени менеджера идет спам-рассылка. Срочно заблокировать!", PRIORITY_CRITICAL, STATUS_IN_PROGRESS),
]


def seed_demo_data(conn):
    """Наполняет базу данных пользователями и 24 заявками при первом старте с SEED_DEMO=1."""
    cur = conn.cursor()
    now = datetime.now(timezone.utc)
    now_str = now.isoformat()

    user_ids = {}
    for username, raw_pass, role in DEMO_USERS:
        cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if not row:
            p_hash = hash_password(raw_pass)
            cur.execute(
                """
                INSERT INTO users (username, password_hash, role, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (username, p_hash, role, now_str, now_str),
            )
            user_ids[username] = cur.lastrowid
        else:
            user_ids[username] = row[0]

    cur.execute("SELECT COUNT(*) FROM zayavki")
    existing_tickets = cur.fetchone()[0]

    if existing_tickets == 0:
        ivanova_id = user_ids.get("ivanova", 1)
        petrov_id = user_ids.get("petrov", 2)
        support_id = user_ids.get("support", 3)

        for i, (subj, desc, prio, stat) in enumerate(SAMPLE_TICKETS):
            # Распределяем авторов и даты создания
            author = ivanova_id if i % 2 == 0 else petrov_id
            assignee = support_id if stat in (STATUS_IN_PROGRESS, STATUS_RESOLVED, STATUS_CLOSED) else None

            # Генерируем даты для демонстрации работы SLA (часть свежие, часть просроченные)
            hours_offset = (i * 3) - 30
            created_dt = now + timedelta(hours=hours_offset)
            created_str = created_dt.isoformat()

            cur.execute(
                """
                INSERT INTO zayavki (subject, description, priority, status, author_id, assignee_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (subj, desc, prio, stat, author, assignee, created_str, created_str),
            )
            t_id = cur.lastrowid

            cur.execute(
                """
                INSERT INTO events (zayavka_id, user_id, event_type, details, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (t_id, author, "created", "Заявка создана (демо-данные)", created_str),
            )
            if assignee:
                cur.execute(
                    """
                    INSERT INTO events (zayavka_id, user_id, event_type, details, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (t_id, support_id, "assignment", "Назначен исполнитель: support", created_str),
                )
    conn.commit()
