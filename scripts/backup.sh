#!/usr/bin/env bash
# ==============================================================================
# Скрипт безопасного горячего резервного копирования базы данных SQLite
# Решает пункты 5.3, 5.4 аудита. Использует онлайн-механизм .backup SQLite.
#
# Настройка расписания в cron (пункт 5.4):
# Откройте редактор: crontab -e
# Добавьте строку для ежедневного запуска в 03:00 ночи:
# 0 3 * * * /opt/ais_zayavki/scripts/backup.sh >> /opt/ais_zayavki/instance/backup.log 2>&1
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
INSTANCE_DIR="${INSTANCE_DIR:-$ROOT_DIR/instance}"
DB_PATH="${DATABASE_PATH:-$INSTANCE_DIR/zayavki.db}"
BACKUP_DIR="${INSTANCE_DIR}/backups"

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

if [ ! -f "$DB_PATH" ]; then
    echo "[-] Ошибка: файл базы данных не найден по пути: $DB_PATH" >&2
    exit 1
fi

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/zayavki_backup_${TIMESTAMP}.db"

echo "[*] Создание горячей резервной копии базы данных..."
sqlite3 "$DB_PATH" ".backup '${BACKUP_FILE}'"
chmod 600 "$BACKUP_FILE"

echo "[+] Резервная копия успешно создана: ${BACKUP_FILE}"
echo "[*] Ротация: удаление резервных копий старше 30 дней..."
find "$BACKUP_DIR" -name "zayavki_backup_*.db" -type f -mtime +30 -delete
echo "[+] Резервное копирование завершено."
