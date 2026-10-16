#!/usr/bin/env python3
"""ShieldCode - self-hosted educational static source-code scanner.

Only reads uploaded source files as text. It never executes uploaded code.
Standard-library-only implementation for easy local startup.
"""
from __future__ import annotations
import hashlib
import hmac
import io
import json
import mimetypes
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import tempfile
import time
import textwrap
import zipfile
import threading
from collections import deque
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qs, quote, unquote, urlparse

import security_enhancements as sec

BASE_DIR = Path(__file__).resolve().parent
PUBLIC_DIR = BASE_DIR / "public"
DATA_DIR = Path(os.environ.get("SHIELDCODE_DATA_DIR", os.environ.get("CODESHIELD_DATA_DIR", str(BASE_DIR / "data")))).expanduser().resolve()
DB_PATH = DATA_DIR / "codeshield.sqlite3"
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", os.environ.get("SHIELDCODE_PORT", os.environ.get("CODESHIELD_PORT", "8765"))))
COOKIE_SECURE = os.environ.get("SHIELDCODE_COOKIE_SECURE", os.environ.get("CODESHIELD_COOKIE_SECURE", "0")) == "1"
MAX_REQUEST_BYTES = 12 * 1024 * 1024
MAX_ZIP_UNPACKED = 18 * 1024 * 1024
MAX_FILES = 120
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FINDINGS = 400
SESSION_TTL = 7 * 24 * 60 * 60
ALLOWED_EXTENSIONS = {
    ".html", ".htm", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue",
    ".css", ".scss", ".json", ".py", ".php", ".rb", ".go", ".java", ".cs",
    ".sql", ".yaml", ".yml", ".toml", ".ini", ".sh", ".xml", ".md", ".conf",
    ".config", ".env", ".properties", ".txt"
}
ALLOWED_EXTENSIONS.update(sec.EXTENSIONS_EXTRA)
SPECIAL_FILENAMES = sec.SPECIAL_FILENAMES

SKIP_PARTS = {"node_modules", "vendor", ".git", ".next", "dist", "build", "coverage", "__pycache__", "__MACOSX"}
ARCHIVE_SKIP_PARTS = {"node_modules", "vendor", ".git", "coverage", "__pycache__", "__MACOSX"}

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

RULES = [
    {
        "id": "PRIVATE_KEY", "severity": "critical", "title": "Возможно, встроен приватный ключ",
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "description": "В исходном файле обнаружен маркер приватного ключа. Если ключ настоящий и файл был передан кому-либо или опубликован, считайте его скомпрометированным.",
        "fix": "Удалите ключ из исходников, отзовите или замените его и храните секрет в защищённом хранилище на сервере.",
        "example": "# Не храните приватные ключи в исходном коде. Загрузите ключ из защищённого secret store на сервере."
    },
    {
        "id": "CLOUD_KEY", "severity": "critical", "title": "Похоже на ключ облачного доступа",
        "pattern": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "description": "Строка похожа на идентификатор ключа доступа облачного провайдера.",
        "fix": "Проверьте, настоящий ли это ключ. Если да — отзовите его, проверьте журнал доступа и перенесите секрет на сервер.",
        "example": "# Ключи облачных сервисов не должны попадать в публичный клиентский код."
    },
    {
        "id": "HARDCODED_SECRET", "severity": "high", "title": "Возможный секрет в исходном коде",
        "pattern": re.compile(r"(?i)\b(api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|secret[_-]?key)\b\s*[:=]\s*(['\"])([^\r\n'\"]{8,})\2"),
        "description": "В коде найдено присваивание значения переменной, похожей на секрет. Это может быть тестовый пример, поэтому результат нужно проверить вручную.",
        "fix": "Удалите секрет из исходников, смените его, если он был настоящим, и загружайте его из переменных окружения только на сервере.",
        "example": "import os\nAPI_KEY = os.environ.get('API_KEY')  # только на сервере; не отправлять секрет в браузер"
    },
    {
        "id": "EVAL", "severity": "high", "title": "Динамическое выполнение кода",
        "pattern": re.compile(r"\beval\s*\("),
        "description": "eval() выполняет строку как код. Если строка может зависеть от пользователя или внешнего источника, это способно привести к выполнению нежелательного кода.",
        "fix": "Избегайте eval(). Разберите ожидаемые данные безопасным парсером, например JSON.parse(), или используйте явные ветви логики.",
        "example": "// Вместо eval(text) для JSON:\nconst value = JSON.parse(text);"
    },
    {
        "id": "NEW_FUNCTION", "severity": "high", "title": "Создание функции из строки",
        "pattern": re.compile(r"\bnew\s+Function\s*\("),
        "description": "Конструктор Function компилирует строку в исполняемый код и может создать похожий на eval риск.",
        "fix": "Не генерируйте исполняемый JavaScript из непроверенных строк. Используйте заранее определённые функции и разрешённые операции.",
        "example": "// Вызывайте заранее объявленные функции вместо компиляции строки."
    },
    {
        "id": "INNER_HTML", "severity": "medium", "title": "Потенциально небезопасный HTML в DOM",
        "pattern": re.compile(r"\.innerHTML\s*(?:=|\+=)|\binsertAdjacentHTML\s*\("),
        "description": "Вставка HTML-строки в DOM может привести к XSS, если строка содержит пользовательские или внешние данные.",
        "fix": "Для обычного текста используйте textContent. Если необходим HTML, применяйте проверенную библиотеку санитизации и строгий список разрешённых элементов.",
        "example": "element.textContent = userProvidedText;"
    },
    {
        "id": "DOCUMENT_WRITE", "severity": "high", "title": "Использование document.write()",
        "pattern": re.compile(r"\bdocument\s*\.\s*write(?:ln)?\s*\("),
        "description": "document.write() может небезопасно вставлять контент в страницу и создавать XSS-риски.",
        "fix": "Создавайте DOM-элементы и записывайте обычный текст через textContent вместо document.write().",
        "example": "const node = document.createElement('p');\nnode.textContent = message;\ndocument.body.appendChild(node);"
    },
    {
        "id": "REACT_RAW_HTML", "severity": "high", "title": "Вставка HTML без обычного экранирования React",
        "pattern": re.compile(r"dangerouslySetInnerHTML\s*="),
        "description": "dangerouslySetInnerHTML отключает стандартное экранирование React и требует особого контроля источника HTML.",
        "fix": "Предпочитайте обычные текстовые свойства. Если HTML необходим, очищайте его проверенной санитизацией и никогда не вставляйте непроверенный ввод.",
        "example": "// Предпочтительно: <div>{userText}</div>"
    },
    {
        "id": "WILDCARD_CORS", "severity": "medium", "title": "Слишком широкий CORS-доступ",
        "pattern": re.compile(r"(?i)(?:access-control-allow-origin\s*[:=]\s*['\"]?\*|cors\s*\(\s*\{[^}]*origin\s*:\s*['\"]\*['\"]|origin\s*:\s*['\"]\*['\"])") ,
        "description": "Разрешение любого origin может быть слишком широким. Само по себе оно не всегда является уязвимостью, но часто требует ограничения доверенными доменами.",
        "fix": "Разрешайте только конкретные доверенные домены. Не совмещайте широкий CORS с разрешением credentials.",
        "example": "const allowedOrigins = new Set(['https://example.com']);\n// Сравнивайте Origin с разрешённым списком на сервере."
    },
    {
        "id": "TOKEN_LOCAL_STORAGE", "severity": "medium", "title": "Токен хранится в localStorage",
        "pattern": re.compile(r"(?i)localStorage\s*\.\s*setItem\s*\(\s*['\"][^'\"]*(?:token|jwt|session|auth)[^'\"]*['\"]"),
        "description": "Токены в localStorage доступны JavaScript на странице. При XSS это может упростить их кражу.",
        "fix": "Для веб-сессий рассмотрите серверные сессии с cookie HttpOnly, Secure и подходящим SameSite. Не храните долгоживущие секреты в браузере.",
        "example": "// Настройте серверную cookie с HttpOnly; устанавливайте её с сервера, а не из JS."
    },
    {
        "id": "TARGET_BLANK", "severity": "low", "title": "Ссылка открывается в новой вкладке без rel",
        "pattern": re.compile(r"target\s*=\s*['\"]_blank['\"]", re.I),
        "description": "Ссылки с target=_blank стоит снабжать rel=noopener noreferrer для ограничения взаимодействия новой вкладки с исходной страницей.",
        "fix": "Добавьте rel=\"noopener noreferrer\" к ссылке с target=\"_blank\".",
        "example": "<a href=\"https://example.com\" target=\"_blank\" rel=\"noopener noreferrer\">Открыть</a>"
    },
    {
        "id": "TLS_VERIFY_DISABLED", "severity": "high", "title": "Отключена проверка TLS-сертификата",
        "pattern": re.compile(r"(?i)(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*['\"]?\s*=\s*['\"]?0)"),
        "description": "Отключение проверки TLS-сертификата ослабляет защиту HTTPS-соединения и может позволить перехватить или подменить трафик.",
        "fix": "Включите проверку сертификатов и исправьте причину ошибки сертификата вместо отключения проверки.",
        "example": "# Python requests: requests.get(url, timeout=10)  # verify=True по умолчанию"
    },
    {
        "id": "DEBUG_MODE", "severity": "medium", "title": "Включён режим отладки",
        "pattern": re.compile(r"(?i)(?:debug\s*=\s*True|app\.run\([^\n]*debug\s*=\s*true)"),
        "description": "Режим отладки не должен быть включён на публичном production-сервере: он может раскрывать внутреннюю информацию.",
        "fix": "Отключите debug в production и задавайте настройки окружением. Не публикуйте подробные трассировки ошибок.",
        "example": "app.run(debug=(os.environ.get('APP_ENV') == 'development'))  # проверьте конфигурацию перед публикацией"
    },
    {
        "id": "COMMAND_EXEC", "severity": "high", "title": "Возможное выполнение системной команды",
        "pattern": re.compile(r"(?:child_process\s*\.\s*exec(?:Sync)?\s*\(|\bos\.system\s*\(|\bsubprocess\.(?:Popen|run|call)\s*\([^\n]*shell\s*=\s*True)"),
        "description": "Вызов оболочки с данными, контролируемыми пользователем, может привести к command injection.",
        "fix": "По возможности используйте API библиотеки вместо оболочки. Если нужен subprocess, передавайте аргументы массивом, shell=False, и проверяйте каждое значение.",
        "example": "subprocess.run(['tool', validated_argument], check=True, shell=False)"
    },
    {
        "id": "PICKLE_LOADS", "severity": "high", "title": "Десериализация через pickle",
        "pattern": re.compile(r"\bpickle\s*\.\s*loads?\s*\("),
        "description": "Загрузка pickle-данных из недоверенного источника может выполнять произвольный код.",
        "fix": "Не загружайте pickle из недоверенных источников. Для обмена данными используйте безопасные форматы вроде JSON и валидируйте схему.",
        "example": "data = json.loads(untrusted_text)  # после проверки допустимой структуры"
    },
    {
        "id": "SQL_CONCAT", "severity": "high", "title": "Возможная SQL-инъекция через динамический запрос",
        "pattern": re.compile(r"(?i)(?:execute|executemany|query|raw)\s*\([^\n]*(?:\+\s*[A-Za-z_$]|%\s*[A-Za-z_(]|\.format\s*\(|f['\"])"),
        "description": "Строка запроса может собираться конкатенацией или форматированием. Если в неё попадают внешние данные, возможна SQL-инъекция.",
        "fix": "Используйте параметризованные запросы и передавайте пользовательские значения отдельно от SQL-текста.",
        "example": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
    },
    {
        "id": "HTTP_URL", "severity": "low", "title": "Незашифрованный HTTP-адрес",
        "pattern": re.compile(r'''http://[^\s'"<>]+''', re.I),
        "description": "Адрес HTTP может передавать данные без шифрования. Локальные адреса, документация и примеры не обязательно являются проблемой.",
        "fix": "Для публичных сервисов используйте HTTPS и проверьте, поддерживает ли целевой ресурс защищённое соединение.",
        "example": "const apiUrl = 'https://api.example.com';"
    },
]


def db_connect():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db():
    with db_connect() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL COLLATE NOCASE UNIQUE,
            password_salt BLOB NOT NULL,
            password_hash BLOB NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at INTEGER NOT NULL,
            label TEXT NOT NULL,
            total_files INTEGER NOT NULL,
            skipped_files INTEGER NOT NULL,
            score INTEGER NOT NULL,
            findings_count INTEGER NOT NULL,
            summary_json TEXT NOT NULL,
            findings_json TEXT NOT NULL,
            checks_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS idx_scans_user_created ON scans(user_id, created_at DESC);
        DELETE FROM sessions WHERE expires_at < strftime('%s','now');
        """)
        scan_columns = {row[1] for row in con.execute("PRAGMA table_info(scans)").fetchall()}
        if "checks_json" not in scan_columns:
            con.execute("ALTER TABLE scans ADD COLUMN checks_json TEXT NOT NULL DEFAULT '{}'")
        user_columns = {row[1] for row in con.execute("PRAGMA table_info(users)").fetchall()}
        if "password_iterations" not in user_columns:
            con.execute("ALTER TABLE users ADD COLUMN password_iterations INTEGER NOT NULL DEFAULT 310000")
        if "language" not in user_columns:
            con.execute("ALTER TABLE users ADD COLUMN language TEXT NOT NULL DEFAULT 'ru'")


def password_hash(password: str, salt: bytes | None = None, iterations: int = 600_000) -> tuple[bytes, bytes]:
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return salt, derived


def safe_source_name(raw: str) -> str | None:
    """Validate a logical relative path. It is never used directly as a disk path."""
    raw = (raw or "uploaded-file").replace("\\", "/")
    # Reject Windows alternate data streams, absolute/drive paths, NUL and control characters.
    if len(raw) > 240 or ":" in raw or any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        return None
    pp = PurePosixPath(raw)
    if pp.is_absolute() or re.match(r"^[A-Za-z]:", raw) or ".." in pp.parts:
        return None
    parts = [p for p in pp.parts if p not in ("", ".")]
    if not parts or any(p.lower() in SKIP_PARTS for p in parts):
        return None
    name = "/".join(parts)
    leaf = parts[-1].lower()
    suffix = PurePosixPath(leaf).suffix
    if (leaf in SPECIAL_FILENAMES or leaf.startswith(".env.") or leaf.startswith("id_rsa") or
            leaf.startswith("id_ed25519") or leaf.startswith("dockerfile.") or leaf.startswith("containerfile.") or leaf.startswith("makefile.") or suffix in ALLOWED_EXTENSIONS or
            leaf.endswith((".tfstate", ".tfstate.backup", ".pem", ".key", ".crt", ".der", ".p12", ".pfx", ".jks", ".keystore", ".lock", ".sum", ".mod"))):
        return name
    return None


def safe_archive_entry_name(raw: str) -> str | None:
    """Validate a relative project path for copying assets into a result ZIP."""
    raw = (raw or "").replace("\\", "/")
    if not raw or len(raw) > 240 or ":" in raw or any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        return None
    pp = PurePosixPath(raw)
    if pp.is_absolute() or re.match(r"^[A-Za-z]:", raw) or ".." in pp.parts:
        return None
    parts = [part for part in pp.parts if part not in ("", ".")]
    if not parts or any(part.lower() in ARCHIVE_SKIP_PARTS for part in parts):
        return None
    return "/".join(parts)


def unique_project_name(name: str, used: set[str]) -> str:
    if name not in used:
        used.add(name)
        return name
    stem, suffix = os.path.splitext(name)
    index = 2
    while f"{stem}_{index}{suffix}" in used:
        index += 1
    result = f"{stem}_{index}{suffix}"
    used.add(result)
    return result


def get_candidate_files_from_zip(name: str, payload: bytes) -> tuple[list[tuple[str, str]], int]:
    candidates: list[tuple[str, str]] = []
    skipped = 0
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_FILES * 3:
                raise ValueError("В архиве слишком много элементов. Допускается не более 360 записей в ZIP.")
            unpacked = 0
            for info in infos:
                if info.is_dir():
                    continue
                unpacked += info.file_size
                if unpacked > MAX_ZIP_UNPACKED:
                    raise ValueError("Распакованный объём архива превышает лимит 18 МБ.")
                safe_name = safe_source_name(info.filename)
                # Avoid symlink entries in ZIP.
                mode = (info.external_attr >> 16) & 0o170000
                if mode == 0o120000 or safe_name is None:
                    skipped += 1
                    continue
                if Path(safe_name).suffix.lower() in {".p12", ".pfx", ".jks", ".keystore", ".der"}:
                    candidates.append((safe_name, "[Бинарный контейнер ключа: содержимое не разбиралось; проверено только имя файла]"))
                    continue
                if info.file_size > MAX_FILE_BYTES:
                    skipped += 1
                    continue
                try:
                    with zf.open(info, "r") as f:
                        data = f.read(MAX_FILE_BYTES + 1)
                    if len(data) > MAX_FILE_BYTES or b"\x00" in data:
                        skipped += 1
                        continue
                    text = data.decode("utf-8", errors="replace")
                    if text.strip():
                        candidates.append((safe_name, text))
                except (RuntimeError, OSError, zipfile.BadZipFile):
                    skipped += 1
                if len(candidates) > MAX_FILES:
                    raise ValueError(f"В архиве найдено больше {MAX_FILES} подходящих файлов.")
    except zipfile.BadZipFile:
        raise ValueError(f"Файл {name} не является корректным ZIP-архивом.")
    return candidates, skipped


def parse_multipart(content_type: str, body: bytes) -> list[tuple[str, str | None, bytes]]:
    raw = b"MIME-Version: 1.0\r\nContent-Type: " + content_type.encode("latin-1", errors="replace") + b"\r\n\r\n" + body
    message = BytesParser(policy=policy.default).parsebytes(raw)
    if not message.is_multipart():
        raise ValueError("Ожидалась multipart-загрузка файлов.")
    result = []
    for part in message.iter_parts():
        disposition = part.get_content_disposition()
        if disposition != "form-data":
            continue
        field = part.get_param("name", header="content-disposition") or ""
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        # Include non-file form controls too; extract_files ignores those fields.
        result.append((field, filename, payload))
    return result


def extract_files(parts: list[tuple[str, str, bytes]]) -> tuple[list[tuple[str, str]], int, str]:
    collected: list[tuple[str, str]] = []
    skipped = 0
    labels = []
    for field, filename, payload in parts:
        if field != "files" or not filename:
            continue
        if len(payload) > MAX_FILE_BYTES and not filename.lower().endswith(".zip"):
            skipped += 1
            continue
        safe_name = safe_source_name(filename)
        if filename.lower().endswith(".zip"):
            unpacked, skip_count = get_candidate_files_from_zip(filename, payload)
            collected.extend(unpacked)
            skipped += skip_count
            labels.append(Path(filename).name)
        else:
            if safe_name is None:
                skipped += 1
                continue
            if Path(safe_name).suffix.lower() in {".p12", ".pfx", ".jks", ".keystore", ".der"}:
                collected.append((safe_name, "[Бинарный контейнер ключа: содержимое не разбиралось; проверено только имя файла]"))
                labels.append(Path(filename).name)
                continue
            if len(payload) > MAX_FILE_BYTES or b"\x00" in payload:
                skipped += 1
                continue
            text = payload.decode("utf-8", errors="replace")
            if text.strip():
                collected.append((safe_name, text))
            else:
                skipped += 1
            labels.append(Path(filename).name)
        if len(collected) > MAX_FILES:
            raise ValueError(f"Допускается не более {MAX_FILES} файлов исходного кода на одну проверку.")
    # Keep at most one instance of identical path names without overwriting silently.
    unique = []
    used = {}
    for name, content in collected:
        used[name] = used.get(name, 0) + 1
        if used[name] > 1:
            stem, ext = os.path.splitext(name)
            name = f"{stem}_{used[name]}{ext}"
        unique.append((name, content))
    if not unique:
        raise ValueError("Не найдено подходящих текстовых файлов. Загрузите поддерживаемый исходник, файл настроек/зависимостей или ZIP-проект.")
    return unique, skipped, ", ".join(labels[:3]) or "Исходный код"


def collect_fixpack_project(parts: list[tuple[str, str | None, bytes]]) -> tuple[list[tuple[str, str]], list[tuple[str, bytes]], int, str]:
    """Read project files as data, keep safe ZIP assets, and never extract to disk."""
    scan_files: list[tuple[str, str]] = []
    archive_entries: list[tuple[str, bytes]] = []
    used_names: set[str] = set()
    skipped = 0
    labels = []
    total_unpacked = 0
    entry_count = 0

    def add_entry(name: str, data: bytes, scan_allowed: bool) -> None:
        nonlocal skipped
        output_name = unique_project_name(name, used_names)
        archive_entries.append((output_name, data))
        if not scan_allowed:
            return
        if Path(name).suffix.lower() in {".p12", ".pfx", ".jks", ".keystore", ".der"}:
            scan_files.append((output_name, "[Бинарный контейнер ключа: содержимое не разбиралось; проверено только имя файла]"))
        elif len(data) <= MAX_FILE_BYTES and b"\x00" not in data:
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                skipped += 1
                return
            if text.strip():
                scan_files.append((output_name, text))
        else:
            skipped += 1

    for field, filename, payload in parts:
        if field != "files" or not filename:
            continue
        if filename.lower().endswith(".zip"):
            labels.append(Path(filename).name)
            try:
                with zipfile.ZipFile(io.BytesIO(payload)) as zf:
                    infos = zf.infolist()
                    if len(infos) > MAX_FILES * 3:
                        raise ValueError("В архиве слишком много элементов. Допускается не более 360 записей в ZIP.")
                    for info in infos:
                        if info.is_dir():
                            continue
                        entry_count += 1
                        if entry_count > MAX_FILES * 3:
                            raise ValueError("В проекте слишком много файлов и ресурсов для одного архива результата.")
                        total_unpacked += info.file_size
                        if total_unpacked > MAX_ZIP_UNPACKED:
                            raise ValueError("Распакованный объём проекта превышает лимит 18 МБ.")
                        safe_name = safe_archive_entry_name(info.filename)
                        mode = (info.external_attr >> 16) & 0o170000
                        if mode == 0o120000 or safe_name is None:
                            skipped += 1
                            continue
                        try:
                            with zf.open(info, "r") as stream:
                                data = stream.read(min(MAX_ZIP_UNPACKED - (total_unpacked - info.file_size) + 1, info.file_size + 1))
                        except (RuntimeError, OSError, zipfile.BadZipFile):
                            skipped += 1
                            continue
                        if len(data) != info.file_size:
                            raise ValueError("Архив содержит некорректный или чрезмерно сжатый элемент; он не был обработан.")
                        add_entry(safe_name, data, safe_source_name(safe_name) is not None)
            except zipfile.BadZipFile:
                raise ValueError(f"Файл {filename} не является корректным ZIP-архивом.")
        else:
            safe_name = safe_source_name(filename)
            if safe_name is None or len(payload) > MAX_FILE_BYTES:
                skipped += 1
                continue
            labels.append(Path(filename).name)
            entry_count += 1
            if entry_count > MAX_FILES * 3:
                raise ValueError("Загружено слишком много файлов для одного архива результата.")
            add_entry(safe_name, payload, True)

    if len(scan_files) > MAX_FILES:
        raise ValueError(f"Допускается не более {MAX_FILES} файлов исходного кода на одну проверку.")
    if not scan_files:
        raise ValueError("В проекте не найдено поддерживаемых текстовых файлов для подготовки исправленной копии.")
    return scan_files, archive_entries, skipped, ", ".join(labels[:3]) or "Исходный код"


def redact_sensitive_text(text: str) -> str:
    """Mask credentials before snippets or report objects are stored."""
    return sec.redact_text(text)


def scan_sources(files: list[tuple[str, str]]) -> list[dict]:
    findings = []
    for filename, content in files:
        lines = content.splitlines()
        suffix = Path(filename).suffix.lower()
        leaf = Path(filename).name.lower()
        for lineno, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            # Per-line regex rules are transparent and auditable. A finding is a lead, not a proof of exploitability.
            previous_line = lines[lineno - 2] if lineno > 1 else ""
            for rule in RULES:
                pattern = rule["pattern"]
                if not pattern.search(line):
                    continue
                # Documentation, test samples, rule definitions and lines marked "shieldcode: ignore" are not vulnerabilities.
                if sec.should_skip_finding(rule["id"], filename, line, previous_line):
                    continue
                if rule["id"] == "HTTP_URL":
                    urls = pattern.findall(line)
                    meaningful = []
                    for url in urls:
                        low = url.lower()
                        if low.startswith(("http://localhost", "http://127.0.0.1", "http://0.0.0.0", "http://[::1]", "http://{", "http://$", "http://%", "http://example.com", "http://example.org", "http://www.w3.org", "http://schemas.")):
                            continue
                        if "/" not in low[len("http://"):].split("/", 1)[0] and low.endswith(".svg"):
                            continue
                        meaningful.append(url)
                    if not meaningful:
                        continue
                if rule["id"] == "HARDCODED_SECRET":
                    match = pattern.search(line)
                    value = (match.group(3) if match and match.lastindex and match.lastindex >= 3 else "").lower()
                    placeholders = ("example", "dummy", "placeholder", "changeme", "change_me", "your_", "xxxx", "replace", "test", "redacted", "null", "none", "secret_here")
                    if any(p in value for p in placeholders):
                        continue
                    # A generic password field can be intentional in a login form; this is still only a signal.
                if rule["id"] == "TARGET_BLANK":
                    # Handle the common one-line anchor. Don't flag if the same line has an appropriate rel.
                    if re.search(r"\brel\s*=\s*['\"][^'\"]*\bnoopener\b", line, re.I):
                        continue
                # Avoid duplicate multiple HTTP URLs on a single line; one line is enough for a finding.
                snippet = line.strip()[:300]
                # If the current finding is a credential assignment, mask its exact captured value;
                # then apply broad redaction to every snippet so a second finding on the same line
                # cannot accidentally persist the same credential in plaintext.
                if rule["id"] == "HARDCODED_SECRET":
                    match = pattern.search(line)
                    if match and match.lastindex and match.lastindex >= 3:
                        secret_start, secret_end = match.span(3)
                        snippet = (line[:secret_start] + "[REDACTED]" + line[secret_end:]).strip()[:300]
                snippet = redact_sensitive_text(snippet)
                findings.append({
                    "id": rule["id"],
                    "severity": rule["severity"],
                    "title": rule["title"],
                    "file": filename,
                    "line": lineno,
                    "snippet": snippet,
                    "description": rule["description"],
                    "fix": rule["fix"],
                    "example": rule["example"],
                    "confidence": "low" if rule["id"] in {"HTTP_URL", "HARDCODED_SECRET", "SQL_CONCAT", "WILDCARD_CORS"} else "medium",
                })
            if len(findings) >= MAX_FINDINGS:
                break
        # File-level check for .env files and missing server-controlled protections.
        if leaf == ".env" or leaf.startswith(".env."):
            findings.append({
                "id": "ENV_FILE_INCLUDED", "severity": "high", "title": "Файл .env включён в набор проекта",
                "file": filename, "line": 1, "snippet": "[содержимое скрыто]",
                "description": "Файлы .env часто содержат секреты. Их нельзя публиковать на веб-сервере или отправлять в открытые репозитории.",
                "fix": "Удалите .env из публичной раздачи и репозитория. Добавьте его в .gitignore. При подозрении на утечку смените содержащиеся секреты.",
                "example": ".env\n.env.*\n# Добавьте эти шаблоны в .gitignore и безопасно задавайте значения на сервере.",
                "confidence": "medium"
            })
    # Extend the base rules to additional languages, dependency files, and infrastructure configuration.
    findings.extend(sec.scan_advanced_sources(files))
    # Remove duplicate rule/file/line results from overlapping rule packs.
    seen = set()
    deduplicated = []
    for finding in findings:
        key = (finding["id"], finding["file"], finding["line"])
        if key not in seen:
            seen.add(key)
            deduplicated.append(finding)
    findings = deduplicated
    def classify(finding):
        rid = finding.get("id", "")
        low = (rid + " " + finding.get("title", "")).lower()
        if not finding.get("owasp"):
            if any(k in low for k in ("secret", "key", "token", "password", "crypto", "private")):
                finding["owasp"] = "A04:2025 Cryptographic Failures"
            elif any(k in low for k in ("sql", "xss", "injection", "eval", "command", "deserialize", "xxe", "pickle")):
                finding["owasp"] = "A05:2025 Injection / A08:2025 Integrity (review)"
            elif any(k in low for k in ("cookie", "jwt", "session", "auth")):
                finding["owasp"] = "A07:2025 Authentication Failures"
            elif any(k in low for k in ("docker", "terraform", "kubernetes", "cors", "csp", "tls", "http", "config", "debug", "iframe")):
                finding["owasp"] = "A02:2025 Security Misconfiguration"
            else:
                finding["owasp"] = "Ручная классификация / secure coding review"
        finding.setdefault("category", "Static code signal")
        finding.setdefault("source", "built-in")
        return finding
    findings = [classify(item) for item in findings]
    findings.sort(key=lambda f: (SEVERITY_RANK.get(f["severity"], 9), f["file"].lower(), f["line"], f["id"]))
    return findings[:MAX_FINDINGS]


def build_fixpack_summary(original_files: list[tuple[str, str]], patched_files: list[tuple[str, str]], changes: list[dict]) -> dict:
    """Re-scan the corrected copy so the person sees what was really fixed and what still needs a human."""
    before = scan_sources(original_files)
    after = scan_sources(patched_files)
    return {
        "before": len(before),
        "after": len(after),
        "fixed": max(0, len(before) - len(after)),
        "edits": len(changes),
        "files": len({change.get("file") for change in changes}),
    }


PDF_SEVERITY = {
    "critical": "СРОЧНО",
    "high": "ВАЖНО",
    "medium": "ПЛАНОВО",
    "low": "НИЗКИЙ ПРИОРИТЕТ",
    "info": "СОВЕТ",
}


def _pdf_clean(value) -> str:
    text = str(value or "").replace("\r\n", "\n").replace("\r", "\n")
    return "".join(ch if ch in "\n\t" or ord(ch) >= 32 else " " for ch in text).expandtabs(4)


def _pdf_wrap(value, width: int, initial_indent: str = "", subsequent_indent: str = "") -> list[str]:
    output = []
    for paragraph in _pdf_clean(value).split("\n"):
        wrapped = textwrap.wrap(
            paragraph, width=max(12, width), initial_indent=initial_indent,
            subsequent_indent=subsequent_indent, break_long_words=True,
            break_on_hyphens=False, replace_whitespace=True, drop_whitespace=True,
        )
        output.extend(wrapped or [initial_indent.rstrip()])
    return output


def _pdf_table(rows: list[list[str]], widths: list[int]) -> list[str]:
    rule = "+" + "+".join("-" * width for width in widths) + "+"
    output = [rule]
    for row_index, row in enumerate(rows):
        cells = []
        for value, width in zip(row, widths):
            cells.append(_pdf_wrap(value, width) or [""])
        height = max(len(cell) for cell in cells)
        for line_index in range(height):
            values = [cell[line_index] if line_index < len(cell) else "" for cell in cells]
            output.append("|" + "|".join(value[:width].ljust(width) for value, width in zip(values, widths)) + "|")
        output.append(rule if row_index == 0 else rule)
    return output


def _pdf_labeled(label: str, value, width: int = 74) -> list[str]:
    prefix = f"{label}: "
    return _pdf_wrap(value, width, initial_indent=prefix, subsequent_indent=" " * len(prefix))


def _report_pdf_text(record: dict, kind: str, language: str = "ru") -> str:
    if language == "en":
        return _report_pdf_text_en(record, kind)
    findings = record.get("findings") or []
    summary = record.get("summary") or {}
    label = _pdf_clean(record.get("label") or "Мой проект").replace("\n", " ")
    timestamp = record.get("createdAt")
    if isinstance(timestamp, (int, float)):
        checked_at = datetime.fromtimestamp(timestamp, timezone.utc).astimezone().strftime("%d.%m.%Y, %H:%M")
    else:
        checked_at = _pdf_clean(record.get("createdAtISO") or "Не указано")
    is_plan = kind == "fixes"
    heading = "ПЛАН ИСПРАВЛЕНИЙ" if is_plan else "ПОЛНЫЙ ОТЧЁТ ПРОВЕРКИ"
    lines = [
        "SHIELDCODE", heading, "=" * 60,
        *_pdf_labeled("Проект", label),
        *_pdf_labeled("Проверено", checked_at),
        *_pdf_labeled("Оценка", f"{record.get('score', '—')} из 100"),
        *_pdf_labeled("Файлов проверено", record.get("totalFiles", 0)),
        *_pdf_labeled("Найдено проблем", len(findings)),
        *(_pdf_labeled("Файлов не удалось разобрать", int(record.get("skippedFiles", 0) or 0)) if record.get("skippedFiles") else []),
        "",
        "В таблице указано, где искать проблему. Ниже — что проверить и сделать.",
    ]
    summary_line = (
        f"СВОДКА: срочно {int(summary.get('critical', 0) or 0)} | важно {int(summary.get('high', 0) or 0)}"
        f" | планово {int(summary.get('medium', 0) or 0)} | низкие {int(summary.get('low', 0) or 0)}"
        f" | советы {int(summary.get('info', 0) or 0)}"
    )
    lines += ["", *_pdf_wrap(summary_line, 68), "", "ТАБЛИЦА ПРОБЛЕМ", ""]
    if findings:
        problem_rows = [["№", "ВАЖНОСТЬ", "ГДЕ ИСКАТЬ", "ЧТО НАЙДЕНО"]]
        for number, finding in enumerate(findings, 1):
            location = f"{finding.get('file', 'Файл не указан')}:{finding.get('line', '?')}"
            problem_rows.append([
                str(number), PDF_SEVERITY.get(finding.get("severity"), "ПРОВЕРИТЬ"),
                location, finding.get("title", "Найдено совпадение"),
            ])
        lines.extend(_pdf_table(problem_rows, [2, 9, 24, 30]))
    else:
        lines.append("Проверка не нашла знакомых проблем в поддерживаемых файлах.")
    lines += [""]
    if not findings:
        lines.extend([
            "Это хороший результат, но он не доказывает, что ошибок нет. Автоматическая проверка ищет только известные ей признаки.",
            "",
        ])
    page_start_line = 0
    for number, finding in enumerate(findings, 1):
        if number > 1 and len(lines) - page_start_line > 44:
            lines += ["\f", f"SHIELDCODE — {heading} (ПРОДОЛЖЕНИЕ)", ""]
            page_start_line = len(lines)
        severity = PDF_SEVERITY.get(finding.get("severity"), "ПРОВЕРИТЬ")
        location = f"{finding.get('file', 'Файл не указан')}, строка {finding.get('line', '?')}"
        lines += [
            f"{number}. {severity} — {_pdf_clean(finding.get('title') or 'Найдено совпадение')}",
            "-" * 60,
            *_pdf_labeled("Где искать", location),
        ]
        if not is_plan:
            lines += _pdf_labeled("Почему обратить внимание", finding.get("description", ""))
        lines += _pdf_labeled("Что сделать", finding.get("fix", "Проверьте этот участок проекта."))
        if is_plan:
            lines += _pdf_labeled(
                "Если попросить ИИ", "Откройте указанный файл и попросите исправить эту проблему, не меняя остальной проект."
            )
        else:
            example = _pdf_clean(finding.get("example", "")).strip()
            if example:
                lines += ["Пример из отчёта:"]
                for code_line in example.splitlines():
                    lines.extend(_pdf_wrap(code_line, 70, initial_indent="  ", subsequent_indent="  "))
            snippet = _pdf_clean(finding.get("snippet", "")).strip()
            if snippet:
                lines += ["Фрагмент, который стоит проверить (секреты скрыты):"]
                for code_line in snippet.splitlines()[:8]:
                    lines.extend(_pdf_wrap(code_line, 70, initial_indent="  ", subsequent_indent="  "))
        lines.append("")
    checks = record.get("checks") or {}
    if not is_plan and checks:
        status = checks.get("status")
        if status == "completed":
            lines += ["ПРОВЕРКА БИБЛИОТЕК", "Поддерживаемые библиотеки сверены с онлайн-базой известных проблем.", ""]
        elif status == "unavailable":
            lines += ["ПРОВЕРКА БИБЛИОТЕК", "Онлайн-базу проверить не удалось; результаты проверки исходных файлов сохранены.", ""]
    lines += [
        "Автопроверка может ошибаться и пропустить часть проблем. Сохрани копию проекта до замены файлов.",
    ]
    printable_lines = []
    for line in lines:
        if len(line) <= 74:
            printable_lines.append(line)
        else:
            printable_lines.extend(_pdf_wrap(line, 74))
    return "\n".join(printable_lines) + "\n"


def _report_pdf_text_en(record: dict, kind: str) -> str:
    findings = record.get("findings") or []
    summary = record.get("summary") or {}
    label = _pdf_clean(record.get("label") or "My project").replace("\n", " ")
    timestamp = record.get("createdAt")
    if isinstance(timestamp, (int, float)):
        checked_at = datetime.fromtimestamp(timestamp, timezone.utc).astimezone().strftime("%b %d, %Y at %I:%M %p")
    else:
        checked_at = _pdf_clean(record.get("createdAtISO") or "Not specified")
    is_plan = kind == "fixes"
    heading = "FIX PLAN" if is_plan else "FULL SCAN REPORT"
    try:
        translations = json.loads((PUBLIC_DIR / "i18n.json").read_text(encoding="utf-8")).get("en", {})
    except (OSError, ValueError):
        translations = {}
    titles = translations.get("findingTitles", {})
    descriptions = translations.get("findingDescriptions", {})
    fixes = translations.get("findingFixes", {})
    defaults = translations.get("findingDefaults", {})
    severity_labels = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "TIP"}

    def issue_copy(finding):
        title = titles.get(finding.get("id"), titles.get("UNKNOWN", "Potential issue found"))
        if finding.get("id") == "OSV_DEPENDENCY":
            versioned_name = str(finding.get("snippet", "")).split(None, 1)[0] if finding.get("snippet") else "dependency"
            title = title.replace("{name}", versioned_name)
        return title

    lines = [
        "SHIELDCODE", heading, "=" * 60,
        *_pdf_labeled("Project", label),
        *_pdf_labeled("Checked", checked_at),
        *_pdf_labeled("Score", f"{record.get('score', '—')} out of 100"),
        *_pdf_labeled("Files checked", record.get("totalFiles", 0)),
        *_pdf_labeled("Findings", len(findings)),
        *(_pdf_labeled("Files skipped", int(record.get("skippedFiles", 0) or 0)) if record.get("skippedFiles") else []),
        "",
        "The table shows where to look. The notes below explain what to check and do.",
        "",
        f"SUMMARY: critical {int(summary.get('critical', 0) or 0)} | high {int(summary.get('high', 0) or 0)}"
        f" | medium {int(summary.get('medium', 0) or 0)} | low {int(summary.get('low', 0) or 0)}"
        f" | tips {int(summary.get('info', 0) or 0)}",
        "", "FINDINGS TABLE", "",
    ]
    if findings:
        rows = [["#", "PRIORITY", "WHERE TO LOOK", "WHAT WAS FOUND"]]
        for number, finding in enumerate(findings, 1):
            location = f"{finding.get('file', 'File not specified')}:{finding.get('line', '?')}"
            rows.append([str(number), severity_labels.get(finding.get("severity"), "REVIEW"), location, issue_copy(finding)])
        lines.extend(_pdf_table(rows, [2, 10, 25, 28]))
    else:
        lines.append("No known issues were found in the supported files.")
    lines.append("")
    if not findings:
        lines.extend([
            "This is a good result, but it does not prove that the project has no issues. The automated scan only looks for patterns it knows about.",
            "",
        ])
    page_start_line = len(lines)
    for number, finding in enumerate(findings, 1):
        if number > 1 and len(lines) - page_start_line > 44:
            lines += ["\f", f"SHIELDCODE — {heading} (CONTINUED)", ""]
            page_start_line = len(lines)
        severity = severity_labels.get(finding.get("severity"), "REVIEW")
        location = f"{finding.get('file', 'File not specified')}, line {finding.get('line', '?')}"
        lines += [f"{number}. {severity} — {_pdf_clean(issue_copy(finding))}", "-" * 60, *_pdf_labeled("Where to look", location)]
        if not is_plan:
            lines += _pdf_labeled("Why it matters", descriptions.get(finding.get("id"), defaults.get("description", "Review this code pattern and its context.")))
        lines += _pdf_labeled("What to do", fixes.get(finding.get("id"), defaults.get("fix", "Review this code and apply a safe fix.")))
        if is_plan:
            lines += _pdf_labeled("If using an AI assistant", "Open the listed file and ask your coding assistant to fix this issue without changing unrelated parts of the project.")
        else:
            example = _pdf_clean(finding.get("example", "")).strip()
            if example:
                lines.append("Example from the scan:")
                if re.search(r"[А-Яа-яЁё]", example):
                    lines.append("  See the recommendation above for a safe approach.")
                else:
                    for code_line in example.splitlines():
                        lines.extend(_pdf_wrap(code_line, 70, initial_indent="  ", subsequent_indent="  "))
            snippet = _pdf_clean(finding.get("snippet", "")).strip()
            if snippet:
                snippet = re.sub(r"\[СОДЕРЖИМОЕ СКРЫТО\]", "[CONTENT HIDDEN]", snippet, flags=re.I)
                snippet = re.sub(r"\[содержимое не отображается\]", "[content hidden]", snippet, flags=re.I)
                snippet = re.sub(r"\[не найден \.dockerignore\]", "[.dockerignore not found]", snippet, flags=re.I)
                lines.append("Code snippet to review (detected secrets are hidden):")
                for code_line in snippet.splitlines()[:8]:
                    lines.extend(_pdf_wrap(code_line, 70, initial_indent="  ", subsequent_indent="  "))
        lines.append("")
    checks = record.get("checks") or {}
    if not is_plan and checks:
        status = checks.get("status")
        if status == "completed":
            lines += ["DEPENDENCY CHECK", "Supported package versions were checked against the online vulnerability database.", ""]
        elif status == "unavailable":
            lines += ["DEPENDENCY CHECK", "The online database could not be reached. The local source scan was completed and saved.", ""]
    lines += ["Automated scans can be wrong or miss issues. Keep a backup before replacing project files."]
    printable_lines = []
    for line in lines:
        printable_lines.extend([line] if len(line) <= 74 else _pdf_wrap(line, 74))
    return "\n".join(printable_lines) + "\n"


def _make_pdf(text: str, title: str) -> bytes:
    renderer = shutil.which("cupsfilter") or ("/usr/sbin/cupsfilter" if Path("/usr/sbin/cupsfilter").is_file() else None)
    if not renderer:
        raise RuntimeError("В этой системе не найден встроенный способ сохранить документ в PDF.")
    with tempfile.TemporaryDirectory(prefix="shieldcode-pdf-") as temp_dir:
        source = Path(temp_dir) / "shieldcode-document.txt"
        source.write_text(text, encoding="utf-8")
        try:
            result = subprocess.run(
                [renderer, "-i", "text/plain", "-m", "application/pdf", "-t", title, str(source)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Создание PDF заняло слишком много времени. Повтори скачивание.") from exc
    if result.returncode != 0 or not result.stdout.startswith(b"%PDF-"):
        raise RuntimeError("Не удалось подготовить PDF. Перезапусти ShieldCode и попробуй ещё раз.")
    return result.stdout


def _download_disposition(filename: str, fallback: str) -> str:
    safe_fallback = re.sub(r"[^A-Za-z0-9._-]", "_", fallback) or "download"
    return f"attachment; filename=\"{safe_fallback}\"; filename*=UTF-8''{quote(filename, safe='')}"


def score_findings(findings: list[dict]) -> int:
    deductions = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}
    return max(0, 100 - sum(deductions.get(f["severity"], 1) for f in findings))


def summarize(findings: list[dict]) -> dict:
    counts = {s: 0 for s in SEVERITY_RANK}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


_RATE_LIMITS = {}
_RATE_LOCK = threading.Lock()
def _rate_limited(key: str, limit: int, window_seconds: int) -> bool:
    now = time.monotonic()
    with _RATE_LOCK:
        q = _RATE_LIMITS.setdefault(key, deque())
        while q and now - q[0] > window_seconds:
            q.popleft()
        if len(q) >= limit:
            return True
        q.append(now)
        if len(_RATE_LIMITS) > 5000:
            for old_key in list(_RATE_LIMITS)[:1000]: _RATE_LIMITS.pop(old_key, None)
        return False


class ShieldCodeHandler(BaseHTTPRequestHandler):
    server_version = "ShieldCode/2.38"
    sys_version = ""

    def log_message(self, fmt, *args):
        # Keep default logs concise; never log request bodies, tokens, or source contents.
        super().log_message(fmt, *args)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def _send_bytes(self, status: int, data: bytes, content_type: str, extra_headers: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, status: int, obj, extra_headers: dict | None = None):
        data = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers = {"Content-Type": "application/json; charset=utf-8"}
        if extra_headers:
            headers.update(extra_headers)
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_body(self, max_bytes=MAX_REQUEST_BYTES) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Некорректный Content-Length.")
        if length < 0 or length > max_bytes:
            raise ValueError(f"Запрос превышает допустимый размер {max_bytes // (1024 * 1024)} МБ.")
        body = self.rfile.read(length) if length else b""
        if len(body) != length:
            raise ValueError("Не удалось полностью прочитать запрос.")
        return body

    def _json_body(self) -> dict:
        if "application/json" not in self.headers.get("Content-Type", ""):
            raise ValueError("Ожидался JSON-запрос.")
        raw = self._read_body(128 * 1024)
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("Некорректный JSON.")
        if not isinstance(value, dict):
            raise ValueError("Ожидался JSON-объект.")
        return value

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        parsed = urlparse(origin)
        return parsed.netloc.lower() == self.headers.get("Host", "").lower() and parsed.scheme in ("http", "https")

    def _cookie_token(self) -> str | None:
        raw = self.headers.get("Cookie", "")
        jar = cookies.SimpleCookie()
        try:
            jar.load(raw)
        except cookies.CookieError:
            return None
        morsel = jar.get("codeshield_session")
        return morsel.value if morsel else None

    def _user(self):
        token = self._cookie_token()
        if not token:
            return None
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        now = int(time.time())
        with db_connect() as con:
            row = con.execute("SELECT users.id, users.username, users.language FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>?", (token_hash, now)).fetchone()
            return dict(row) if row else None

    def _new_session(self, user_id: int):
        token = secrets.token_urlsafe(36)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        expires = int(time.time()) + SESSION_TTL
        with db_connect() as con:
            con.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)", (token_hash, user_id, expires))
        cookie = f"codeshield_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}" + ("; Secure" if COOKIE_SECURE else "")
        return {"Set-Cookie": cookie}

    def _clear_session(self):
        token = self._cookie_token()
        if token:
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            with db_connect() as con:
                con.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
        cookie = "codeshield_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0" + ("; Secure" if COOKIE_SECURE else "")
        return {"Set-Cookie": cookie}

    def _require_user(self):
        user = self._user()
        if not user:
            self._json(401, {"error": "Войдите в аккаунт, чтобы продолжить."})
            return None
        return user

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/" or path == "/index.html":
            try:
                data = (PUBLIC_DIR / "index.html").read_bytes()
                self._send_bytes(200, data, "text/html; charset=utf-8")
            except OSError:
                self._send_bytes(500, b"App files missing", "text/plain; charset=utf-8")
            return
        if path in ("/app.js", "/i18n.json", "/style.css", "/theme-light.css", "/theme-dark.css", "/favicon.svg", "/shieldcode-liquid-glass.svg"):
            file_path = PUBLIC_DIR / path.lstrip("/")
            content_type = "application/javascript; charset=utf-8" if path.endswith(".js") else "application/json; charset=utf-8" if path.endswith(".json") else "image/svg+xml" if path.endswith(".svg") else "text/css; charset=utf-8"
            try:
                self._send_bytes(200, file_path.read_bytes(), content_type)
            except OSError:
                self._send_bytes(404, b"Not found", "text/plain; charset=utf-8")
            return
        if path == "/favicon.ico":
            self._send_bytes(204, b"", "image/x-icon")
            return
        if path == "/api/health":
            self._json(200, {"ok": True, "version": "2.38", "scanner": "built-in-static", "maxFiles": MAX_FILES, "maxFileBytes": MAX_FILE_BYTES, "maxRequestBytes": MAX_REQUEST_BYTES, "onlineDependencyChecks": "automatic OSV lookup; package names and versions only"})
            return
        if path == "/api/me":
            user = self._user()
            if user:
                self._json(200, {"authenticated": True, "user": user})
            else:
                self._json(200, {"authenticated": False})
            return
        if path == "/api/scans":
            user = self._require_user()
            if not user:
                return
            with db_connect() as con:
                rows = con.execute("SELECT id,created_at,label,total_files,skipped_files,score,findings_count,summary_json FROM scans WHERE user_id=? ORDER BY created_at DESC LIMIT 50", (user["id"],)).fetchall()
            scans = []
            for r in rows:
                scans.append({"id": r["id"], "createdAt": r["created_at"], "label": r["label"], "totalFiles": r["total_files"], "skippedFiles": r["skipped_files"], "score": r["score"], "findingsCount": r["findings_count"], "summary": json.loads(r["summary_json"])})
            self._json(200, {"scans": scans})
            return
        match = re.fullmatch(r"/api/scans/([a-f0-9]{16})", path)
        if match:
            user = self._require_user()
            if not user:
                return
            with db_connect() as con:
                row = con.execute("SELECT * FROM scans WHERE id=? AND user_id=?", (match.group(1), user["id"])).fetchone()
            if not row:
                self._json(404, {"error": "Проверка не найдена."})
                return
            self._json(200, self._scan_record(row, include_findings=True))
            return
        match = re.fullmatch(r"/api/scans/([a-f0-9]{16})/(report|fixes)", path)
        if match:
            user = self._require_user()
            if not user:
                return
            scan_id, kind = match.groups()
            with db_connect() as con:
                row = con.execute("SELECT * FROM scans WHERE id=? AND user_id=?", (scan_id, user["id"])).fetchone()
            if not row:
                self._json(404, {"error": "Проверка не найдена."})
                return
            record = self._scan_record(row, include_findings=True)
            try:
                language = parse_qs(parsed.query).get("lang", ["ru"])[0]
                language = "en" if language == "en" else "ru"
                pdf_title = ("ShieldCode - Fix Plan" if kind == "fixes" else "ShieldCode - Full Report") if language == "en" else ("ShieldCode - план исправлений" if kind == "fixes" else "ShieldCode - полный отчет")
                data = _make_pdf(_report_pdf_text(record, kind, language), pdf_title)
            except RuntimeError as exc:
                self._json(503, {"error": str(exc)})
                return
            base_name = Path(_pdf_clean(record.get("label") or "проект").split(",", 1)[0]).stem
            if language == "en":
                base_name = re.sub(r"[^A-Za-z0-9._-]+", "_", base_name).strip("._-") or "Project"
                filename = f"Fix_Plan_{base_name}.pdf" if kind == "fixes" else f"Full_Report_{base_name}.pdf"
            else:
                base_name = re.sub(r"[^A-Za-zА-Яа-яЁё0-9._-]+", "_", base_name).strip("._-") or "проект"
                filename = f"План_исправлений_{base_name}.pdf" if kind == "fixes" else f"Полный_отчёт_{base_name}.pdf"
            fallback = f"shieldcode-{kind}-{scan_id}.pdf"
            self._send_bytes(200, data, "application/pdf", {"Content-Disposition": _download_disposition(filename, fallback)})
            return
        self._send_bytes(404, b"Not found", "text/plain; charset=utf-8")

    @staticmethod
    def _scan_record(row, include_findings=False):
        record = {
            "id": row["id"], "createdAt": row["created_at"],
            "createdAtISO": datetime.fromtimestamp(row["created_at"], timezone.utc).isoformat(),
            "label": row["label"], "totalFiles": row["total_files"],
            "skippedFiles": row["skipped_files"], "score": row["score"],
            "findingsCount": row["findings_count"], "summary": json.loads(row["summary_json"]),
            "checks": json.loads(row["checks_json"] or "{}") if "checks_json" in row.keys() else {},
        }
        if include_findings:
            record["findings"] = json.loads(row["findings_json"])
        return record

    def do_POST(self):
        path = urlparse(self.path).path
        if not self._origin_ok():
            self._json(403, {"error": "Запрос с другого источника отклонён."})
            return
        remote = self.client_address[0] if self.client_address else "unknown"
        scope = "scan" if path in {"/api/scan", "/api/fixpack"} else "auth" if path in {"/api/login", "/api/register"} else "write"
        limit, window = ((10, 60) if scope == "scan" else (8, 300) if scope == "auth" else (30, 60))
        if _rate_limited(f"{remote}:{scope}", limit, window):
            self._json(429, {"error": "Слишком много запросов. Подожди немного и повтори попытку."}, {"Retry-After": str(window)})
            return
        try:
            if path == "/api/register":
                body = self._json_body()
                username = str(body.get("username", "")).strip()
                password = str(body.get("password", ""))
                language = "en" if body.get("language") == "en" else "ru"
                if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
                    self._json(400, {"error": "Логин должен содержать 3–32 символа: латинские буквы, цифры, точку, дефис или подчёркивание."})
                    return
                if len(password) < 10 or len(password) > 128:
                    self._json(400, {"error": "Пароль должен содержать от 10 до 128 символов."})
                    return
                password_iterations = 600_000
                salt, digest = password_hash(password, iterations=password_iterations)
                try:
                    with db_connect() as con:
                        cur = con.execute("INSERT INTO users(username,password_salt,password_hash,created_at,password_iterations,language) VALUES(?,?,?,?,?,?)", (username, salt, digest, int(time.time()), password_iterations, language))
                        user_id = cur.lastrowid
                except sqlite3.IntegrityError:
                    self._json(409, {"error": "Такой логин уже занят."})
                    return
                headers = self._new_session(user_id)
                self._json(201, {"authenticated": True, "user": {"id": user_id, "username": username, "language": language}}, headers)
                return
            if path == "/api/login":
                body = self._json_body()
                username = str(body.get("username", "")).strip()
                password = str(body.get("password", ""))
                if len(username) > 32 or len(password) > 128:
                    self._json(401, {"error": "Неверный логин или пароль."})
                    return
                with db_connect() as con:
                    row = con.execute("SELECT id,username,password_salt,password_hash,password_iterations,language FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone()
                if not row:
                    # Constant-ish work to reduce obvious username timing differences.
                    password_hash(password or "incorrect", b"codeshield-constant-salt", 600_000)
                    self._json(401, {"error": "Неверный логин или пароль."})
                    return
                _, calculated = password_hash(password, row["password_salt"], int(row["password_iterations"] or 310_000))
                if not hmac.compare_digest(calculated, row["password_hash"]):
                    self._json(401, {"error": "Неверный логин или пароль."})
                    return
                headers = self._new_session(row["id"])
                self._json(200, {"authenticated": True, "user": {"id": row["id"], "username": row["username"], "language": row["language"]}}, headers)
                return
            if path == "/api/language":
                user = self._require_user()
                if not user:
                    return
                body = self._json_body()
                language = body.get("language")
                if language not in ("ru", "en"):
                    self._json(400, {"error": "Выбери русский или английский язык."})
                    return
                with db_connect() as con:
                    con.execute("UPDATE users SET language=? WHERE id=?", (language, user["id"]))
                self._json(200, {"ok": True, "language": language})
                return
            if path == "/api/logout":
                user = self._user()
                headers = self._clear_session()
                self._json(200, {"authenticated": False}, headers)
                return
            if path == "/api/fixpack":
                user = self._require_user()
                if not user:
                    return
                content_type = self.headers.get("Content-Type", "")
                if not content_type.lower().startswith("multipart/form-data"):
                    self._json(400, {"error": "Загрузите исходные файлы через форму."})
                    return
                parts = parse_multipart(content_type, self._read_body())
                uploaded_files = [(filename, payload) for field, filename, payload in parts if field == "files" and filename]
                files, archive_entries, skipped, label = collect_fixpack_project(parts)
                patched, changes = sec.apply_safe_fixes(files)
                summary = build_fixpack_summary(files, patched, changes)
                summary_headers = {
                    "X-ShieldCode-Before": str(summary["before"]),
                    "X-ShieldCode-After": str(summary["after"]),
                    "X-ShieldCode-Fixed": str(summary["fixed"]),
                    "X-ShieldCode-Edits": str(summary["edits"]),
                    "X-ShieldCode-Files": str(summary["files"]),
                }
                patched_contents = {filename: content.encode("utf-8") for filename, content in patched}

                is_single_plain_file = (
                    len(uploaded_files) == 1
                    and not uploaded_files[0][0].lower().endswith(".zip")
                    and len(archive_entries) == 1
                )
                if is_single_plain_file:
                    original_name, original_bytes = archive_entries[0]
                    output_bytes = patched_contents.get(original_name, original_bytes)
                    source_path = Path(original_name)
                    output_name = f"{source_path.stem}_исправленный{source_path.suffix}"
                    mime_type = mimetypes.guess_type(source_path.name)[0] or "application/octet-stream"
                    self._send_bytes(200, output_bytes, mime_type, {
                        "Content-Disposition": _download_disposition(output_name, f"shieldcode-fixed{source_path.suffix or '.txt'}"),
                        **summary_headers,
                    })
                    return

                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
                    for filename, original in archive_entries:
                        zf.writestr(filename, patched_contents.get(filename, original))
                out = buf.getvalue()
                project_stem = Path(uploaded_files[0][0]).stem if len(uploaded_files) == 1 else "проект"
                project_stem = re.sub(r"[^A-Za-zА-Яа-яЁё0-9._-]+", "_", project_stem).strip("._-") or "проект"
                output_name = f"{project_stem}_исправленный.zip"
                self._send_bytes(200, out, "application/zip", {
                    "Content-Disposition": _download_disposition(output_name, "shieldcode-fixed-project.zip"),
                    **summary_headers,
                })
                return
            if path == "/api/scan":
                user = self._require_user()
                if not user:
                    return
                content_type = self.headers.get("Content-Type", "")
                if not content_type.lower().startswith("multipart/form-data"):
                    self._json(400, {"error": "Загрузите файлы через форму."})
                    return
                body = self._read_body()
                parts = parse_multipart(content_type, body)
                files, skipped, label = extract_files(parts)
                findings = scan_sources(files)
                # Always check supported dependency versions. Only package coordinates are sent; source files stay local.
                online_result = sec.check_dependencies_osv(files)
                findings.extend(online_result.get("findings", []))
                findings = sorted(findings, key=lambda f: (SEVERITY_RANK.get(f["severity"], 9), f["file"].lower(), f["line"], f["id"]))[:MAX_FINDINGS]
                score = score_findings(findings)
                summary = summarize(findings)
                checks = {k:v for k,v in online_result.items() if k != "findings"}
                now = int(time.time())
                scan_id = secrets.token_hex(8)
                with db_connect() as con:
                    con.execute("INSERT INTO scans(id,user_id,created_at,label,total_files,skipped_files,score,findings_count,summary_json,findings_json,checks_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (scan_id, user["id"], now, label[:160], len(files), skipped, score, len(findings), json.dumps(summary), json.dumps(findings, ensure_ascii=False), json.dumps(checks, ensure_ascii=False)))
                record = {"id": scan_id, "createdAt": now, "createdAtISO": datetime.fromtimestamp(now, timezone.utc).isoformat(), "label": label, "totalFiles": len(files), "skippedFiles": skipped, "score": score, "findingsCount": len(findings), "summary": summary, "findings": findings, "checks": checks, "note": "Статический анализ ищет известные шаблоны и не доказывает наличие или отсутствие эксплуатируемой уязвимости. Исходные файлы не сохраняются в истории; сохраняются только отчёт и обезличенные фрагменты находок. Проверка поддерживаемых библиотек выполняется автоматически через онлайн-базу; отправляются только их названия и версии, исходный код не передаётся."}
                self._json(201, record)
                return
            self._json(404, {"error": "Неизвестный endpoint."})
        except ValueError as e:
            self._json(400, {"error": str(e)})
        except Exception as e:
            # Do not disclose stack traces or paths to the user.
            print(f"[ShieldCode] request failed: {type(e).__name__}")
            self._json(500, {"error": "Внутренняя ошибка сервера. Проверьте формат файлов и повторите попытку."})

    def do_HEAD(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()


def main():
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), ShieldCodeHandler)
    server.daemon_threads = True
    print("=" * 58)
    print(" ShieldCode — локальный сервер")
    print(f" Адрес: http://{HOST}:{PORT}")
    print(f" База данных: {DB_PATH}")
    print(" Загруженный код анализируется как текст и не исполняется.")
    print(" Нажмите Ctrl+C для остановки.")
    print("=" * 58)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановка ShieldCode...")
    finally:
        server.server_close()

if __name__ == "__main__":
    main()
