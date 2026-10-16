"""Additional language/configuration security heuristics and automatic OSV dependency lookup.

No uploaded source code is executed. Regex matches are leads for manual review, not proof of exploitability.
"""
from __future__ import annotations
import ast
import io
import json
import re
import shlex
import tokenize
from pathlib import Path, PurePosixPath

EXTENSIONS_EXTRA = {
    ".xhtml", ".svelte", ".astro", ".jinja", ".jinja2", ".j2", ".ejs", ".pug", ".hbs", ".handlebars", ".mustache", ".twig", ".erb", ".xsl", ".xsd", ".graphqls", ".sqlx", ".adoc", ".nix", ".jinja", ".jinja2", ".j2", ".ejs", ".pug", ".hbs", ".handlebars", ".mustache", ".twig", ".erb", ".xsl", ".xsd", ".graphqls", ".sqlx", ".adoc", ".nix", ".sass", ".less", ".map", ".ipynb", ".graphql", ".gql",
    ".pyw", ".phtml", ".kt", ".kts", ".fs", ".vb", ".cc", ".hpp", ".hh", ".mm", ".swift",
    ".dart", ".rs", ".scala", ".sc", ".pl", ".pm", ".r", ".lua", ".ex", ".exs", ".erl", ".hrl",
    ".clj", ".cljs", ".groovy", ".sol", ".vy", ".prisma", ".proto", ".thrift", ".asm", ".bash",
    ".zsh", ".ps1", ".psm1", ".bat", ".cmd", ".jsonc", ".json5", ".cfg", ".tf", ".tfvars", ".hcl",
    ".tfstate", ".service", ".socket", ".rules", ".policy", ".pem", ".key", ".pub", ".crt", ".cer",
    ".der", ".p12", ".pfx", ".jks", ".keystore", ".lock", ".sum", ".mod", ".gradle", ".csproj",
    ".sln", ".targets", ".props", ".nuspec", ".plist", ".xcconfig", ".mobileprovision", ".c", ".h", ".cpp", ".cxx", ".c++",
    ".lockb", ".gradle.kts", ".dockerfile", ".tfplan", ".tfstate.backup", ".service.yaml",
    ".mdx", ".rst", ".bicep", ".rego", ".cue", ".fish", ".f", ".for", ".f90", ".f95",
    ".pas", ".pp", ".hxx", ".ixx", ".cob", ".cbl", ".elm", ".m", ".swiftinterface",
}
SPECIAL_FILENAMES = {
    ".env", ".envrc", ".npmrc", ".pypirc", ".netrc", ".htaccess", ".dockerignore", ".gitignore", ".gitlab-ci.yml",
    "dockerfile", "containerfile", "makefile", "gemfile", "gemfile.lock", "rakefile", "procfile", "caddyfile",
    "nginx.conf", "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "requirements-dev.txt", "pipfile", "pipfile.lock", "poetry.lock", "uv.lock", "pyproject.toml",
    "cargo.toml", "cargo.lock", "go.mod", "go.sum", "composer.json", "composer.lock", "pubspec.yaml", "pubspec.lock",
    "mix.exs", "mix.lock", "podfile", "podfile.lock", "gradle.lockfile", "pom.xml", "build.gradle", "build.gradle.kts",
    "gradle.properties", "nuget.config", "packages.config", "terraform.tfstate", "terraform.tfstate.backup",
    "id_rsa", "id_ed25519", "id_ecdsa", "credentials", "known_hosts", "authorized_keys", "caddyfile",
    "pnpm-lock.yaml", "yarn.lock", "packages.lock.json", "packages.config", "global.json", "nuget.config",
    "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml", "serverless.yml", "vercel.json",
    "netlify.toml", "firebase.json", "firestore.rules", "security.rules", "app.yaml", "Procfile",
    "bun.lock", "deno.lock", "bunfig.toml", "deno.json", "deno.jsonc", "biome.json", "biome.jsonc",
    "renovate.json", ".prettierrc", ".prettierrc.json", ".prettierrc.yaml", ".eslintrc", ".eslintrc.json",
    "dependabot.yml", "dependabot.yaml", "justfile", "taskfile.yml", "taskfile.yaml",
}

# Some formats are configuration-oriented: rule applicability is deliberately scoped where possible.
RULES = [
    dict(id="GITHUB_TOKEN", severity="critical", title="Возможный GitHub-токен в исходниках",
         pattern=re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
         description="Строка похожа на токен GitHub.", fix="Отзовите токен, проверьте журналы доступа и создайте новый токен с минимальными правами.",
         example="# Храните токен в серверном secret store; не встраивайте его во frontend."),
    dict(id="GITLAB_TOKEN", severity="critical", title="Возможный GitLab-токен в исходниках",
         pattern=re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), description="Строка похожа на токен GitLab.",
         fix="Отзовите токен, изучите журналы доступа и замените его секретом с наименьшими правами.", example="# Используйте protected CI/CD variables или хранилище секретов."),
    dict(id="SLACK_TOKEN", severity="critical", title="Возможный токен Slack в исходниках",
         pattern=re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), description="Строка похожа на токен Slack API.",
         fix="Отзовите/ротируйте токен и проверьте рабочие пространства и журналы событий.", example="# Держите токены интеграций только в серверном secret store."),
    dict(id="STRIPE_SECRET", severity="critical", title="Возможный секретный ключ Stripe",
         pattern=re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b"), description="Строка похожа на production-секрет Stripe.",
         fix="Деактивируйте ключ, проверьте события и создайте замену с минимальными правами.", example="# Платёжный секрет хранится на сервере; браузер получает только публичный ключ."),
    dict(id="GOOGLE_API_KEY", severity="high", title="Возможный ключ Google API",
         pattern=re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"), description="Строка похожа на ключ Google API.",
         fix="Проверьте квоты, ограничьте ключ по API/рефереру/IP, а при утечке замените его.", example="# Ограничивайте ключи у провайдера; приватные операции выполняйте на сервере."),
    dict(id="JWT_LITERAL", severity="high", title="Похоже на встроенный JWT",
         pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
         description="Найдено значение, похожее на JSON Web Token.", fix="Не коммитьте токены. Если токен настоящий — отзовите/ротируйте его и изучите аудит.",
         example="# Не размещайте токены в репозитории, логах или публичной клиентской сборке."),
    dict(id="HARDCODED_SECRET_UNQUOTED", severity="high", title="Возможный секрет без кавычек в конфигурации",
         pattern=re.compile(r"(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|secret[_-]?key|aws_secret_access_key|database_url)\b[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_./+=-]{8,})"),
         description="Значение поля, похожего на секрет, записано напрямую в конфигурации. Это может быть тестовое значение; проверьте вручную.",
         fix="Удалите реальный секрет из файла, смените его после подтверждённой утечки и храните на сервере в переменной окружения или secret store.",
         example="API_KEY = os.environ.get('API_KEY')  # серверная среда, не клиентский код"),
    dict(id="JWT_VERIFY_DISABLED", severity="high", title="Возможное отключение проверки JWT",
         pattern=re.compile(r"(?i)(?:verify_signature\s*[\"']?\s*:\s*False|algorithms?\s*=\s*\[\s*[\"']none[\"']|algorithms\s*:\s*\[\s*[\"']none[\"']|ignoreExpiration\s*:\s*true)"),
         description="Настройка может отключать проверку подписи или срока действия JWT.", fix="Проверяйте подпись, алгоритм по allowlist, issuer, audience и срок действия.",
         example="# Явно укажите разрешённые алгоритмы и проверяйте обязательные claims."),
    dict(id="YAML_UNSAFE_LOAD", severity="high", title="Возможная небезопасная загрузка YAML",
         pattern=re.compile(r"\byaml\s*\.\s*load\s*\("), description="Некоторые YAML-loader могут создавать произвольные объекты.",
         fix="Используйте yaml.safe_load() или SafeLoader и проверяйте схему.", example="data = yaml.safe_load(untrusted_yaml)"),
    dict(id="UNSAFE_DESERIALIZATION", severity="high", title="Потенциально небезопасная десериализация",
         pattern=re.compile(r"(?i)(?:ObjectInputStream\s*\(|new\s+BinaryFormatter\s*\(|BinaryFormatter\s*\.\s*Deserialize\s*\(|\bMarshal\s*\.\s*load\s*\(|\bunserialize\s*\(|jsonpickle\s*\.\s*decode\s*\()"),
         description="Десериализация объектов из недоверенных данных может привести к выполнению кода или созданию небезопасных объектов.",
         fix="Не десериализуйте объекты из недоверенных источников; используйте ограниченную схему и безопасные API.",
         example="# Предпочитайте JSON с явной проверкой полей и типов."),
    dict(id="WEAK_CRYPTO_HASH", severity="medium", title="Использование MD5 или SHA-1",
         pattern=re.compile(r"(?i)(?:\bmd5\s*\(|\bsha1\s*\(|hashlib\.(?:md5|sha1)\s*\(|createHash\s*\(\s*[\"'](?:md5|sha1)[\"']\s*\))"),
         description="MD5/SHA-1 не подходят для новых криптографических применений. Для паролей нужны специальные медленные алгоритмы.",
         fix="Для целостности используйте современный хеш по требованиям задачи; для паролей — Argon2id, scrypt, bcrypt или PBKDF2 с корректными параметрами.",
         example="# Не используйте быстрые хеши для хранения паролей."),
    dict(id="WEAK_PASSWORD_HASH", severity="high", title="Слабый хеш пароля",
         pattern=re.compile(r"(?i)(?:md5\s*\(\s*password|sha1\s*\(\s*password|createHash\s*\(\s*[\"'](?:md5|sha1)[\"']\s*\)\s*\.\s*update\s*\(\s*password|hashlib\.(?:md5|sha1)\s*\(\s*password)"),
         description="Быстрые универсальные хеши плохо защищают парольный хеш от перебора.",
         fix="Используйте Argon2id, scrypt, bcrypt или PBKDF2-HMAC-SHA256 с достаточным work factor и уникальной солью.",
         example="# Используйте проверенную библиотеку для password hashing."),
    dict(id="INSECURE_RANDOM", severity="medium", title="Неподходящий генератор случайных значений",
         pattern=re.compile(r"(?i)(?:Math\s*\.\s*random\s*\(|random\s*\.\s*(?:random|randint|choice)\s*\()"),
         description="Обычный PRNG может быть предсказуемым и не должен использоваться для токенов, сессий и reset-ссылок.",
         fix="Для секретов используйте crypto.randomBytes, secrets.token_urlsafe или SecureRandom. Math.random допустим для несекретных игровых эффектов.",
         example="# Python: secrets.token_urlsafe(32); Node.js: crypto.randomBytes(32)"),
    dict(id="OPEN_REDIRECT", severity="medium", title="Возможный open redirect",
         pattern=re.compile(r"(?i)(?:res\.redirect\s*\(\s*(?:req|request)\.(?:query|params|body)|redirect\s*\(\s*(?:request|req)\.(?:args|GET|query)|(?:window\.location(?:\.href)?|location\.href)\s*=\s*(?:req|request|params|searchParams))"),
         description="Адрес перенаправления может зависеть от пользовательского ввода.",
         fix="Используйте ID разрешённого маршрута или проверяйте URL по allowlist доверенных origin.",
         example="const target = allowedRedirects.has(input) ? input : '/';"),
    dict(id="SSRF_SUSPECT", severity="medium", title="Потенциальный SSRF: запрос к URL из ввода",
         pattern=re.compile(r"(?i)(?:requests\.(?:get|post|put|delete|request)\s*\(\s*(?:url|request\.|user|input|params)|fetch\s*\(\s*(?:req\.|request\.|userInput|userUrl|params\.)|axios\.(?:get|post|request)\s*\(\s*(?:req\.|request\.|user|params\.))"),
         description="Ввод пользователя может участвовать в формировании адреса серверного запроса.",
         fix="Используйте allowlist доменов/схем, блокируйте внутренние адреса, контролируйте redirects и сетевой egress.",
         example="# Проверяйте scheme + hostname по allowlist до серверного HTTP-запроса."),
    dict(id="PATH_TRAVERSAL", severity="high", title="Возможная небезопасная сборка пути к файлу",
         pattern=re.compile(r"(?i)(?:sendFile\s*\(\s*(?:req|request)\.|readFile(?:Sync)?\s*\(\s*(?:req|request)\.(?:query|params|body)|open\s*\(\s*(?:request\.(?:args|GET|POST)|user_input|filename)\s*(?:\+|,)|(?<![A-Za-z0-9_])Path\s*\(\s*(?:request\.|user_input|filename))"),
         description="Путь к файлу может зависеть от пользовательского ввода, что создаёт риск выхода за разрешённую директорию.",
         fix="Предпочитайте ID вместо путей; нормализуйте итоговый путь и проверьте, что он остаётся внутри разрешённой директории.",
         example="# Сравните resolve() итогового пути с resolve() корневой разрешённой директории."),
    dict(id="CSP_UNSAFE_INLINE", severity="medium", title="Ослабленная Content Security Policy",
         pattern=re.compile(r"(?i)(?:script-src[^;\n]*'unsafe-inline'|script-src[^;\n]*'unsafe-eval')"),
         description="unsafe-inline/unsafe-eval ослабляют CSP против XSS.",
         fix="По возможности удалите unsafe-inline/unsafe-eval; для нужных inline-скриптов используйте nonce/hash.",
         example="Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-<случайный-nonce>'"),
    dict(id="IFRAME_NO_SANDBOX", severity="medium", title="iframe без sandbox",
         pattern=re.compile(r"(?i)<iframe\b(?![^>]*\bsandbox\b)[^>]*>"), description="Встраиваемый документ без sandbox может получить лишние возможности.",
         fix="Добавьте sandbox с минимальными разрешениями или откажитесь от iframe, если он не нужен.",
         example="<iframe src=\"...\" sandbox title=\"Встроенный контент\"></iframe>"),
    dict(id="SRI_MISSING", severity="low", title="Внешний скрипт/стиль без SRI",
         pattern=re.compile(r"(?i)<script\b(?=[^>]*\bsrc\s*=\s*['\"]https?://)(?![^>]*\bintegrity\s*=)[^>]*>|<link\b(?=[^>]*\bhref\s*=\s*['\"]https?://)(?=[^>]*\brel\s*=\s*['\"]stylesheet['\"])(?![^>]*\bintegrity\s*=)[^>]*>"),
         description="Для фиксированных CDN-ресурсов Subresource Integrity позволяет браузеру проверять хеш содержимого.",
         fix="Для неизменяемой версии добавьте integrity и crossorigin или разместите проверенную копию локально.",
         example="<script src=\"https://cdn.example/library.js\" integrity=\"sha384-...\" crossorigin=\"anonymous\"></script>"),
    dict(id="SHELL_PIPE_DOWNLOAD", severity="high", title="Скачивание и немедленный запуск удалённого скрипта",
         pattern=re.compile(r"(?i)(?:curl|wget)[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b"),
         description="Удалённый контент запускается без предварительной проверки подписи или контрольной суммы.",
         fix="Закрепите версию, скачайте артефакт отдельно и проверьте подпись/хеш до исполнения.",
         example="# Не передавайте скачанный поток напрямую в оболочку."),
    dict(id="PERMISSIVE_CHMOD", severity="medium", title="Слишком широкие права доступа к файлам",
         pattern=re.compile(r"(?i)(?:chmod\s+(?:-R\s+)?(?:777|a\s*\+\s*rwx)|mode\s*=\s*0o?777)"),
         description="Права на чтение/запись/исполнение для всех пользователей часто избыточны.",
         fix="Применяйте минимально необходимые права доступа в зависимости от владельца и назначения файла.", example="chmod 640 config-file"),
    dict(id="COOKIE_SAMESITE_NONE", severity="medium", title="SameSite=None без явного Secure",
         pattern=re.compile(r"(?i)(?:SameSite\s*=\s*None|sameSite\s*:\s*['\"]none['\"])(?![^\n]{0,120}(?:Secure|secure\s*:\s*true))"),
         description="SameSite=None допускает cross-site отправку cookie; в современных браузерах для неё требуется Secure.",
         fix="Используйте SameSite=Lax/Strict, если возможно. Для None обязательно Secure и CSRF-защита.",
         example="Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax"),
    dict(id="LOGS_SECRET", severity="medium", title="Возможная запись секрета в логи",
         pattern=re.compile(r"(?i)(?:console\.(?:log|info|warn|error)|print|logger\.(?:info|debug|warning|error))\s*\([^\n]*(?:password|passwd|access[_-]?token|secret|api[_-]?key|authorization|cookie)"),
         description="Логирование секретов может создать дополнительное место утечки.",
         fix="Логируйте тип события и безопасный идентификатор; маскируйте пароли, токены, cookie и заголовки авторизации.",
         example="logger.info('Login attempt failed for user_id=%s', safe_user_id)"),
    dict(id="DOCKER_LATEST", severity="medium", title="Docker-образ использует тег latest",
         pattern=re.compile(r"(?im)^\s*FROM\s+[^\s#]+:latest\b"), description="Тег latest меняется со временем и снижает воспроизводимость сборки.",
         fix="Закрепите проверенную версию и по возможности digest образа; обновляйте через контролируемый процесс.",
         example="FROM python:3.13-slim@sha256:<проверенный-digest>", docker_only=True),
    dict(id="DOCKER_ROOT", severity="high", title="Dockerfile явно запускает контейнер от root",
         pattern=re.compile(r"(?im)^\s*USER\s+(?:root|0)(?:\s|$)"), description="Процесс контейнера работает с root-правами.",
         fix="Создайте непривилегированного пользователя и переключитесь на него в финальном stage.",
         example="RUN adduser --disabled-password --gecos '' appuser\nUSER appuser", docker_only=True),
    dict(id="DOCKER_SECRET_ENV", severity="high", title="Секрет может быть встроен в Dockerfile",
         pattern=re.compile(r"(?im)^\s*(?:ARG|ENV)\s+[A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY)[A-Za-z0-9_]*\s*[:= ]\s*\S+"),
         description="Значения ARG/ENV могут попасть в метаданные образа, историю слоёв или логи сборки.",
         fix="Не задавайте секреты через ARG/ENV; используйте BuildKit secrets или runtime secret manager.",
         example="RUN --mount=type=secret,id=api_key ...", docker_only=True),
    dict(id="DOCKER_SOCKET", severity="critical", title="Доступ к сокету Docker",
         pattern=re.compile(r"/var/run/docker\.sock"), description="Монтирование Docker socket в контейнер может дать чрезмерный контроль над хостом.",
         fix="Не подключайте docker.sock к обычным контейнерам; используйте ограниченный API и отдельный изолированный worker.",
         example="# Не монтируйте /var/run/docker.sock в приложение."),
    dict(id="K8S_PRIVILEGED", severity="critical", title="Kubernetes-контейнер privileged",
         pattern=re.compile(r"(?im)^\s*privileged\s*:\s*true\b"), description="Privileged-контейнер получает расширенные полномочия ядра.",
         fix="Удалите privileged, настройте runAsNonRoot, readOnlyRootFilesystem, seccomp и минимальные capabilities.",
         example="securityContext:\n  privileged: false\n  allowPrivilegeEscalation: false", kubernetes_only=True),
    dict(id="K8S_HOSTPATH", severity="high", title="Kubernetes использует hostPath",
         pattern=re.compile(r"(?im)^\s*hostPath\s*:"), description="hostPath монтирует путь узла в контейнер; риск зависит от пути и прав записи.",
         fix="Предпочитайте PVC/ConfigMap/Secret; если hostPath необходим, используйте ограниченный путь и readOnly.",
         example="# Используйте отдельный PersistentVolumeClaim вместо произвольного hostPath.", kubernetes_only=True),
    dict(id="K8S_HOST_NETWORK", severity="medium", title="Kubernetes использует hostNetwork/hostPID/hostIPC",
         pattern=re.compile(r"(?im)^\s*(?:hostNetwork|hostPID|hostIPC)\s*:\s*true\b"), description="Совместное использование namespace узла уменьшает изоляцию pod.",
         fix="Отключите hostNetwork/hostPID/hostIPC, если это не требуется документированной причиной.", example="hostNetwork: false", kubernetes_only=True),
    dict(id="K8S_TOKEN_AUTOMOUNT", severity="medium", title="Автоматическое монтирование service account token",
         pattern=re.compile(r"(?im)^\s*automountServiceAccountToken\s*:\s*true\b"), description="Токен доступен процессам внутри pod и может дать доступ к Kubernetes API.",
         fix="Отключите automount, если API не нужен; ограничьте RBAC минимально необходимыми разрешениями.", example="automountServiceAccountToken: false", kubernetes_only=True),
    dict(id="TF_OPEN_INGRESS", severity="high", title="Terraform разрешает сетевой доступ из любой сети",
         pattern=re.compile(r"(?i)(?:cidr_blocks?\s*=\s*\[?\s*['\"]0\.0\.0\.0/0|ipv6_cidr_blocks?\s*=\s*\[?\s*['\"]::/0)"),
         description="Правило может открыть порт всему интернету; публичный HTTPS может быть допустим, а admin-порты обычно должны быть ограничены.",
         fix="Ограничьте CIDR и порты; отдельно проверьте SSH/RDP/DB/admin-порты.", example="cidr_blocks = [\"<доверенный-CIDR>\"]", terraform_only=True),
    dict(id="TF_ENCRYPTION_DISABLED", severity="high", title="В Terraform отключено шифрование хранения",
         pattern=re.compile(r"(?i)\b(?:encrypted|storage_encrypted|enable_encryption|encrypt_at_rest)\s*=\s*false\b"),
         description="Ресурс может хранить данные без шифрования на стороне сервиса.", fix="Включите шифрование платформы и проверьте управление ключами, ротацию и доступ.",
         example="storage_encrypted = true", terraform_only=True),
    dict(id="GHA_WRITE_ALL", severity="high", title="GitHub Actions получили write-all permissions",
         pattern=re.compile(r"(?im)^\s*permissions\s*:\s*write-all\s*$"), description="Широкие разрешения увеличивают последствия компрометации workflow или стороннего action.",
         fix="Задайте read-only по умолчанию и разрешайте write только конкретным scopes/jobs.", example="permissions:\n  contents: read", workflow_only=True),
    dict(id="GHA_MUTABLE_REF", severity="medium", title="GitHub Action закреплён изменяемой веткой",
         pattern=re.compile(r"(?im)^\s*uses\s*:\s*[^\s@]+@(?:main|master|develop|latest)\s*$"), description="Изменяемая ветка может поменять используемый action без изменения workflow.",
         fix="Закрепляйте action на проверенном полном commit SHA и регулярно обновляйте его после review.", example="uses: owner/action@<полный-проверенный-commit-SHA>", workflow_only=True),
    dict(id="GHA_UNTRUSTED_INPUT", severity="high", title="Возможная инъекция через данные события GitHub Actions",
         pattern=re.compile(r"\$\{\{\s*github\.event\.(?:pull_request\.(?:title|body|head\.ref)|issue\.(?:title|body)|comment\.body)\s*\}\}"),
         description="Поля события могут контролироваться внешним участником. Прямая подстановка в shell может приводить к command injection.",
         fix="Не вставляйте expression напрямую в run; передавайте значение через env и обрабатывайте как данные. Особенно осторожно с pull_request_target.",
         example="env:\n  PR_TITLE: ${{ github.event.pull_request.title }}\nrun: printf '%s\\n' \"$PR_TITLE\"", workflow_only=True),
    dict(id="GHA_PERSIST_CREDENTIALS", severity="medium", title="GitHub Actions сохраняет токен Git в рабочей папке",
         pattern=re.compile(r"(?im)^\s*persist-credentials\s*:\s*true\b"),
         description="Checkout action может оставить токен в настройках Git. Последующие шаги workflow тогда потенциально могут использовать его.",
         fix="Для checkout задайте persist-credentials: false, если дальнейшие git push этим токеном не нужны. Если нужны — ограничьте права и доверенные шаги.",
         example="- uses: actions/checkout@<проверенный-commit-SHA>\n  with:\n    persist-credentials: false", workflow_only=True),
    dict(id="COOKIE_HTTPONLY_DISABLED", severity="medium", title="Для cookie явно отключён HttpOnly",
         pattern=re.compile(r"(?i)\bhttpOnly\s*[:=]\s*(?:false|0)\b"),
         description="HttpOnly=false позволяет JavaScript читать такую cookie. Для сессионных cookie это может увеличить последствия XSS.",
         fix="Для сессионной cookie включите HttpOnly; проверьте, что frontend не должен читать это значение.",
         example="res.cookie('session', value, { httpOnly: true, secure: true, sameSite: 'lax' })",
         suffixes={".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".vue", ".svelte", ".py", ".pyw", ".rb", ".php"}),
    dict(id="COOKIE_SECURE_DISABLED", severity="medium", title="Для cookie явно отключён Secure",
         pattern=re.compile(r"(?i)\bsecure\s*[:=]\s*(?:false|0)\b"),
         description="Secure=false разрешает отправку cookie по незашифрованному HTTP. В production это может раскрыть сессию.",
         fix="Для production-cookie включите Secure и обслуживайте сайт по HTTPS. Локальную разработку проверяйте отдельно.",
         example="res.cookie('session', value, { httpOnly: true, secure: true, sameSite: 'lax' })",
         suffixes={".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".vue", ".svelte", ".py", ".pyw", ".rb", ".php"}),
    dict(id="XML_EXTERNAL_ENTITY", severity="high", title="Возможная XML External Entity (XXE)",
         pattern=re.compile(r"(?i)<!ENTITY\s+\w+\s+SYSTEM\s+['\"]|DocumentBuilderFactory|XMLReaderFactory"),
         description="XML-парсер с внешними сущностями может раскрыть файлы или инициировать сетевые запросы, если DTD/XXE не отключены.",
         fix="Отключите внешние сущности/DTD, включите secure processing и не разбирайте недоверенный XML небезопасным парсером.",
         example="# Отключите external general/parameter entities и DTD."),
    dict(id="FRONTEND_SECRET_PREFIX", severity="high", title="Потенциальный секрет с публичным frontend-префиксом",
         pattern=re.compile(r"(?i)\b(?:VITE|NEXT_PUBLIC|REACT_APP|NUXT_PUBLIC|PUBLIC)_[A-Z0-9_]*(?:SECRET|PRIVATE_KEY|ACCESS_TOKEN|PASSWORD|CLIENT_SECRET|SERVICE_ROLE)[A-Z0-9_]*\b\s*[:=]"),
         description="Публичные frontend-переменные часто встраиваются в клиентскую сборку и видны посетителям.",
         fix="Не помещайте приватные ключи в клиентские env-переменные; перенесите секретные операции на сервер.",
         example="# VITE_PUBLIC_ENDPOINT допустим; VITE_SERVICE_ROLE_SECRET — нет."),
    dict(id="PHP_ALLOW_URL_INCLUDE", severity="high", title="Включён allow_url_include в PHP-конфигурации",
         pattern=re.compile(r"(?im)^\s*allow_url_include\s*=\s*on\b"), description="Загрузка удалённых файлов в include/require повышает риск удалённого выполнения кода.",
         fix="Отключите allow_url_include и не включайте путь к файлу из пользовательского ввода.", example="allow_url_include = Off", config_only=True),
    dict(id="PHP_ASSERT_INPUT", severity="high", title="Потенциально опасный assert в PHP",
         pattern=re.compile(r"(?i)\bassert\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)|\$[A-Za-z_]\w*\s*\.)"), description="Использование недоверенного ввода в assert может быть небезопасным и зависит от версии/контекста.",
         fix="Не используйте assert для проверки пользовательского ввода; применяйте явные проверки типов и допустимых значений.", example="if (!is_string($value)) { throw new InvalidArgumentException(); }", suffixes={".php", ".phtml"}),
    dict(id="C_UNSAFE_STRING_FUNCTION", severity="high", title="Потенциально небезопасная C/C++ строковая функция",
         pattern=re.compile(r"\b(?:gets|strcpy|strcat|sprintf|vsprintf)\s*\("), description="Функции без ограничения длины могут приводить к переполнению буфера, если вход не ограничен.",
         fix="Используйте функции с проверкой размера/границ, например snprintf, и валидируйте длину входных данных.", example='snprintf(dst, sizeof(dst), "%s", src);', suffixes={".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}),
    dict(id="JAVA_RUNTIME_EXEC", severity="high", title="Выполнение системной команды в JVM-коде",
         pattern=re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\("), description="Запуск системной команды требует особенно осторожного контроля аргументов.",
         fix="Избегайте сборки команд из пользовательского ввода; передавайте аргументы отдельными элементами и используйте allowlist операций.", example='ProcessBuilder("safe-tool", validatedArgument)', suffixes={".java", ".kt", ".kts", ".scala"}),
    dict(id="COOKIE_FLAGS_MISSING", severity="medium", title="Cookie может быть создана без защитных флагов",
         pattern=re.compile(r"(?i)(?:res\.cookie|setcookie|set_cookie|response\.set_cookie)\s*\([^\n]*(?:session|auth|token)[^\n]*\)"), description="Cookie с сессией должна использовать подходящие HttpOnly, Secure и SameSite флаги.",
         fix="Проверьте конфигурацию cookie: HttpOnly, Secure при HTTPS, SameSite=Lax/Strict, ограниченные Path/Domain и срок действия.", example="Set-Cookie: session=…; Secure; HttpOnly; SameSite=Lax", suffixes={".js", ".mjs", ".ts", ".py", ".php", ".rb", ".java"}),
    dict(id="CSP_UNSAFE_EVAL", severity="medium", title="CSP может разрешать unsafe-eval",
         pattern=re.compile(r"(?i)script-src[^\n;]*'unsafe-eval'"), description="Разрешение eval в Content Security Policy ослабляет защиту от инъекций скриптов.",
         fix="Удалите unsafe-eval, если приложение не требует его; откажитесь от eval/new Function и проверьте совместимость.", example="Content-Security-Policy: script-src 'self'", suffixes={".html", ".htm", ".conf", ".config", ".json", ".yaml", ".yml"}),
    dict(id="CORS_REFLECT_ORIGIN", severity="medium", title="Origin запроса может отражаться в CORS-ответе",
         pattern=re.compile(r"(?i)(?:Access-Control-Allow-Origin|allowOrigin)\s*[:=]\s*(?:req(?:uest)?\.headers\.origin|request\.headers\[['\"]origin['\"]\])"), description="Отражение произвольного Origin может разрешить недоверенным сайтам читать ответы, если остальные настройки тоже позволяют доступ.",
         fix="Сопоставляйте Origin с точным allowlist; для запросов с credentials никогда не используйте отражение без проверки.", example="if (allowedOrigins.has(origin)) setHeader('Access-Control-Allow-Origin', origin);"),
    dict(id="PY_TEMPFILE_MKTEMP", severity="medium", title="Используется небезопасное создание временного файла",
         pattern=re.compile(r"\btempfile\.mktemp\s*\("), description="mktemp только возвращает имя и подвержен гонке между выбором имени и созданием файла.",
         fix="Используйте tempfile.NamedTemporaryFile, TemporaryDirectory или безопасный open с эксклюзивным созданием.", example="with tempfile.NamedTemporaryFile() as temp:", suffixes={".py", ".pyw"}),
    dict(id="DOTNET_DANGEROUS_TYPE", severity="high", title="Потенциально опасная десериализация .NET",
         pattern=re.compile(r"(?i)(?:TypeNameHandling\s*=\s*TypeNameHandling\.All|BinaryFormatter|LosFormatter)"), description="Некоторые .NET-десериализаторы могут создавать произвольные типы из недоверенного ввода.",
         fix="Избегайте BinaryFormatter/LosFormatter для недоверенных данных; ограничьте типы и используйте безопасный формат/настройки.", example="System.Text.Json с явной DTO-схемой", suffixes={".cs", ".config", ".json", ".xml"}),

    dict(id="TEMPLATE_UNSAFE_MARKUP", severity="high", title="Возможен обход экранирования в шаблоне",
         pattern=re.compile(r"(?i)(?:\|\s*safe\b|\bmark_safe\s*\(|\bMarkup\s*\()"),
         description="Специальный маркер может отключить автоматическое экранирование HTML. Риск зависит от того, может ли значение контролироваться пользователем.",
         fix="Не отключайте escaping для недоверенных строк. Если HTML необходим, используйте проверенную allowlist-санитизацию и тесты XSS.",
         example="{{ user_text }}  {# не добавляйте |safe без обоснования и санитизации #}", suffixes={".py", ".html", ".htm", ".jinja", ".jinja2", ".j2", ".ejs", ".pug", ".hbs", ".handlebars", ".mustache", ".twig", ".erb", ".xsl", ".xsd", ".graphqls", ".sqlx", ".adoc", ".nix", ".vue", ".svelte"}),
    dict(id="PY_RENDER_TEMPLATE_STRING", severity="medium", title="Шаблон рендерится из строки",
         pattern=re.compile(r"\brender_template_string\s*\("),
         description="Рендеринг динамической строки как шаблона может стать SSTI, если строка зависит от пользователя.",
         fix="Предпочитайте заранее подготовленные шаблоны и передавайте значения как данные; не вставляйте пользовательский ввод в текст шаблона.",
         example="return render_template('page.html', value=user_value)", suffixes={".py", ".pyw"}),
    dict(id="PY_TAR_EXTRACTALL", severity="medium", title="Извлечение TAR-архива без проверки путей",
         pattern=re.compile(r"\.extractall\s*\("),
         description="Извлечение недоверенного TAR-архива может приводить к записи файлов вне ожидаемой папки, если пути не ограничены. Защита зависит от версии Python и параметров вызова.",
         fix="Не распаковывайте недоверенные архивы вслепую. Используйте безопасные фильтры tarfile (например, data filter где доступен), проверяйте имена и пишите в отдельную временную папку.",
         example="with tarfile.open(path) as archive:\n    archive.extractall(destination, filter='data')", suffixes={".py", ".pyw"}),
    dict(id="NODE_TLS_VERIFY_DISABLED", severity="high", title="Отключена проверка TLS-сертификатов Node.js",
         pattern=re.compile(r"(?i)NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['\"]?0\b"),
         description="Отключение проверки TLS делает HTTPS-соединения уязвимыми для перехвата и подмены сертификата.",
         fix="Удалите эту настройку и исправьте цепочку сертификатов. Не компенсируйте ошибки TLS отключением проверки.",
         example="# Удалите NODE_TLS_REJECT_UNAUTHORIZED=0", suffixes={".js", ".mjs", ".cjs", ".ts", ".json", ".yaml", ".yml", ".env", ".sh", ".conf", ".properties"}),
    dict(id="GO_TLS_INSECURE_SKIP_VERIFY", severity="high", title="Отключена проверка TLS в Go",
         pattern=re.compile(r"(?i)InsecureSkipVerify\s*:\s*true\b"),
         description="Параметр отключает стандартную проверку сертификата и имени сервера.",
         fix="Оставьте стандартную проверку TLS; при необходимости настройте доверенные CA и проверку имени сервера.",
         example="tls.Config{MinVersion: tls.VersionTLS12}", suffixes={".go"}),
    dict(id="JAVA_TRUST_ALL_CERTS", severity="high", title="Возможен доверенный всеми сертификатами TLS-клиент",
         pattern=re.compile(r"(?i)(?:NoopHostnameVerifier|TrustAllStrategy|ALLOW_ALL_HOSTNAME_VERIFIER)"),
         description="Такие классы/константы могут отключать проверку имени хоста или доверять любым сертификатам.",
         fix="Используйте стандартную проверку сертификатов и hostname verification; доверяйте только нужным CA.",
         example="Используйте системный trust store и стандартный hostname verifier.", suffixes={".java", ".kt", ".kts", ".scala"}),
    dict(id="CSRF_PROTECTION_DISABLED", severity="medium", title="Возможное отключение защиты CSRF",
         pattern=re.compile(r"(?i)(?:@csrf_exempt\b|WTF_CSRF_ENABLED\s*=\s*False|csrf_protect\s*[:=]\s*False|csrf\s*:\s*false)"),
         description="Отключение CSRF-защиты может позволить другому сайту инициировать действия от имени вошедшего пользователя. Контекст приложения важен.",
         fix="Включите CSRF-защиту для изменяющих состояние запросов и проверяйте токен; исключения документируйте и защищайте отдельно.",
         example="Включите CSRF-проверку framework и используйте токен в формах.", suffixes={".py", ".pyw", ".js", ".ts", ".yaml", ".yml", ".json", ".conf", ".ini"}),
    dict(id="DJANGO_WILDCARD_ALLOWED_HOSTS", severity="medium", title="Django ALLOWED_HOSTS разрешает любой Host",
         pattern=re.compile(r"(?i)ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]\s*\]"),
         description="Шаблонный ALLOWED_HOSTS снимает штатное ограничение Host header и может быть опасен в производственной конфигурации.",
         fix="Укажите конкретные домены своего приложения; оставляйте wildcard только при осознанной архитектуре и дополнительной защите.",
         example="ALLOWED_HOSTS = ['app.example.com']", suffixes={".py", ".pyw"}),
    dict(id="PHP_DYNAMIC_INCLUDE", severity="high", title="Подключение PHP-файла по пользовательскому вводу",
         pattern=re.compile(r"(?i)\b(?:include|include_once|require|require_once)\s*(?:\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE)\b"),
         description="Путь include/require, зависящий от запроса, может приводить к включению нежелательного локального или удалённого файла.",
         fix="Не используйте пользовательский ввод напрямую как путь. Сопоставляйте идентификатор с фиксированным allowlist файлов.",
         example="$pages = ['home' => __DIR__ . '/home.php'];\nrequire $pages[$validatedPage] ?? $pages['home'];", suffixes={".php", ".phtml"}),
    dict(id="POSTMESSAGE_WILDCARD_ORIGIN", severity="medium", title="postMessage отправляет сообщение любому origin",
         pattern=re.compile(r"(?i)\.postMessage\s*\([^\n]*,\s*['\"]\*['\"]\s*\)"),
         description="Целевой origin '*' разрешает передать сообщение любому окну; это небезопасно, если сообщение содержит чувствительные данные.",
         fix="Укажите точный ожидаемый origin и на принимающей стороне проверяйте event.origin и структуру сообщения.",
         example="targetWindow.postMessage(message, 'https://trusted.example')", suffixes={".js", ".mjs", ".cjs", ".ts", ".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte"}),
    dict(id="CORS_CREDENTIALS_WILDCARD", severity="high", title="CORS сочетает wildcard origin и credentials",
         pattern=re.compile(r"(?i)(?:Access-Control-Allow-Origin\s*[:=]\s*['\"]?\*|origin\s*:\s*['\"]\*['\"])[^\n]*(?:Access-Control-Allow-Credentials\s*[:=]\s*['\"]?true|credentials\s*:\s*true)|(?:Access-Control-Allow-Credentials\s*[:=]\s*['\"]?true|credentials\s*:\s*true)[^\n]*(?:Access-Control-Allow-Origin\s*[:=]\s*['\"]?\*|origin\s*:\s*['\"]\*['\"])"),
         description="Wildcard origin вместе с credentials обычно некорректен/опасен; соседние настройки могут находиться в разных строках и потребуют ручной проверки.",
         fix="Используйте точный allowlist origin. Не отражайте входящий Origin без проверки и ограничивайте доступ к ответам.",
         example="const allowedOrigins = new Set(['https://app.example.com']);", suffixes={".js", ".mjs", ".cjs", ".ts", ".json", ".yaml", ".yml", ".conf", ".ini", ".py", ".php"}),

    dict(id="PY_SUBPROCESS_SHELL_TRUE", severity="high", title="subprocess может запускаться с shell=True",
         pattern=re.compile(r"(?i)subprocess\.(?:run|call|popen|check_output|check_call)\s*\([^\n]*\bshell\s*=\s*True\b"),
         description="shell=True передаёт команду shell-интерпретатору. Если команда включает пользовательские данные, возможна command injection.",
         fix="Передавайте executable и аргументы списком, отключите shell и валидируйте аргументы по allowlist.",
         example="subprocess.run(['tool', validated_arg], check=True)", suffixes={".py", ".pyw"}),
    dict(id="RUBY_UNSAFE_YAML_LOAD", severity="high", title="Потенциально небезопасная загрузка YAML в Ruby",
         pattern=re.compile(r"\bYAML\.(?:load|unsafe_load)\s*\("),
         description="Загрузка YAML от недоверенного источника может создавать небезопасные объекты в зависимости от версии Ruby и loader.",
         fix="Для недоверенных данных используйте safe_load с разрешёнными классами/символами или безопасный парсер по версии Ruby.",
         example="YAML.safe_load(input, permitted_classes: [], permitted_symbols: [], aliases: false)", suffixes={".rb"}),
    dict(id="EJS_UNESCAPED_OUTPUT", severity="medium", title="EJS выводит значение без HTML-экранирования",
         pattern=re.compile(r"<%-\s*[^\n]+?%>"),
         description="Синтаксис EJS `<%- ... %>` выводит HTML без escaping и может стать XSS при использовании недоверенных данных.",
         fix="Для обычного текста используйте экранирующий синтаксис `<%= value %>`; raw HTML применяйте только после проверенной санитизации.",
         example="<%= userDisplayName %>", suffixes={".ejs"}),
    dict(id="SPRING_ACTUATOR_EXPOSE_ALL", severity="medium", title="Spring Actuator может раскрывать все endpoints",
         pattern=re.compile(r"(?i)management\.endpoints\.web\.exposure\.include\s*[:=]\s*['\"]\*['\"]"),
         description="Публикация всех Actuator endpoints может раскрыть чувствительную диагностическую информацию или административные функции, если доступ не ограничен.",
         fix="Открывайте только необходимые endpoints и защищайте их аутентификацией, сетью и отдельными правами доступа.",
         example="management.endpoints.web.exposure.include=health,info", suffixes={".properties", ".yml", ".yaml", ".conf"}),

]

SECRET_IDS = {"PRIVATE_KEY", "CLOUD_KEY", "HARDCODED_SECRET", "HARDCODED_SECRET_UNQUOTED", "GITHUB_TOKEN", "GITLAB_TOKEN", "SLACK_TOKEN", "STRIPE_SECRET", "GOOGLE_API_KEY", "JWT_LITERAL", "FRONTEND_SECRET_PREFIX"}

OWASP = {
    "A01": "A01:2025 Broken Access Control",
    "A02": "A02:2025 Security Misconfiguration",
    "A03": "A03:2025 Software Supply Chain Failures",
    "A04": "A04:2025 Cryptographic Failures",
    "A05": "A05:2025 Injection",
    "A06": "A06:2025 Insecure Design",
    "A07": "A07:2025 Authentication Failures",
    "A08": "A08:2025 Software or Data Integrity Failures",
    "A09": "A09:2025 Security Logging and Alerting Failures",
    "A10": "A10:2025 Mishandling of Exceptional Conditions",
}
RULE_OWASP = {
    "GITHUB_TOKEN":"A04", "GITLAB_TOKEN":"A04", "SLACK_TOKEN":"A04", "STRIPE_SECRET":"A04", "GOOGLE_API_KEY":"A04",
    "JWT_LITERAL":"A07", "JWT_VERIFY_DISABLED":"A07", "WEAK_PASSWORD_HASH":"A07", "OPEN_REDIRECT":"A01", "SSRF_SUSPECT":"A01",
    "DOCKER_LATEST":"A03", "GHA_MUTABLE_REF":"A03", "GHA_WRITE_ALL":"A01", "TF_OPEN_INGRESS":"A02",
    "TF_ENCRYPTION_DISABLED":"A02", "K8S_PRIVILEGED":"A02", "K8S_HOSTPATH":"A02", "CSP_UNSAFE_INLINE":"A02",
    "WEAK_CRYPTO_HASH":"A04", "YAML_UNSAFE_LOAD":"A08", "UNSAFE_DESERIALIZATION":"A08", "XML_EXTERNAL_ENTITY":"A05",
    "HARDCODED_SECRET_UNQUOTED":"A04", "FRONTEND_SECRET_PREFIX":"A04", "LOGS_SECRET":"A09", "COOKIE_SAMESITE_NONE":"A07",
    "DOCKER_SECRET_ENV":"A04", "DOCKER_SOCKET":"A02", "K8S_HOST_NETWORK":"A02", "K8S_TOKEN_AUTOMOUNT":"A01",
    "SHELL_PIPE_DOWNLOAD":"A03", "SRI_MISSING":"A08", "IFRAME_NO_SANDBOX":"A02", "PERMISSIVE_CHMOD":"A02",
    "TEMPLATE_UNSAFE_MARKUP":"A05", "PY_RENDER_TEMPLATE_STRING":"A05", "PY_TAR_EXTRACTALL":"A08",
    "NODE_TLS_VERIFY_DISABLED":"A04", "GO_TLS_INSECURE_SKIP_VERIFY":"A04", "JAVA_TRUST_ALL_CERTS":"A04",
    "CSRF_PROTECTION_DISABLED":"A01", "DJANGO_WILDCARD_ALLOWED_HOSTS":"A02", "PHP_DYNAMIC_INCLUDE":"A05",
    "POSTMESSAGE_WILDCARD_ORIGIN":"A01", "CORS_CREDENTIALS_WILDCARD":"A01",
    "COOKIE_HTTPONLY_DISABLED":"A07", "COOKIE_SECURE_DISABLED":"A07", "GHA_PERSIST_CREDENTIALS":"A03",
    "PY_SUBPROCESS_SHELL_TRUE":"A05", "RUBY_UNSAFE_YAML_LOAD":"A08", "EJS_UNESCAPED_OUTPUT":"A05", "SPRING_ACTUATOR_EXPOSE_ALL":"A02",
}


def redact_text(text: str) -> str:
    """Mask common credentials in displayed snippets and saved reports."""
    text = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY_BLOCK]", text, flags=re.S)
    text = re.sub(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]", text)
    key_names = r"(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|secret[_-]?key|secret|token|jwt|private[_-]?key|aws_secret_access_key|aws_session_token|database_url|connection_string)"
    # JSON/YAML and quoted assignments, without retaining the credential value.
    text = re.sub(rf"(?i)([\"']?{key_names}[\"']?\s*:\s*)([\"'])(.*?)([\"'])", r'\1"[REDACTED]"', text)
    text = re.sub(rf"(?i)([\"']?{key_names}[\"']?\s*:\s*)([^\s,;#'\"]{{6,}})", r"\1[REDACTED]", text)
    text = re.sub(rf"(?i)(\b{key_names}\b\s*=\s*)([\"'])(.*?)([\"'])", r'\1"[REDACTED]"', text)
    text = re.sub(rf"(?i)(\b{key_names}\b\s*=\s*)([^\s,;#'\"]{{6,}})", r"\1[REDACTED]", text)
    replacements = [
        (r"\bAKIA[0-9A-Z]{16}\b", "[REDACTED_CLOUD_KEY]"),
        (r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b", "[REDACTED_GITHUB_TOKEN]"),
        (r"\bglpat-[A-Za-z0-9_-]{20,}\b", "[REDACTED_GITLAB_TOKEN]"),
        (r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "[REDACTED_SLACK_TOKEN]"),
        (r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b", "[REDACTED_STRIPE_KEY]"),
        (r"\bAIza[0-9A-Za-z_-]{30,}\b", "[REDACTED_GOOGLE_KEY]"),
        (r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "[REDACTED_JWT]"),
        (r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/-]+=*", r"\1[REDACTED]"),
        (r"(?i)([?&](?:token|key|secret|password|api_key|access_token)=)[^&\s'\"]+", r"\1[REDACTED]"),
    ]
    for pattern, replacement in replacements:
        text = re.sub(pattern, replacement, text)
    return text


# ---------------------------------------------------------------------------
# Context filtering shared by the scanner and the automatic fixer.
#
# Both sides must agree on what is "real code": otherwise the scanner reports
# problems the fixer will (rightly) never touch, and the fixer may edit text
# that only *describes* a problem (rule descriptions, docs, translations).
# ---------------------------------------------------------------------------
PROSE_SUFFIXES = {".md", ".mdx", ".rst", ".adoc"}
LOCALE_HINTS = ("i18n", "locale", "locales", "translation", "translations")
TEST_DIR_NAMES = {"tests", "test", "__tests__", "fixtures", "fixture", "spec", "specs", "__mocks__", "testdata"}
TEST_FILE_RE = re.compile(r"^(?:test_.+\.py|.+_test\.(?:py|go)|.+\.(?:test|spec)\.(?:js|jsx|ts|tsx|mjs|cjs))$", re.I)
_SPECIAL_LOWER = {name.lower() for name in SPECIAL_FILENAMES}
# A line that only *defines* a rule (title/description/fix/example/pattern ...) contains example code inside a string.
RULE_META_LINE = re.compile(
    r"""^\s*(?:dict\(\s*)?["']?(?:id|title|description|fix|example|pattern|message|hint|help)["']?\s*[:=]\s*(?:re\.compile\(|[rRbBfF]{0,2}["'])"""
)
HEURISTIC_SECRET_IDS = {"HARDCODED_SECRET", "HARDCODED_SECRET_UNQUOTED"}
IGNORE_SAME_LINE = re.compile(r"shieldcode\s*:\s*ignore(?!-next-line)", re.I)
IGNORE_NEXT_LINE = re.compile(r"shieldcode\s*:\s*ignore-next-line", re.I)


def _norm_path(filename: str) -> PurePosixPath:
    return PurePosixPath(filename.replace("\\", "/"))


def is_prose_file(filename: str) -> bool:
    """Documentation and translation files describe code; they do not run it."""
    path = _norm_path(filename)
    suffix, leaf = path.suffix.lower(), path.name.lower()
    if suffix in PROSE_SUFFIXES:
        return True
    if suffix == ".txt" and leaf not in _SPECIAL_LOWER:
        return True
    if suffix in {".json", ".json5", ".jsonc"}:
        folders = [part.lower() for part in path.parts[:-1]]
        if any(hint in leaf for hint in LOCALE_HINTS) or any(folder in LOCALE_HINTS for folder in folders):
            return True
    return False


def is_test_path(filename: str) -> bool:
    """Test fixtures intentionally contain vulnerable-looking samples and are not shipped."""
    path = _norm_path(filename)
    if any(part.lower() in TEST_DIR_NAMES for part in path.parts[:-1]):
        return True
    return bool(TEST_FILE_RE.match(path.name))


def is_comment_line(line: str) -> bool:
    """A whole-line comment executes nothing. (A '#' directly followed by a letter is not a comment: #include, #id, #private.)"""
    stripped = line.strip()
    return stripped.startswith(("//", "/*", "# ", "#!")) or stripped == "#"


def line_is_ignored(line: str, previous_line: str = "") -> bool:
    return bool(IGNORE_SAME_LINE.search(line) or IGNORE_NEXT_LINE.search(previous_line or ""))


def should_skip_finding(rule_id: str, filename: str, line: str, previous_line: str = "") -> bool:
    """True when a regex hit is documentation, a test sample, a rule definition or explicitly ignored."""
    if line_is_ignored(line, previous_line):
        return True
    if rule_id in SECRET_IDS:
        # Real key formats (private keys, cloud/GitHub/Slack/Stripe tokens ...) are reported everywhere: they are dangerous even
        # in docs and tests. Only the generic "name = 'value'" guesses are ignored in docs and test fixtures.
        return rule_id in HEURISTIC_SECRET_IDS and (is_prose_file(filename) or is_test_path(filename))
    if is_prose_file(filename) or is_test_path(filename):
        return True
    return is_comment_line(line) or bool(RULE_META_LINE.match(line))


def _applies(rule: dict, filename: str, suffix: str, leaf: str) -> bool:
    if rule.get("docker_only") and leaf not in {"dockerfile", "containerfile"} and not filename.lower().endswith(".dockerfile"):
        return False
    if rule.get("terraform_only") and suffix not in {".tf", ".tfvars", ".hcl", ".tfstate"}:
        return False
    if rule.get("kubernetes_only") and suffix not in {".yaml", ".yml", ".json"}:
        return False
    if rule.get("workflow_only") and ".github/workflows/" not in filename.lower().replace("\\", "/"):
        return False
    if rule.get("suffixes") and suffix not in rule["suffixes"]:
        return False
    if rule.get("config_only") and suffix not in {".ini", ".conf", ".config", ".properties", ".yaml", ".yml", ".php.ini", ".txt", ".env"}:
        return False
    return True


def _make_finding(rule: dict, filename: str, line_no: int, line: str) -> dict:
    rid = rule["id"]
    snippet = "[СОДЕРЖИМОЕ СЕКРЕТА СКРЫТО]" if rid in SECRET_IDS else redact_text(line.strip()[:300])
    code = RULE_OWASP.get(rid)
    return {
        "id": rid, "severity": rule["severity"], "title": rule["title"], "file": filename,
        "line": max(1, line_no), "snippet": snippet, "description": rule["description"], "fix": rule["fix"],
        "example": rule["example"], "confidence": "low" if rid in {"OPEN_REDIRECT", "SSRF_SUSPECT", "PATH_TRAVERSAL"} else "medium",
        "owasp": OWASP.get(code, "Secure coding review"), "category": "Advanced static analysis", "source": "built-in",
    }


def scan_advanced_sources(files: list[tuple[str, str]]) -> list[dict]:
    findings = []
    dockerfiles = []
    dockerignore_present = False
    for filename, content in files:
        suffix = Path(filename).suffix.lower()
        leaf = Path(filename).name.lower()
        if leaf in {"dockerfile", "containerfile"} or filename.lower().endswith(".dockerfile"):
            dockerfiles.append((filename, content))
        if leaf == ".dockerignore":
            dockerignore_present = True
        scan_content = content
        lines = content.splitlines()
        if suffix == ".ipynb":
            try:
                nb = json.loads(content)
                lines = []
                for cell in nb.get("cells", []):
                    if cell.get("cell_type") == "code":
                        src = cell.get("source", [])
                        lines.extend(src if isinstance(src, list) else str(src).splitlines())
            except (ValueError, AttributeError, TypeError):
                findings.append({"id":"INVALID_NOTEBOOK", "severity":"low", "title":"Не удалось разобрать Jupyter Notebook", "file":filename, "line":1, "snippet":"[notebook JSON]", "description":"Структура .ipynb не распознана; кодовые ячейки могли быть пропущены.", "fix":"Проверьте JSON notebook и сохраните файл из Jupyter.", "example":"", "confidence":"medium", "owasp":"File validation", "category":"File validation", "source":"built-in"})
        for line_no, line in enumerate(lines, 1):
            if not line.strip():
                continue
            previous_line = lines[line_no - 2] if line_no > 1 else ""
            for rule in RULES:
                if not _applies(rule, filename, suffix, leaf) or not rule["pattern"].search(line):
                    continue
                rid = rule["id"]
                # Documentation, test samples, rule definitions and lines marked "shieldcode: ignore" are not vulnerabilities.
                if should_skip_finding(rid, filename, line, previous_line):
                    continue
                # The fix recommended by the report must make the finding disappear.
                if rid == "PY_TAR_EXTRACTALL" and re.search(r"\bfilter\s*=", line):
                    continue
                if rid == "TEMPLATE_UNSAFE_MARKUP" and not rule["pattern"].search(re.sub(r"\{#.*?#\}", "", line)):
                    continue  # the filter sits inside a Jinja comment block, which is never rendered
                if rid == "GHA_UNTRUSTED_INPUT":
                    key = re.match(r"^\s*(?:-\s*)?([A-Za-z_][\w.-]*)\s*:\s*['\"]?\$\{\{", line)
                    if key and key.group(1).lower() != "run":
                        continue  # passing the value through env:/with: is the recommended safe pattern
                if rid == "COOKIE_FLAGS_MISSING" and re.search(r"(?i)httponly\s*[:=]\s*(?:true|1)\b", line) and re.search(r"(?i)\bsecure\s*[:=]\s*(?:true|1)\b", line):
                    continue  # HttpOnly and Secure are set explicitly
                if rid == "PATH_TRAVERSAL":
                    # Path(name).name / .suffix / .stem only take a part of a string: this is sanitising, not file access.
                    if not rule["pattern"].search(re.sub(r"Path\s*\([^()]*\)\s*\.(?:name|suffix|suffixes|stem)\b", "", line)):
                        continue
                if rid == "YAML_UNSAFE_LOAD" and re.search(r"(?:safe_load|SafeLoader)", line, re.I):
                    continue
                if rid == "HARDCODED_SECRET_UNQUOTED":
                    low = line.lower()
                    # HTML autocomplete hints such as 'new-password' / 'current-password' are not credentials.
                    if re.search(r"autocomplete|new-password|current-password|type\s*=\s*[\"']password", low):
                        continue
                    if any(token in low for token in ("process.env", "os.environ", "getenv(", "env.get(", "secretmanager", "secret_manager", "placeholder", "changeme", "your_key", "example_key")):
                        continue
                    match = rule["pattern"].search(line)
                    value = match.group(1).lower() if match and match.lastindex else ""
                    if not value or any(token in value for token in ("example", "dummy", "placeholder", "changeme", "replace_me", "your_", "redacted", "null", "none")):
                        continue
                if rid == "IFRAME_NO_SANDBOX" and re.search(r"\bsandbox\b", line, re.I):
                    continue
                if rid == "SRI_MISSING" and re.search(r"\bintegrity\s*=", line, re.I):
                    continue
                if rid == "INSECURE_RANDOM" and not re.search(r"token|secret|session|nonce|password|reset|csrf|auth|key", line, re.I):
                    continue
                if rid in {"COOKIE_HTTPONLY_DISABLED", "COOKIE_SECURE_DISABLED"} and not re.search(r"cookie|session|auth|token|set[_-]?cookie", line, re.I):
                    continue
                if rid == "WEAK_CRYPTO_HASH" and not re.search(r"password|passwd|hash|sign|verify|digest|checksum|token", line, re.I):
                    continue
                if rid == "OPEN_REDIRECT" and re.search(r"allowlist|allowed_redirect|safe_redirect", line, re.I):
                    continue
                findings.append(_make_finding(rule, filename, line_no, line))
        if leaf in {".env", ".env.local", ".env.production", ".env.development"} or (leaf.startswith(".env.") and leaf != ".env.example"):
            findings.append({"id":"ENV_FILE_INCLUDED", "severity":"high", "title":"Файл .env включён в набор проекта", "file":filename, "line":1, "snippet":"[СОДЕРЖИМОЕ СКРЫТО]", "description":"Файл .env часто содержит реальные секреты. Если он попадёт в публичный репозиторий, клиентскую сборку или webroot, значения могут утечь.", "fix":"Не публикуйте .env; добавьте его в .gitignore и .dockerignore. Используйте .env.example только с фиктивными значениями. При реальной утечке смените секреты.", "example":".env\n.env.*\n!.env.example", "confidence":"medium", "owasp":"A04:2025 Cryptographic Failures", "category":"Secrets management", "source":"built-in"})
        if leaf in {"id_rsa", "id_ed25519", "id_ecdsa"} or suffix in {".p12", ".pfx", ".keystore", ".jks", ".der"}:
            findings.append({"id":"PRIVATE_CREDENTIAL_FILE", "severity":"high", "title":"Включён файл приватного ключа/keystore", "file":filename, "line":1, "snippet":"[СОДЕРЖИМОЕ СКРЫТО]", "description":"Приватные ключи и keystore обычно не должны находиться в клиентском проекте или публичном репозитории.", "fix":"Уберите файл из репозитория и webroot. При публикации отзовите/замените связанные ключи и проверьте историю Git.", "example":"Добавьте файл в .gitignore и храните его в защищённом хранилище.", "confidence":"medium", "owasp":"A04:2025 Cryptographic Failures", "category":"Secrets management", "source":"built-in"})
        if leaf == ".dockerignore" and not re.search(r"(?m)^\s*(?:\.env|\.env\.\*|\*\.pem|\*\.key)\s*$", content):
            findings.append({"id":"DOCKERIGNORE_SECRETS", "severity":"medium", "title":"В .dockerignore не найдено очевидных исключений для секретов", "file":filename, "line":1, "snippet":"[содержимое не отображается]", "description":"Файлы env/ключей могут случайно попасть в контекст Docker-сборки.", "fix":"Добавьте точные исключения для секретных файлов и убедитесь, что нужные файлы не включаются обратно.", "example":".env\n.env.*\n!.env.example\n*.pem\n*.key", "confidence":"low", "owasp":"A02:2025 Security Misconfiguration", "category":"Container configuration", "source":"built-in"})
    if dockerfiles and not dockerignore_present:
        findings.append({"id":"DOCKERIGNORE_MISSING", "severity":"low", "title":"Не найден .dockerignore в загруженном наборе", "file":dockerfiles[0][0], "line":1, "snippet":"[не найден .dockerignore]", "description":"Без .dockerignore чувствительные и ненужные файлы могут попасть в контекст сборки; файл может просто отсутствовать в загружаемой выборке.", "fix":"Добавьте .dockerignore и исключите секреты, .git, зависимости и временные файлы.", "example":".env\n.env.*\n.git\nnode_modules\n__pycache__\n*.pem\n*.key", "confidence":"low", "owasp":"A02:2025 Security Misconfiguration", "category":"Container configuration", "source":"built-in"})
    return findings


def extract_dependency_versions(files: list[tuple[str, str]]) -> list[dict]:
    """Extract exact package versions from familiar lockfiles. Range-only manifests are ignored."""
    found = {}
    def add(ecosystem, name, version, filename):
        name, version = str(name or "").strip(), str(version or "").strip()
        if version.startswith(("=", "v")): version = version.lstrip("=v")
        if not name or not version or len(name) > 200 or len(version) > 100:
            return
        if not re.fullmatch(r"[0-9][A-Za-z0-9.+!_-]*", version):
            return
        found[(ecosystem, name, version)] = {"ecosystem":ecosystem,"name":name,"version":version,"file":filename}
    for filename, content in files:
        leaf = Path(filename).name.lower()
        try:
            if leaf in {"package-lock.json", "npm-shrinkwrap.json"}:
                obj = json.loads(content)
                packages = obj.get("packages", {})
                if isinstance(packages, dict):
                    for path, meta in packages.items():
                        if path.startswith("node_modules/") and isinstance(meta, dict):
                            add("npm", path.split("node_modules/")[-1], meta.get("version"), filename)
                else:
                    def walk(deps):
                        for name, meta in (deps or {}).items():
                            if isinstance(meta, dict):
                                add("npm", name, meta.get("version"), filename); walk(meta.get("dependencies"))
                    walk(obj.get("dependencies"))
            elif leaf in {"requirements.txt", "requirements-dev.txt"} or leaf.startswith("requirements-") and leaf.endswith(".txt"):
                for line in content.splitlines():
                    m = re.match(r"\s*([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.+!-]+)", line)
                    if m: add("PyPI", m.group(1), m.group(2), filename)
            elif leaf == "pipfile.lock":
                obj = json.loads(content)
                for group in ("default", "develop"):
                    for name, meta in (obj.get(group, {}) or {}).items():
                        if isinstance(meta, dict): add("PyPI", name, meta.get("version"), filename)
            elif leaf in {"poetry.lock", "uv.lock", "cargo.lock"}:
                try:
                    import tomllib
                    obj = tomllib.loads(content)
                    ecosystem = "crates.io" if leaf == "cargo.lock" else "PyPI"
                    for meta in obj.get("package", []): add(ecosystem, meta.get("name"), meta.get("version"), filename)
                except (ImportError, ValueError):
                    # No unsafe parser fallback; dependency lookup is simply omitted.
                    pass
            elif leaf == "go.mod":
                in_require = False
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("require ("): in_require = True; continue
                    if in_require and stripped == ")": in_require = False; continue
                    parts = stripped.split()
                    if stripped.startswith("require ") and len(parts) >= 3: add("Go", parts[1], parts[2], filename)
                    elif in_require and len(parts) >= 2 and not stripped.startswith("//"): add("Go", parts[0], parts[1], filename)
            elif leaf == "composer.lock":
                obj = json.loads(content)
                for group in ("packages", "packages-dev"):
                    for meta in obj.get(group, []): add("Packagist", meta.get("name"), meta.get("version"), filename)
            elif leaf == "bun.lock":
                # Bun's text lockfile is JSON; lockb is binary and is deliberately not parsed.
                obj = json.loads(content)
                for name, meta in (obj.get("packages", {}) or {}).items():
                    if isinstance(meta, list) and meta and isinstance(meta[0], str):
                        resolved = re.match(r"^(@[^/]+/[^@]+|[^@]+)@([0-9][A-Za-z0-9.+!_-]*)$", meta[0])
                        if resolved: add("npm", resolved.group(1), resolved.group(2), filename)
            elif leaf == "deno.lock":
                obj = json.loads(content)
                for coordinate in (obj.get("npm", {}) or {}):
                    resolved = re.match(r"^(@[^/]+/[^@]+|[^@]+)@([0-9][A-Za-z0-9.+!_-]*)$", str(coordinate))
                    if resolved: add("npm", resolved.group(1), resolved.group(2), filename)
            elif leaf == "pnpm-lock.yaml":
                in_packages = False
                for line in content.splitlines():
                    if re.match(r"^packages:\s*$", line): in_packages = True; continue
                    if in_packages and line and not line[0].isspace() and not line.startswith("#"): in_packages = False
                    if not in_packages: continue
                    candidate = line.strip().rstrip(":").strip("\"'")
                    # Supports pnpm v6-v9 package keys; peer suffixes are intentionally dropped.
                    m = re.match(r"^(@[^/]+/[^@]+|[^@]+)@([0-9][^()\s]*)", candidate)
                    if m: add("npm", m.group(1), m.group(2), filename)
            elif leaf == "yarn.lock":
                current = []
                for line in content.splitlines():
                    if line and not line[0].isspace() and line.rstrip().endswith(":"):
                        header = line.rstrip().rstrip(":").strip().strip("\"")
                        current = []
                        for spec in re.split(r",\s+(?=(?:@?[^,]+@))", header):
                            spec = spec.strip().strip("\"")
                            if spec.startswith("@"):
                                at = spec.find("@", spec.find("/") + 1)
                            else:
                                at = spec.find("@")
                            if at > 0:
                                name = spec[:at]
                                if name and not name.startswith("npm:"): current.append(name)
                    version_match = re.match(r"\s+version\s+[\"]([^\"]+)[\"]", line)
                    if version_match:
                        for name in current: add("npm", name, version_match.group(1), filename)
            elif leaf == "go.sum":
                for line in content.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and not parts[1].endswith("/go.mod"):
                        add("Go", parts[0], parts[1], filename)
            elif leaf == "pom.xml":
                for block in re.findall(r"(?is)<dependency\b[^>]*>(.*?)</dependency>", content):
                    group = re.search(r"(?is)<groupId>\s*([^<]+)\s*</groupId>", block)
                    artifact = re.search(r"(?is)<artifactId>\s*([^<]+)\s*</artifactId>", block)
                    version = re.search(r"(?is)<version>\s*([^<]+)\s*</version>", block)
                    if group and artifact and version and "${" not in version.group(1):
                        add("Maven", group.group(1).strip() + ":" + artifact.group(1).strip(), version.group(1).strip(), filename)
            elif leaf == "packages.lock.json":
                obj = json.loads(content)
                def walk_nuget(value):
                    if isinstance(value, dict):
                        if isinstance(value.get("resolved"), str) and ("type" in value or "requested" in value):
                            # Package name is supplied by the parent key.
                            pass
                        for key, child in value.items():
                            if isinstance(child, dict) and isinstance(child.get("resolved"), str):
                                add("NuGet", key, child.get("resolved"), filename)
                            walk_nuget(child)
                    elif isinstance(value, list):
                        for child in value: walk_nuget(child)
                walk_nuget(obj.get("dependencies", {}))
            elif leaf == "pubspec.lock":
                current = None
                for line in content.splitlines():
                    m = re.match(r"^  ([A-Za-z0-9_]+):\s*$", line)
                    if m: current = m.group(1); continue
                    v = re.match(r"^    version:\s*[\"]([^\"]+)[\"]", line)
                    if current and v: add("Pub", current, v.group(1), filename)
            elif leaf == "mix.lock":
                for m in re.finditer(r'"([A-Za-z0-9_]+)"\s*:\s*\{\s*:hex\s*,\s*:[A-Za-z0-9_]+\s*,\s*"([0-9][^" ]*)"', content):
                    add("Hex", m.group(1), m.group(2), filename)
            elif leaf == "gemfile.lock":
                for m in re.finditer(r"(?m)^\s{4}([A-Za-z0-9_.-]+) \(([^)]+)\)", content): add("RubyGems", m.group(1), m.group(2), filename)
        except (ValueError, TypeError, AttributeError):
            continue
    return list(found.values())[:200]


def check_dependencies_osv(files: list[tuple[str, str]], timeout: float = 12.0) -> dict:
    """Check exact dependency versions in OSV; only package coordinates leave the computer."""
    import socket
    import ssl
    import time
    from urllib.error import HTTPError, URLError
    from urllib.request import Request, urlopen

    packages = extract_dependency_versions(files)
    if not packages:
        return {"status":"no-pinned-dependencies", "message":"Не нашли список используемых библиотек и их точных версий, поэтому дополнительную онлайн-проверку выполнить не удалось.", "packagesChecked":0, "findings":[]}

    queries = [{"package":{"name":p["name"],"ecosystem":p["ecosystem"]},"version":p["version"]} for p in packages]
    request_data = json.dumps({"queries":queries}).encode("utf-8")

    def make_request():
        return Request(
            "https://api.osv.dev/v1/querybatch",
            data=request_data,
            headers={"Content-Type":"application/json", "User-Agent":"ShieldCode-Educational-Scanner/2.1"},
            method="POST",
        )

    def friendly_error(exc):
        reason = getattr(exc, "reason", exc)
        if isinstance(exc, HTTPError):
            code = exc.code
            if code == 429:
                return "Онлайн-база временно ограничила число запросов. Повтори проверку позже.", "rate-limited"
            if code >= 500:
                return "Сервер онлайн-базы временно недоступен. Повтори проверку позже.", "service-error"
            return f"Онлайн-база вернула ошибку HTTP {code}. Локальная проверка завершена.", "http-error"
        if isinstance(reason, ssl.SSLCertVerificationError):
            return (
                "Python не смог проверить HTTPS-сертификат онлайн-базы. Обнови сертификаты командой в Терминале: "
                "python3 -m pip install --user --upgrade certifi. "
                "Проверка кода завершена; проверка библиотек онлайн пропущена.",
                "certificate-verification",
            )
        if isinstance(reason, ssl.SSLError):
            return "Не удалось установить защищённое HTTPS-соединение с онлайн-базой. Проверь сертификаты Python и настройки сети.", "tls-error"
        if isinstance(reason, socket.gaierror):
            return "Не удалось найти адрес онлайн-базы. Проверь подключение к интернету, DNS или настройки VPN.", "dns-error"
        if isinstance(reason, (TimeoutError, socket.timeout)):
            return "Онлайн-база не ответила вовремя. Проверь подключение к интернету и повтори проверку.", "timeout"
        if isinstance(reason, (ConnectionRefusedError, ConnectionResetError)):
            return "Соединение с онлайн-базой было отклонено или прервано. Проверь VPN, прокси и сетевой экран.", "connection-error"
        detail = str(reason).strip()
        if detail:
            detail = detail[:180]
            return f"Не удалось обратиться к онлайн-базе ({type(reason).__name__}: {detail}). Локальная проверка завершена.", "network-error"
        return "Не удалось обратиться к онлайн-базе. Локальная проверка завершена.", "network-error"

    body = None
    last_error = None
    for attempt in range(2):
        try:
            with urlopen(make_request(), timeout=timeout, context=ssl.create_default_context()) as response:
                payload = response.read(2_000_000)
            body = json.loads(payload.decode("utf-8"))
            break
        except HTTPError as exc:
            last_error = exc
            if attempt == 0 and (exc.code == 429 or exc.code >= 500):
                time.sleep(0.6)
                continue
            break
        except URLError as exc:
            last_error = exc
            reason = getattr(exc, "reason", exc)
            # A certificate bundle can be missing from some Python installations on macOS.
            # Try certifi if present, while keeping certificate verification enabled.
            if isinstance(reason, ssl.SSLCertVerificationError):
                try:
                    import certifi
                    with urlopen(make_request(), timeout=timeout, context=ssl.create_default_context(cafile=certifi.where())) as response:
                        payload = response.read(2_000_000)
                    body = json.loads(payload.decode("utf-8"))
                    break
                except ImportError:
                    pass
                except (HTTPError, URLError, TimeoutError, OSError, ValueError) as fallback_exc:
                    last_error = fallback_exc
            if attempt == 0 and not isinstance(reason, ssl.SSLError):
                time.sleep(0.6)
                continue
            break
        except (TimeoutError, OSError, ValueError) as exc:
            last_error = exc
            if attempt == 0 and not isinstance(exc, ValueError):
                time.sleep(0.6)
                continue
            break

    if body is None:
        message, error_code = friendly_error(last_error or OSError("Unknown network error"))
        return {"status":"unavailable", "message":message, "packagesChecked":0, "errorType":type(last_error).__name__ if last_error else "NetworkError", "errorCode":error_code, "findings":[]}
    findings = []
    for package, result in zip(packages, body.get("results", [])):
        for vuln in result.get("vulns", []) if isinstance(result, dict) else []:
            severity = "medium"
            cvss = None
            for item in vuln.get("severity", []) or []:
                if str(item.get("type", "")).upper().startswith("CVSS"):
                    try: cvss = float(str(item.get("score", "")).split("/")[0])
                    except ValueError: pass
            if cvss is not None: severity = "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low"
            else:
                level = str((vuln.get("database_specific", {}) or {}).get("severity", "")).upper()
                severity = {"CRITICAL":"critical", "HIGH":"high", "MODERATE":"medium", "MEDIUM":"medium", "LOW":"low"}.get(level, "medium")
            fixed = set()
            for affected in vuln.get("affected", []) or []:
                for rng in affected.get("ranges", []) or []:
                    for event in rng.get("events", []) or []:
                        if event.get("fixed"): fixed.add(str(event["fixed"]))
            vuln_id = vuln.get("id", "OSV advisory")
            findings.append({"id":"OSV_DEPENDENCY", "severity":severity, "title":f"Известная уязвимость зависимости: {package['name']}@{package['version']} ({vuln_id})", "file":package["file"], "line":1, "snippet":f"{package['name']}@{package['version']}", "description":str(vuln.get("summary") or vuln.get("details") or "В OSV есть advisory для этой версии.")[:900], "fix":("Проверьте возможность обновления до версии: " + ", ".join(sorted(fixed)[:5])) if fixed else "Проверьте advisory и совместимые исправления; база не указала точную исправленную версию.", "example":"Проверьте совместимые обновления, протестируйте приложение и повторите сканирование.", "confidence":"high", "owasp":"A03:2025 Software Supply Chain Failures", "category":"Dependency vulnerability (OSV)", "source":"OSV", "advisoryId":vuln_id, "aliases":(vuln.get("aliases", []) or [])[:10], "references":[r.get("url") for r in (vuln.get("references", []) or [])[:5] if r.get("url")]})
    return {"status":"completed", "message":f"По онлайн-базе проверено библиотек: {len(queries)}. Найдено известных уязвимостей: {len(findings)}.", "packagesChecked":len(queries), "vulnerabilitiesFound":len(findings), "findings":findings[:400]}


# ---------------------------------------------------------------------------
# Automatic fixes
#
# Rules of the fixer:
#   * only edit real code: never text inside string literals, comments, docs, tests or rule definitions;
#   * only apply replacements that keep the program valid and make it safer (secure default);
#   * a Python file whose edited version no longer compiles is returned unchanged;
#   * everything that needs a human decision (SQL, CORS origins, eval, ...) stays in the report.
# ---------------------------------------------------------------------------
HTML_LIKE = {".html", ".htm", ".xhtml", ".vue", ".svelte", ".astro"}
PY_SUFFIXES = {".py", ".pyw"}
JS_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"}
CONFIG_SUFFIXES = {".yml", ".yaml", ".env", ".sh", ".bash", ".zsh", ".conf", ".ini", ".properties", ".bat", ".cmd", ".ps1", ".dockerfile"}
CONFIG_LEAVES = {"dockerfile", "containerfile", ".env", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
SECRET_NAME_RE = re.compile(r"(?i)(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|secret[_-]?key)")
SECRET_PLACEHOLDERS = ("example", "dummy", "placeholder", "changeme", "change_me", "your_", "xxxx", "replace", "test", "redacted", "null", "none", "secret_here")
COOKIE_CONTEXT_RE = re.compile(r"cookie|session|auth|token|set[_-]?cookie", re.I)


def _split_lines(content: str) -> list[str]:
    return io.StringIO(content).readlines()


def _python_code_mask(lines: list[str], content: str) -> list[list[bool]] | None:
    """Per-character mask: True = real code, False = string literal or comment. None if the file does not tokenize."""
    masks = [[True] * (len(line) + 1) for line in lines]
    non_code = {tokenize.STRING, tokenize.COMMENT}
    for name in ("FSTRING_START", "FSTRING_MIDDLE", "FSTRING_END"):
        if hasattr(tokenize, name):
            non_code.add(getattr(tokenize, name))
    try:
        for token in tokenize.generate_tokens(io.StringIO(content).readline):
            if token.type not in non_code:
                continue
            (srow, scol), (erow, ecol) = token.start, token.end
            for row in range(srow, erow + 1):
                if row - 1 >= len(masks):
                    break
                start = scol if row == srow else 0
                end = ecol if row == erow else len(masks[row - 1])
                for col in range(start, min(end, len(masks[row - 1]))):
                    masks[row - 1][col] = False
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return None
    return masks


def _js_code_mask(lines: list[str]) -> list[list[bool]]:
    """Conservative JS/TS lexer: comments, quotes and template literals are treated as non-code."""
    masks = [[True] * (len(line) + 1) for line in lines]
    in_block = False
    quote = ""
    for row, line in enumerate(lines):
        col, size = 0, len(line)
        while col < size:
            char = line[col]
            if in_block:
                masks[row][col] = False
                if char == "*" and col + 1 < size and line[col + 1] == "/":
                    masks[row][col + 1] = False
                    in_block = False
                    col += 2
                    continue
                col += 1
                continue
            if quote:
                masks[row][col] = False
                if char == "\\":
                    if col + 1 < size:
                        masks[row][col + 1] = False
                    col += 2
                    continue
                if char == quote:
                    quote = ""
                col += 1
                continue
            if char == "/" and col + 1 < size and line[col + 1] == "/":
                for k in range(col, size):
                    masks[row][k] = False
                break
            if char == "/" and col + 1 < size and line[col + 1] == "*":
                masks[row][col] = masks[row][col + 1] = False
                in_block = True
                col += 2
                continue
            if char in "'\"`":
                masks[row][col] = False
                quote = char
            col += 1
        if quote in {"'", '"'}:
            quote = ""  # ordinary strings cannot span lines
    return masks


def _sub_in_code(pattern, repl, line: str, mask: list[bool], anchor: int = 0) -> tuple[str, int, list[bool]]:
    """Replace regex hits whose `anchor` group starts in real code. `repl` may return None to skip a hit.

    Returns the new line, the number of replacements and a mask that stays aligned with the new line.
    """
    out, new_mask, last, count = [], [], 0, 0
    for match in pattern.finditer(line):
        position = match.start(anchor) if anchor else match.start()
        if position < 0 or position >= len(mask) or not mask[position]:
            continue
        replacement = repl(match) if callable(repl) else match.expand(repl)
        if replacement is None:
            continue
        out.append(line[last:match.start()])
        new_mask.extend(mask[last:match.start()])
        out.append(replacement)
        new_mask.extend([True] * len(replacement))
        last = match.end()
        count += 1
    out.append(line[last:])
    new_mask.extend(mask[last:])
    if not count:
        return line, 0, mask
    return "".join(out), count, new_mask


def _ensure_import_os(content: str) -> str:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return content
    for node in tree.body:
        if isinstance(node, ast.Import) and any(alias.name == "os" and alias.asname is None for alias in node.names):
            return content
    insert_after = 0
    for index, node in enumerate(tree.body):
        is_doc = index == 0 and isinstance(node, ast.Expr) and isinstance(getattr(node, "value", None), ast.Constant) and isinstance(node.value.value, str)
        is_future = isinstance(node, ast.ImportFrom) and node.module == "__future__"
        if is_doc or is_future:
            insert_after = node.end_lineno or insert_after
        else:
            break
    lines = _split_lines(content)
    newline = "\r\n" if lines and lines[0].endswith("\r\n") else "\n"
    if insert_after and lines[insert_after - 1] and not lines[insert_after - 1].endswith("\n"):
        lines[insert_after - 1] += newline
    lines.insert(insert_after, "import os" + newline)
    return "".join(lines)


def _fix_anchor_tag(tag: str, local: list, lineno_of) -> str:
    if "=>" in tag or not re.search(r"\btarget\s*=\s*(['\"])_blank\1", tag, re.I):
        return tag
    rel_match = re.search(r"\brel\s*=\s*(['\"])(.*?)\1", tag, re.I)
    if not rel_match:
        local.append({"rule": "TARGET_BLANK", "line": lineno_of(), "description": "Добавлен rel=\"noopener noreferrer\" для target=\"_blank\"."})
        return tag[:-1] + ' rel="noopener noreferrer">'
    tokens = rel_match.group(2).lower().split()
    missing = [item for item in ("noopener", "noreferrer") if item not in tokens]
    if not missing:
        return tag
    quote = rel_match.group(1)
    value = quote + (rel_match.group(2) + " " + " ".join(missing)).strip() + quote
    local.append({"rule": "TARGET_BLANK", "line": lineno_of(), "description": "Дополнен rel у ссылки target=\"_blank\" (noopener noreferrer)."})
    return tag[:rel_match.start()] + "rel=" + value + tag[rel_match.end():]


def _fix_html(content: str, local: list) -> str:
    anchor = re.compile(r"<a\b[^>]*>", re.I)

    def replace(match):
        lineno = content.count("\n", 0, match.start()) + 1
        return _fix_anchor_tag(match.group(0), local, lambda: lineno)

    return anchor.sub(replace, content)


# (rule id, regex, replacement, anchor group, description, optional line predicate)
_PY_RULES = [
    ("YAML_UNSAFE_LOAD",
     re.compile(r"(?<![\w.])(yaml)\.load\(\s*([A-Za-z_]\w*)\s*(?:,\s*Loader\s*=\s*yaml\.(?:Loader|UnsafeLoader|FullLoader)\s*)?\)"),
     r"yaml.safe_load(\2)", 1,
     "yaml.load(переменная) заменён на yaml.safe_load(переменная); проверьте, что в YAML только обычные данные.", None),
    ("TLS_VERIFY_DISABLED",
     re.compile(r"(\brequests\.(?:get|post|put|patch|delete|head|request)\s*\([^\n]*?\bverify\s*=\s*)(False)\b"),
     r"\1True", 2,
     "Включена проверка TLS-сертификата в вызове requests; для внутреннего сервера настройте доверенный сертификат.", None),
    ("DEBUG_MODE",
     re.compile(r"(\.run\s*\([^\n]*?\bdebug\s*=\s*)(True)\b"),
     r"\1False", 2,
     "Режим отладки в app.run(...) выключен (debug=False). Для разработки включайте его только на своём компьютере.", None),
    ("CSRF_PROTECTION_DISABLED",
     re.compile(r"\b(WTF_CSRF_ENABLED\s*=\s*)(False)\b"),
     r"\1True", 2,
     "Включена CSRF-защита (WTF_CSRF_ENABLED = True).", None),
    ("COOKIE_HTTPONLY_DISABLED",
     re.compile(r"(?i)\b(httponly\s*[:=]\s*)(false|0)\b"),
     r"\1True", 2,
     "Для cookie включён флаг HttpOnly.", COOKIE_CONTEXT_RE.search),
    ("COOKIE_SECURE_DISABLED",
     re.compile(r"(?i)\b(secure\s*[:=]\s*)(false|0)\b"),
     r"\1True", 2,
     "Для cookie включён флаг Secure (cookie отправляется только по HTTPS).", COOKIE_CONTEXT_RE.search),
]

_JS_RULES = [
    ("TLS_VERIFY_DISABLED",
     re.compile(r"(\brejectUnauthorized\s*:\s*)(false)\b"),
     r"\1true", 2,
     "Включена проверка TLS-сертификата (rejectUnauthorized: true); для внутреннего сервера настройте доверенный сертификат.", None),
    ("TLS_VERIFY_DISABLED",
     re.compile(r"(\bNODE_TLS_REJECT_UNAUTHORIZED\s*['\"]?\s*=\s*['\"]?)(0)\b"),
     r"\g<1>1", 1,
     "NODE_TLS_REJECT_UNAUTHORIZED переключён на 1: проверка сертификатов снова включена.", None),
    ("COOKIE_HTTPONLY_DISABLED",
     re.compile(r"(?i)\b(httpOnly\s*:\s*)(false|0)\b"),
     r"\1true", 2,
     "Для cookie включён флаг httpOnly.", COOKIE_CONTEXT_RE.search),
    ("COOKIE_SECURE_DISABLED",
     re.compile(r"(?i)\b(secure\s*:\s*)(false|0)\b"),
     r"\1true", 2,
     "Для cookie включён флаг secure (cookie отправляется только по HTTPS).", COOKIE_CONTEXT_RE.search),
    ("CSRF_PROTECTION_DISABLED",
     re.compile(r"(?i)\b(csrf\s*:\s*)(false)\b"),
     r"\1true", 2,
     "Включена CSRF-защита (csrf: true).", None),
    ("INNER_HTML",
     re.compile(r"(\.)(innerHTML)(\s*=\s*)(?:''|\"\"|([\"'])[^\"'<>&\\\n$]*\4)(?=\s*(?:[;,)}]|$))"),
     lambda m: ".textContent" + m.group(0)[len(".innerHTML"):], 2,
     "innerHTML = «простой текст» заменён на textContent: текст выводится как текст, а не как HTML.", None),
]

_CONFIG_RULES = [
    ("TLS_VERIFY_DISABLED",
     re.compile(r"(NODE_TLS_REJECT_UNAUTHORIZED['\"]?\s*[:=]\s*['\"]?)(0)\b"),
     r"\g<1>1", 1,
     "NODE_TLS_REJECT_UNAUTHORIZED переключён на 1: проверка сертификатов снова включена.", None),
]

_SUBPROCESS_RE = re.compile(
    r"(subprocess\.(?:run|call|check_output|check_call|Popen)\(\s*)([\"'])([^\"'\\\n]*)\2((?:\s*,[^\n]*?)?\s*,?\s*)shell\s*=\s*True\b"
)
_TAR_RE = re.compile(r"(\.extractall\s*\()([^()\n]*)(\))")
_SECRET_ASSIGN_RE = re.compile(
    r"^(\s*)((?:self\.)?([A-Za-z_]\w*))(\s*(?::\s*[\w\[\], .|]+)?\s*=\s*)([\"'])([^\"'\\\n]{8,})\5(\s*(?:#.*)?)$"
)


def _apply_simple_rules(rules, lines, masks, local, comment_prefixes=()):
    for index, line in enumerate(lines):
        previous = lines[index - 1] if index else ""
        body = line.rstrip("\r\n")
        ending = line[len(body):]
        if line_is_ignored(body, previous) or RULE_META_LINE.match(body):
            continue
        if comment_prefixes and body.lstrip().startswith(comment_prefixes):
            continue
        mask = masks[index] if masks else [True] * (len(body) + 1)
        for rule_id, pattern, repl, anchor, description, predicate in rules:
            if predicate is not None and not predicate(body):
                continue
            body, count, mask = _sub_in_code(pattern, repl, body, mask, anchor)
            for _ in range(count):
                local.append({"rule": rule_id, "line": index + 1, "description": description})
        if masks:
            masks[index] = mask
        lines[index] = body + ending


def _fix_python(content: str, local: list) -> str:
    lines = _split_lines(content)
    masks = _python_code_mask(lines, content)
    if masks is None:
        return content
    _apply_simple_rules(_PY_RULES, lines, masks, local)
    uses_tar = bool(re.search(r"\btarfile\b", content)) and not re.search(r"\bzipfile\b", content)
    needs_os = False
    for index, line in enumerate(lines):
        previous = lines[index - 1] if index else ""
        body = line.rstrip("\r\n")
        ending = line[len(body):]
        if line_is_ignored(body, previous) or RULE_META_LINE.match(body) or body.lstrip().startswith("#"):
            continue
        mask = masks[index]
        # subprocess with shell=True and a fixed, metacharacter-free command -> argument list without a shell
        def fix_subprocess(match):
            command = match.group(3).strip()
            if not command or re.search(r"[$|&;<>*?`(){}~!#=\\]", command):
                return None
            try:
                parts = shlex.split(command)
            except ValueError:
                return None
            local.append({"rule": "PY_SUBPROCESS_SHELL_TRUE", "line": index + 1,
                          "description": "Команда запускается списком аргументов без оболочки (shell=False)."})
            return match.group(1) + repr(parts) + match.group(4) + "shell=False"
        new_body, _, mask = _sub_in_code(_SUBPROCESS_RE, fix_subprocess, body, mask, 1)
        if uses_tar:
            def fix_tar(match):
                args = match.group(2)
                if "filter" in args:
                    return None
                joined = args.rstrip() + (", " if args.strip() else "") + "filter='data'"
                local.append({"rule": "PY_TAR_EXTRACTALL", "line": index + 1,
                              "description": "В tar.extractall добавлен filter='data': защита от выхода за пределы папки назначения."})
                return match.group(1) + joined + match.group(3)
            new_body, _, mask = _sub_in_code(_TAR_RE, fix_tar, new_body, mask, 1)
        first_char = len(new_body) - len(new_body.lstrip())
        secret = _SECRET_ASSIGN_RE.match(new_body) if first_char < len(mask) and mask[first_char] else None
        if secret and SECRET_NAME_RE.fullmatch(secret.group(3)):
            value = secret.group(6).lower()
            if not any(token in value for token in SECRET_PLACEHOLDERS):
                env_name = re.sub(r"[^A-Z0-9_]", "_", secret.group(3).upper())
                new_body = f'{secret.group(1)}{secret.group(2)}{secret.group(4)}os.environ.get("{env_name}", ""){secret.group(7)}'
                needs_os = True
                local.append({"rule": "HARDCODED_SECRET", "line": index + 1,
                              "description": f"Секрет убран из кода и читается из переменной окружения {env_name}. "
                                             f"Задайте её значение на сервере перед запуском; старый секрет считайте скомпрометированным."})
        lines[index] = new_body + ending
    result = "".join(lines)
    if needs_os:
        result = _ensure_import_os(result)
    return result


def _fix_javascript(content: str, local: list) -> str:
    lines = _split_lines(content)
    masks = _js_code_mask(lines)
    _apply_simple_rules(_JS_RULES, lines, masks, local, comment_prefixes=("//", "*", "/*"))
    return "".join(lines)


def _fix_config(content: str, local: list, filename: str) -> str:
    lines = _split_lines(content)
    _apply_simple_rules(_CONFIG_RULES, lines, None, local, comment_prefixes=("#", "REM ", "rem ", "::", ";"))
    suffix = _norm_path(filename).suffix.lower()
    leaf = _norm_path(filename).name.lower()
    if suffix in {".yml", ".yaml"}:
        sock = re.compile(r"^(\s*)-\s*[\"']?/var/run/docker\.sock\b[^\n]*$")
        for index, line in enumerate(lines):
            body = line.rstrip("\r\n")
            ending = line[len(body):]
            if line_is_ignored(body, lines[index - 1] if index else ""):
                continue
            match = sock.match(body)
            if match:
                lines[index] = f"{match.group(1)}# [ShieldCode] удалено: монтирование docker.sock в контейнер{ending}"
                local.append({"rule": "DOCKER_SOCKET", "line": index + 1,
                              "description": "Убрано монтирование docker.sock в контейнер (даёт полный контроль над хостом)."})
                # An empty "volumes:" key is invalid for Compose: comment the header out when nothing is left under it.
                prev = index - 1
                while prev >= 0 and not lines[prev].strip():
                    prev -= 1
                if prev >= 0 and re.match(r"^\s*volumes\s*:\s*$", lines[prev].rstrip("\r\n")):
                    nxt = index + 1
                    while nxt < len(lines) and not lines[nxt].strip():
                        nxt += 1
                    header_indent = len(lines[prev]) - len(lines[prev].lstrip())
                    has_more = False
                    if nxt < len(lines) and not lines[nxt].lstrip().startswith("#"):
                        next_indent = len(lines[nxt]) - len(lines[nxt].lstrip())
                        has_more = lines[nxt].lstrip().startswith("-") and next_indent >= header_indent
                    if not has_more:
                        header = lines[prev].rstrip("\r\n")
                        lines[prev] = " " * header_indent + "# [ShieldCode] " + header.strip() + lines[prev][len(header):]
        priv = re.compile(r"^(\s*privileged\s*:\s*)true\b(.*)$")
        for index, line in enumerate(lines):
            body = line.rstrip("\r\n")
            ending = line[len(body):]
            match = priv.match(body)
            if match and not line_is_ignored(body, lines[index - 1] if index else ""):
                lines[index] = f"{match.group(1)}false{match.group(2)}{ending}"
                local.append({"rule": "K8S_PRIVILEGED", "line": index + 1,
                              "description": "privileged: true заменено на privileged: false (контейнер без расширенных прав ядра)."})
    return "".join(lines)


def apply_safe_fixes(files: list[tuple[str, str]]) -> tuple[list[tuple[str, str]], list[dict]]:
    """Apply every edit that is mechanical and safe; leave decisions that need a human in the report.

    Returns (all files, possibly edited) and the list of applied changes with file and line.
    """
    changed_files: list[tuple[str, str]] = []
    changes: list[dict] = []
    for filename, content in files:
        path = _norm_path(filename)
        suffix, leaf = path.suffix.lower(), path.name.lower()
        if is_prose_file(filename) or is_test_path(filename):
            changed_files.append((filename, content))
            continue
        local: list[dict] = []
        new_content = content
        if suffix in HTML_LIKE:
            new_content = _fix_html(content, local)
        elif suffix in PY_SUFFIXES:
            new_content = _fix_python(content, local)
            if new_content != content:
                try:
                    ast.parse(content)
                    original_valid = True
                except (SyntaxError, ValueError):
                    original_valid = False
                if original_valid:
                    try:
                        ast.parse(new_content)
                    except (SyntaxError, ValueError):
                        # Never hand back a file that no longer compiles.
                        new_content, local = content, []
        elif suffix in JS_SUFFIXES:
            new_content = _fix_javascript(content, local)
        if suffix in CONFIG_SUFFIXES or leaf in CONFIG_LEAVES:
            new_content = _fix_config(new_content, local, filename)
        changed_files.append((filename, new_content if new_content != content else content))
        for entry in local:
            entry["file"] = filename
            changes.append(entry)
    return changed_files, changes
