'use strict';

const state = {
  user: null,
  authMode: 'login',
  view: 'dashboard',
  selectedFiles: [],
  currentScan: null,
  patchFiles: null,
  history: [],
  toastTimer: null,
  language: 'ru',
};

const $ = (id) => document.getElementById(id);
let translations = { en: { ui: {}, findingTitles: {}, findingDefaults: {} } };
const staticTextNodes = [];
const staticAttributes = [];
function t(value) {
  if (value === null || value === undefined || typeof value !== 'string' || state.language !== 'en') return value;
  return translations.en.ui[value.trim()] || value;
}
function rememberStaticText() {
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  let node;
  while ((node = walker.nextNode())) {
    if (!node.nodeValue.trim() || node.parentElement?.closest('.code-rain,script,style,pre')) continue;
    staticTextNodes.push({ node, original: node.nodeValue });
  }
  document.querySelectorAll('title,meta[content], [placeholder], [aria-label], [title]').forEach((element) => {
    const attrs = ['content', 'placeholder', 'aria-label', 'title'];
    attrs.forEach((name) => {
      const original = element.getAttribute(name);
      if (original) staticAttributes.push({ element, name, original });
    });
  });
}
function applyLanguage(language) {
  state.language = language === 'en' ? 'en' : 'ru';
  document.documentElement.lang = state.language;
  staticTextNodes.forEach(({ node, original }) => {
    if (node.isConnected) {
      const leading = original.match(/^\s*/)?.[0] || '';
      const trailing = original.match(/\s*$/)?.[0] || '';
      node.nodeValue = `${leading}${t(original.trim())}${trailing}`;
    }
  });
  staticAttributes.forEach(({ element, name, original }) => {
    if (element.isConnected) element.setAttribute(name, t(original));
  });
  $('languageSelect').value = state.language;
  document.title = t('ShieldCode — проверка проекта');
  const description = $('pageDescription');
  if (description) description.content = state.language === 'en'
    ? 'ShieldCode — a clear check of website and app files before publishing.'
    : 'ShieldCode — проверка файлов сайта или приложения перед публикацией.';
  try { localStorage.setItem('shieldcode-language', state.language); } catch {}
}
async function changeLanguage(language) {
  applyLanguage(language);
  setAuthMode(state.authMode);
  setView(state.view);
  renderSelectedFiles();
  if (state.currentScan) renderCurrentScan(state.currentScan);
  if (state.user) renderHistory();
  if (state.user) {
    try {
      await postJSON('/api/language', { language: state.language });
      state.user.language = state.language;
    } catch {
      toast(state.language === 'en'
        ? 'The language changed on this device, but could not be saved to your account.'
        : 'Язык изменён на этом устройстве, но не сохранён в аккаунте.');
    }
  }
}
const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
const severityNames = { critical: 'Критические', high: 'Высокие', medium: 'Средние', low: 'Низкие', info: 'Подсказки' };
const severityNamesEn = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Tips' };
function severityName(severity) { return state.language === 'en' ? severityNamesEn[severity] || 'Other' : severityNames[severity] || 'Другое'; }
const friendlyFindingTitles = {
  EVAL: 'Текст может быть выполнен как программа (eval)',
  NEW_FUNCTION: 'Программа создаётся из текста',
  INNER_HTML: 'Данные могут добавить на страницу чужой код',
  DOCUMENT_WRITE: 'Страница может вставлять данные небезопасным способом',
  REACT_RAW_HTML: 'В React отключена защита от вставки чужого кода',
  WILDCARD_CORS: 'К сайту разрешён доступ с любых сайтов (CORS)',
  TOKEN_LOCAL_STORAGE: 'Токен входа хранится в браузере',
  TLS_VERIFY_DISABLED: 'Не проверяется подлинность защищённого соединения (TLS)',
  COMMAND_EXEC: 'Приложение может запускать команды на компьютере',
  PICKLE_LOADS: 'Файл может запустить код при чтении (pickle)',
  SQL_CONCAT: 'Данные могут попасть в запрос к базе (SQL-инъекция)',
  JWT_LITERAL: 'В коде может быть встроен токен входа (JWT)',
  JWT_VERIFY_DISABLED: 'Не проверяется подлинность токена входа (JWT)',
  UNSAFE_DESERIALIZATION: 'Загрузка данных может запустить посторонний код',
  OPEN_REDIRECT: 'Ссылка может перенаправить на чужой сайт',
  SSRF_SUSPECT: 'Сайт может обращаться по адресу, который ввёл пользователь (SSRF)',
  PATH_TRAVERSAL: 'Путь к файлу может зависеть от ввода пользователя',
  CSP_UNSAFE_INLINE: 'Настройки защиты разрешают небезопасный код (CSP)',
  SRI_MISSING: 'Внешний скрипт загружается без проверки целостности (SRI)',
  COOKIE_SAMESITE_NONE: 'Браузер может отправлять cookie другим сайтам',
  XML_EXTERNAL_ENTITY: 'XML-файл может дать доступ к внешним данным (XXE)',
  WEAK_CRYPTO_HASH: 'Слабый способ проверки целостности данных (MD5 или SHA-1)',
  WEAK_PASSWORD_HASH: 'Пароли защищены слабым способом',
  TARGET_BLANK: 'Ссылка открывается в новой вкладке без дополнительной защиты',
  ENV_FILE_INCLUDED: 'В проект попал файл .env — в нём могут быть пароли и ключи',
  GITHUB_TOKEN: 'Ключ доступа к GitHub может попасть в исходники',
  GITLAB_TOKEN: 'Ключ доступа к GitLab может попасть в исходники',
  SLACK_TOKEN: 'Ключ доступа к Slack может попасть в исходники',
  STRIPE_SECRET: 'Секретный ключ Stripe может попасть в исходники',
  GOOGLE_API_KEY: 'Ключ доступа к Google может попасть в исходники',
  HARDCODED_SECRET_UNQUOTED: 'В настройках может быть записан секретный ключ',
  YAML_UNSAFE_LOAD: 'Файл настроек YAML может запустить код при чтении',
  INSECURE_RANDOM: 'Для важного секрета используется предсказуемое случайное значение',
  IFRAME_NO_SANDBOX: 'Встроенная страница открыта без ограничений (iframe)',
  SHELL_PIPE_DOWNLOAD: 'Скачанный из интернета файл сразу запускается',
  PERMISSIVE_CHMOD: 'Файлам выданы слишком широкие права доступа',
  LOGS_SECRET: 'Секретный ключ может записываться в журналы работы',
  DOCKER_LATEST: 'Версия образа Docker не закреплена и может неожиданно измениться',
  DOCKER_ROOT: 'Контейнер Docker запускается с правами администратора (root)',
  DOCKER_SECRET_ENV: 'Секретный ключ может попасть в образ Docker',
  DOCKERIGNORE_SECRETS: 'Секретные файлы могут попасть в образ Docker',
  DOCKERIGNORE_MISSING: 'Не найден список файлов, которые не нужно добавлять в образ Docker',
  DOCKER_SOCKET: 'Контейнер Docker может получить полный доступ к компьютеру',
  K8S_PRIVILEGED: 'Контейнер Kubernetes запущен с расширенными правами',
  K8S_HOSTPATH: 'Контейнер Kubernetes получает доступ к файлам компьютера',
  K8S_HOST_NETWORK: 'Контейнер Kubernetes использует сеть компьютера напрямую',
  K8S_TOKEN_AUTOMOUNT: 'Контейнер автоматически получает ключ доступа к серверу',
  TF_OPEN_INGRESS: 'Настройки облака открывают доступ из любой сети',
  TF_ENCRYPTION_DISABLED: 'Данные в облачном хранилище могут быть без шифрования',
  GHA_WRITE_ALL: 'Автоматическая сборка получила слишком широкие права на GitHub',
  GHA_MUTABLE_REF: 'Версия действия GitHub может незаметно измениться',
  GHA_UNTRUSTED_INPUT: 'Данные из запроса могут повлиять на автоматическую сборку',
  GHA_PERSIST_CREDENTIALS: 'Ключ GitHub остаётся в папке после автоматической сборки',
  COOKIE_HTTPONLY_DISABLED: 'Код страницы может прочитать данные входа в браузере (cookie)',
  COOKIE_SECURE_DISABLED: 'Данные входа в браузере (cookie) могут передаваться без защиты',
  FRONTEND_SECRET_PREFIX: 'Секрет может попасть в код, отправляемый браузеру',
  PHP_ALLOW_URL_INCLUDE: 'PHP может подключить файл по интернет-ссылке',
  PHP_ASSERT_INPUT: 'Проверка PHP может выполнить данные пользователя как код',
  C_UNSAFE_STRING_FUNCTION: 'Функция работы со строкой может повредить память',
  JAVA_RUNTIME_EXEC: 'Приложение может запускать команды компьютера',
  COOKIE_FLAGS_MISSING: 'Данные входа в браузере (cookie) могут не иметь защитных настроек',
  CSP_UNSAFE_EVAL: 'Настройки защиты страницы разрешают запуск кода из текста (CSP)',
  CORS_REFLECT_ORIGIN: 'Сайт может разрешать доступ любому сайту, который к нему обратился (CORS)',
  PY_TEMPFILE_MKTEMP: 'Временный файл создаётся небезопасным способом',
  DOTNET_DANGEROUS_TYPE: 'Открытие данных .NET может запустить посторонний код',
  TEMPLATE_UNSAFE_MARKUP: 'Шаблон страницы может вставить пользовательский код без проверки',
  PY_RENDER_TEMPLATE_STRING: 'Страница собирается из строки, которая может содержать чужой код',
  PY_TAR_EXTRACTALL: 'Архив распаковывается без проверки путей файлов',
  NODE_TLS_VERIFY_DISABLED: 'Node.js не проверяет подлинность защищённого соединения (TLS)',
  GO_TLS_INSECURE_SKIP_VERIFY: 'Go не проверяет подлинность защищённого соединения (TLS)',
  JAVA_TRUST_ALL_CERTS: 'Java может доверять любому сертификату защищённого соединения (TLS)',
  CSRF_PROTECTION_DISABLED: 'Форма может принять поддельный запрос с другого сайта (CSRF)',
  DJANGO_WILDCARD_ALLOWED_HOSTS: 'Сайт Django принимает запросы с любым именем сайта',
  PHP_DYNAMIC_INCLUDE: 'PHP-файл может выбираться по вводу пользователя',
  POSTMESSAGE_WILDCARD_ORIGIN: 'Сообщение отправляется любой открытой странице',
  CORS_CREDENTIALS_WILDCARD: 'Доступ с любого сайта разрешён вместе с данными входа (CORS)',
  PY_SUBPROCESS_SHELL_TRUE: 'Команда компьютера может выполняться вместе с вводом пользователя',
  RUBY_UNSAFE_YAML_LOAD: 'Файл настроек YAML может запустить код при чтении',
  EJS_UNESCAPED_OUTPUT: 'Данные пользователя могут попасть на страницу без проверки',
  SPRING_ACTUATOR_EXPOSE_ALL: 'Внутренние сведения о приложении могут быть доступны всем',
};
const friendlyFindingDescriptions = {
  INNER_HTML: 'Если в страницу вставляются данные пользователя, злоумышленник может добавить на неё свой код.',
  DOCUMENT_WRITE: 'Если сюда попадают данные пользователя или внешнего сайта, на страницу может попасть чужой код.',
  REACT_RAW_HTML: 'Обычная защита React от вставки чужого кода отключена. Проверяй и очищай данные перед показом на странице.',
  WILDCARD_CORS: 'Сайт разрешает запросы с любого другого сайта. Обычно доступ лучше оставить только доверенным сайтам.',
  TOKEN_LOCAL_STORAGE: 'Данные для входа доступны коду страницы. При другой ошибке сайта их может быть проще украсть.',
  TLS_VERIFY_DISABLED: 'Без этой проверки приложение может подключиться к поддельному сайту, а данные — перехватить.',
  COMMAND_EXEC: 'Если команда включает данные пользователя, он может заставить приложение выполнить другие действия.',
  PICKLE_LOADS: 'Открытие такого файла от незнакомого источника может выполнить содержащийся в нём код.',
  SQL_CONCAT: 'Если в запрос к базе попадают данные пользователя, он может изменить запрос и получить чужие данные.',
  JWT_VERIFY_DISABLED: 'Приложение должно проверять подпись токена входа. Без этого оно может принять поддельный токен.',
  OPEN_REDIRECT: 'Ссылка может использоваться, чтобы незаметно отправить человека на поддельный сайт.',
  SSRF_SUSPECT: 'Если адрес задаёт пользователь, приложение может обратиться к внутренним ресурсам, которые не должны быть доступны снаружи.',
  SRI_MISSING: 'Без проверки целостности невозможно заметить, если внешний скрипт заменили на другой.',
  COOKIE_SAMESITE_NONE: 'Такая настройка позволяет браузеру отправлять данные входа вместе с запросами на другие сайты.',
  XML_EXTERNAL_ENTITY: 'Некоторые XML-файлы могут заставить приложение читать файлы компьютера или обращаться к внутренним адресам.',
  CSP_UNSAFE_INLINE: 'Эта настройка ослабляет защиту страницы от запуска постороннего кода.',
  CSRF_PROTECTION_DISABLED: 'Без защиты другой сайт может незаметно отправить запрос от имени вошедшего пользователя.',
  OSV_DEPENDENCY: 'В онлайн-базе известных проблем найдена запись для этой версии библиотеки. Проверь подробности и обнови библиотеку, если доступно исправление.',
};
function findingTitle(finding) {
  if (state.language === 'en') {
    const versionedName = String(finding.snippet || '').split(/\s/, 1)[0];
    const translated = translations.en.findingTitles?.[finding.id] || translations.en.findingTitles?.UNKNOWN || 'Potential issue found';
    return translated.replace('{name}', versionedName || 'dependency');
  }
  if (finding.id === 'OSV_DEPENDENCY') {
    const versionedName = String(finding.snippet || '').split(/\s/, 1)[0];
    return `Найдена проблема в библиотеке ${versionedName}`;
  }
  return friendlyFindingTitles[finding.id] || finding.title;
}
function findingDescription(finding) {
  if (state.language === 'en') return translations.en.findingDescriptions?.[finding.id] || translations.en.findingDefaults?.description || 'Review this code pattern. It may indicate a security or reliability issue.';
  return friendlyFindingDescriptions[finding.id] || finding.description;
}
function findingRecommendation(finding) {
  if (state.language === 'en') return translations.en.findingFixes?.[finding.id] || translations.en.findingDefaults?.fix || 'Review this code, follow the suggested safe pattern, and scan the project again after making changes.';
  return finding.fix;
}
function findingExample(finding) {
  if (state.language === 'en' && /[А-Яа-яЁё]/.test(finding.example || '')) return 'See the recommendation above for a safe approach.';
  return finding.example || '';
}
function findingSnippet(finding) {
  let snippet = `${finding.file}:${finding.line}\n${finding.snippet || ''}`;
  if (state.language === 'en') {
    snippet = snippet.replace(/\[СОДЕРЖИМОЕ СКРЫТО\]/gi, '[CONTENT HIDDEN]')
      .replace(/\[содержимое не отображается\]/gi, '[content hidden]')
      .replace(/\[не найден \.dockerignore\]/gi, '[.dockerignore not found]');
  }
  return snippet;
}
const acceptedExt = new Set([".adoc", ".asm", ".astro", ".bash", ".bat", ".c", ".c++", ".cc", ".cer", ".cfg", ".cjs", ".clj", ".cljs", ".cmd", ".conf", ".config", ".cpp", ".crt", ".cs", ".csproj", ".css", ".cxx", ".dart", ".der", ".dockerfile", ".ejs", ".env", ".erb", ".erl", ".ex", ".exs", ".fs", ".go", ".gql", ".gradle", ".gradle.kts", ".graphql", ".graphqls", ".groovy", ".h", ".handlebars", ".hbs", ".hcl", ".hh", ".hpp", ".hrl", ".htm", ".html", ".ini", ".ipynb", ".j2", ".java", ".jinja", ".jinja2", ".jks", ".js", ".json", ".json5", ".jsonc", ".jsx", ".key", ".keystore", ".kt", ".kts", ".less", ".lock", ".lockb", ".lua", ".map", ".md", ".mjs", ".mm", ".mobileprovision", ".mod", ".mustache", ".nix", ".nuspec", ".p12", ".pem", ".pfx", ".php", ".phtml", ".pl", ".plist", ".pm", ".policy", ".prisma", ".properties", ".props", ".proto", ".ps1", ".psm1", ".pub", ".pug", ".py", ".pyw", ".r", ".rb", ".rs", ".rules", ".sass", ".sc", ".scala", ".scss", ".service", ".service.yaml", ".sh", ".sln", ".socket", ".sol", ".sql", ".sqlx", ".sum", ".svelte", ".swift", ".targets", ".tf", ".tfplan", ".tfstate", ".tfstate.backup", ".tfvars", ".thrift", ".toml", ".ts", ".tsx", ".twig", ".txt", ".vb", ".vue", ".vy", ".xcconfig", ".xhtml", ".xml", ".xsd", ".xsl", ".yaml", ".yml", ".zsh"]);
const acceptedSpecial = new Set([".dockerignore", ".env", ".envrc", ".gitignore", ".gitlab-ci.yml", ".htaccess", ".netrc", ".npmrc", ".pypirc", "app.yaml", "authorized_keys", "build.gradle", "build.gradle.kts", "caddyfile", "cargo.lock", "cargo.toml", "compose.yaml", "compose.yml", "composer.json", "composer.lock", "containerfile", "credentials", "docker-compose.yaml", "docker-compose.yml", "dockerfile", "firebase.json", "firestore.rules", "gemfile", "gemfile.lock", "global.json", "go.mod", "go.sum", "gradle.lockfile", "gradle.properties", "id_ecdsa", "id_ed25519", "id_rsa", "known_hosts", "makefile", "mix.exs", "mix.lock", "netlify.toml", "nginx.conf", "npm-shrinkwrap.json", "nuget.config", "package-lock.json", "package.json", "packages.config", "packages.lock.json", "pipfile", "pipfile.lock", "pnpm-lock.yaml", "podfile", "podfile.lock", "poetry.lock", "pom.xml", "procfile", "pubspec.lock", "pubspec.yaml", "pyproject.toml", "rakefile", "requirements-dev.txt", "requirements.txt", "security.rules", "serverless.yml", "terraform.tfstate", "terraform.tfstate.backup", "uv.lock", "vercel.json", "yarn.lock"]);
['.mdx', '.rst', '.bicep', '.rego', '.cue', '.fish', '.f', '.for', '.f90', '.f95', '.pas', '.pp', '.hxx', '.ixx', '.cob', '.cbl', '.elm', '.m', '.swiftinterface'].forEach((extension) => acceptedExt.add(extension));
['bun.lock', 'deno.lock', 'bunfig.toml', 'deno.json', 'deno.jsonc', 'biome.json', 'biome.jsonc', 'renovate.json', '.prettierrc', '.prettierrc.json', '.prettierrc.yaml', '.eslintrc', '.eslintrc.json', 'dependabot.yml', 'dependabot.yaml', 'justfile', 'taskfile.yml', 'taskfile.yaml'].forEach((filename) => acceptedSpecial.add(filename));

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) {
    const userContent = tag === 'pre' || ['file-label', 'finding-location'].includes(className);
    node.textContent = String(userContent ? text : t(String(text)));
  }
  return node;
}
function bytes(value) {
  const units = state.language === 'en' ? ['B', 'KB', 'MB'] : ['Б', 'КБ', 'МБ'];
  if (value < 1024) return `${value} ${units[0]}`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} ${units[1]}`;
  return `${(value / (1024 * 1024)).toFixed(2)} ${units[2]}`;
}
function pluralRu(value, one, few, many) {
  if (state.language === 'en') return value === 1 ? 'issue' : 'issues';
  const number = Math.abs(value) % 100;
  const last = number % 10;
  if (number > 10 && number < 20) return many;
  if (last > 1 && last < 5) return few;
  if (last === 1) return one;
  return many;
}
function dateTime(seconds) {
  if (!seconds) return '—';
  try { return new Intl.DateTimeFormat(state.language === 'en' ? 'en-US' : 'ru-RU', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(seconds * 1000)); }
  catch { return new Date(seconds * 1000).toLocaleString(); }
}
function toast(message, duration = 3600) {
  const node = $('toast');
  node.textContent = t(message);
  node.classList.add('show');
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => node.classList.remove('show'), duration);
}
async function api(url, options = {}) {
  const response = await fetch(url, { credentials: 'same-origin', ...options });
  const type = response.headers.get('content-type') || '';
  const data = type.includes('application/json') ? await response.json() : null;
  if (!response.ok) {
    const error = data?.error || `Ошибка запроса (${response.status})`;
    throw new Error(state.language === 'en' ? (t(error) !== error ? t(error) : `The request failed (${response.status}). Check your files and try again.`) : error);
  }
  return data;
}
async function postJSON(url, payload) {
  return api(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
}

function setAuthMode(mode) {
  state.authMode = mode;
  document.querySelectorAll('.auth-tab').forEach((button) => button.classList.toggle('active', button.dataset.authMode === mode));
  const registering = mode === 'register';
  $('authTitle').textContent = t(registering ? 'Создать аккаунт' : 'Добро пожаловать');
  $('authSub').textContent = t(registering ? 'Создайте аккаунт, чтобы сохранять отчёты' : 'Войдите, чтобы начать проверку');
  const submit = $('authSubmit');
  submit.replaceChildren(document.createTextNode(`${t(registering ? 'Создать аккаунт' : 'Войти')} `), el('span', '', '→'));
  $('passwordHint').textContent = t(registering ? 'Пароль — минимум 10 символов. Не используйте пароль от других сервисов.' : 'Используйте длинный уникальный пароль.');
  $('password').autocomplete = registering ? 'new-password' : 'current-password';
  $('authError').classList.add('hidden');
}
function setUser(user) {
  state.user = user;
  $('authView').classList.toggle('hidden', !!user);
  $('appView').classList.toggle('hidden', !user);
  $('logoutBtn').classList.toggle('hidden', !user);
  $('userName').textContent = user ? user.username : t('Гость');
  $('userAvatar').textContent = user ? user.username.slice(0, 1).toUpperCase() : 'S';
  if (user) {
    setView('dashboard');
    refreshHistory().catch(() => {});
  }
}
async function init() {
  try {
    const response = await fetch('/i18n.json', { cache: 'no-store' });
    if (response.ok) translations = await response.json();
  } catch { /* Russian remains available if the translation file cannot load. */ }
  rememberStaticText();
  let savedLanguage = 'ru';
  try { savedLanguage = localStorage.getItem('shieldcode-language') || 'ru'; } catch {}
  applyLanguage(savedLanguage);
  $('languageSelect').addEventListener('change', (event) => changeLanguage(event.target.value));
  // Let Finder show special files without extensions too; client and server still enforce the allowlist.
  $('fileInput').accept = '*/*';
  document.querySelectorAll('[data-auth-mode]').forEach((button) => button.addEventListener('click', () => setAuthMode(button.dataset.authMode)));
  $('authForm').addEventListener('submit', onAuthSubmit);
  $('logoutBtn').addEventListener('click', logout);
  document.querySelectorAll('.nav-item').forEach((button) => button.addEventListener('click', () => setView(button.dataset.view)));
  $('openPrivacy').addEventListener('click', () => { $('authView').classList.add('hidden'); $('appView').classList.remove('hidden'); setView('privacy'); });
  $('privacyBack').addEventListener('click', () => setView('dashboard'));
  document.querySelectorAll('[data-go-view]').forEach((button) => button.addEventListener('click', () => setView(button.dataset.goView)));
  $('mobileMenu').addEventListener('click', () => $('sidebar').classList.toggle('open'));
  $('fileInput').addEventListener('change', (event) => addSelectedFiles(Array.from(event.target.files || [])));
  $('browseBtn').addEventListener('click', (event) => { event.stopPropagation(); $('fileInput').click(); });
  $('dropzone').addEventListener('click', (event) => { if (event.target.closest('button')) return; $('fileInput').click(); });
  $('dropzone').addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); $('fileInput').click(); } });
  ['dragenter', 'dragover'].forEach((name) => $('dropzone').addEventListener(name, (event) => { event.preventDefault(); $('dropzone').classList.add('dragover'); }));
  ['dragleave', 'drop'].forEach((name) => $('dropzone').addEventListener(name, (event) => { event.preventDefault(); $('dropzone').classList.remove('dragover'); }));
  $('dropzone').addEventListener('drop', (event) => addSelectedFiles(Array.from(event.dataTransfer?.files || [])));
  $('clearFiles').addEventListener('click', clearFiles);
  $('scanBtn').addEventListener('click', runScan);
  $('severityFilter').addEventListener('change', () => renderFindings(state.currentScan));
  $('downloadReport').addEventListener('click', () => downloadCurrent('report'));
  $('downloadFixes').addEventListener('click', () => downloadCurrent('fixes'));
  $('downloadPatchPack').addEventListener('click', downloadPatchPack);
  try {
    const result = await api('/api/me');
    if (result.authenticated) {
      applyLanguage(result.user.language || savedLanguage);
      setUser(result.user);
    }
  } catch {
    toast('Не удалось подключиться к серверу. Обнови страницу или перезапусти приложение.');
  }
}

async function onAuthSubmit(event) {
  event.preventDefault();
  const username = $('username').value.trim();
  const password = $('password').value;
  const registering = state.authMode === 'register';
  const errorBox = $('authError');
  const button = $('authSubmit');
  errorBox.textContent = '';
  errorBox.classList.add('hidden');

  // novalidate on the form ensures validation errors are shown in our UI,
  // instead of being silently blocked by browser-native minlength/pattern bubbles.
  if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) {
    errorBox.textContent = t('Логин: 3–32 символа, только латинские буквы, цифры, точка, дефис или подчёркивание.');
    errorBox.classList.remove('hidden');
    $('username').focus();
    return;
  }
  if (registering && (password.length < 10 || password.length > 128)) {
    errorBox.textContent = t('Пароль должен содержать от 10 до 128 символов.');
    errorBox.classList.remove('hidden');
    $('password').focus();
    return;
  }
  if (!registering && (!password || password.length > 128)) {
    errorBox.textContent = t('Введи пароль длиной не более 128 символов.');
    errorBox.classList.remove('hidden');
    $('password').focus();
    return;
  }

  button.disabled = true;
  button.replaceChildren(document.createTextNode(t(registering ? 'Создаём аккаунт…' : 'Входим…')));
  try {
    const data = await postJSON(registering ? '/api/register' : '/api/login', { username, password, language: state.language });
    $('password').value = '';
    applyLanguage(data.user.language || state.language);
    setAuthMode(state.authMode);
    setUser(data.user);
    // Account creation/login is already successful at this point. A history
    // refresh failure must not be misreported as a failed registration.
    toast(registering ? 'Аккаунт создан. Добро пожаловать!' : 'Вход выполнен.');
    refreshHistory().catch(() => toast('Вход выполнен, но историю пока не удалось загрузить. Обнови страницу.'));
  } catch (error) {
    let message = error.message || t('Не удалось выполнить запрос.');
    if (/занят/i.test(message) && registering) {
      message = t('Такой логин уже занят. Перейдите на вкладку «Вход» или укажите другой логин.');
    } else if (/failed to fetch|networkerror|load failed/i.test(message)) {
      message = t('Не удалось связаться с сервером. Убедитесь, что ShieldCode запущен, и обновите страницу.');
    }
    errorBox.textContent = message;
    errorBox.classList.remove('hidden');
  } finally {
    button.disabled = false;
    setAuthMode(state.authMode);
  }
}
async function logout() {
  try { await postJSON('/api/logout', {}); } catch { /* Local UI still returns to sign-in. */ }
  state.currentScan = null;
  state.patchFiles = null;
  state.history = [];
  state.selectedFiles = [];
  clearFiles();
  $('resultsSection').classList.add('hidden');
  setUser(null);
  toast('Вы вышли из аккаунта.');
}
function setView(view) {
  state.view = view;
  if (!state.user) {
    const publicPrivacy = view === 'privacy';
    $('authView').classList.toggle('hidden', publicPrivacy);
    $('appView').classList.toggle('hidden', !publicPrivacy);
  }
  const titles = { dashboard: 'Обзор', history: 'История проверок', guide: 'Как это работает', privacy: 'Конфиденциальность' };
  $('crumbTitle').textContent = t(titles[view] || 'Обзор');
  document.querySelectorAll('.nav-item').forEach((button) => button.classList.toggle('active', button.dataset.view === view));
  document.querySelectorAll('.view-panel').forEach((panel) => panel.classList.add('hidden'));
  const panel = $(`${view}View`);
  if (panel) panel.classList.remove('hidden');
  $('sidebar').classList.remove('open');
  const privacyBack = $('privacyBack');
  if (privacyBack) privacyBack.classList.toggle('hidden', !!state.user);
  if (view === 'history') refreshHistory().catch((e) => toast(e.message));
}
function validateClientFile(file) {
  const name = file.name.toLowerCase();
  const isEnv = name === '.env' || name.startsWith('.env.');
  const dot = name.lastIndexOf('.');
  const extension = dot >= 0 ? name.slice(dot) : '';
  const recognizedPrefix = ['dockerfile.', 'containerfile.', 'makefile.', 'id_rsa', 'id_ed25519', 'id_ecdsa'].some((prefix) => name.startsWith(prefix));
  if (!isEnv && !recognizedPrefix && !acceptedSpecial.has(name) && !acceptedExt.has(extension) && !name.endsWith('.zip')) return state.language === 'en' ? `Unsupported file type: ${file.name}` : `Неподдерживаемый тип файла: ${file.name}`;
  if (name.endsWith('.zip') && file.size > 10 * 1024 * 1024) return state.language === 'en' ? `ZIP archive is larger than 10 MB: ${file.name}` : `ZIP-архив больше 10 МБ: ${file.name}`;
  if (!name.endsWith('.zip') && file.size > 2 * 1024 * 1024) return state.language === 'en' ? `File is larger than 2 MB: ${file.name}` : `Файл больше 2 МБ: ${file.name}`;
  return null;
}
function addSelectedFiles(files) {
  if (!files.length) return;
  const previousFiles = [...state.selectedFiles];
  const existing = new Set(state.selectedFiles.map((f) => `${f.name}:${f.size}:${f.lastModified}`));
  let added = 0;
  for (const file of files) {
    const error = validateClientFile(file);
    if (error) { toast(error); continue; }
    const key = `${file.name}:${file.size}:${file.lastModified}`;
    if (!existing.has(key)) { state.selectedFiles.push(file); existing.add(key); added++; }
  }
  if (state.selectedFiles.length > 120) {
    state.selectedFiles = previousFiles;
    renderSelectedFiles();
    toast('Можно выбрать не более 120 отдельных файлов; для больших проектов используй ZIP.');
  } else if (state.selectedFiles.reduce((sum, f) => sum + f.size, 0) > 12 * 1024 * 1024) {
    state.selectedFiles = previousFiles;
    renderSelectedFiles();
    toast('Общий размер выбранных файлов должен быть не больше 12 МБ.');
  } else if (added) {
    state.patchFiles = null;
    $('downloadPatchPack').disabled = true;
    renderSelectedFiles();
    toast(state.language === 'en' ? `Files added: ${added}` : `Добавлено файлов: ${added}`);
  }
  $('fileInput').value = '';
}
function renderSelectedFiles() {
  const root = $('fileList');
  root.replaceChildren();
  state.selectedFiles.forEach((file, index) => {
    const row = el('div', 'file-pill');
    const extension = file.name.split('.').pop().toUpperCase().slice(0, 4) || 'FILE';
    row.append(el('span', 'file-type-icon', extension));
    row.append(el('span', 'file-label', file.name));
    row.append(el('span', 'file-size', bytes(file.size)));
    const remove = el('button', '', '×'); remove.type = 'button'; remove.title = t('Убрать файл'); remove.setAttribute('aria-label', state.language === 'en' ? `Remove ${file.name}` : `Убрать ${file.name}`);
    remove.addEventListener('click', () => { state.selectedFiles.splice(index, 1); state.patchFiles = null; $('downloadPatchPack').disabled = true; renderSelectedFiles(); });
    row.append(remove); root.append(row);
  });
  $('selectedFiles').classList.toggle('hidden', state.selectedFiles.length === 0);
  $('scanBtn').disabled = state.selectedFiles.length === 0;
}
function clearFiles() { state.selectedFiles = []; state.patchFiles = null; $('downloadPatchPack').disabled = true; $('fileInput').value = ''; renderSelectedFiles(); }

async function runScan() {
  if (!state.selectedFiles.length || $('scanBtn').disabled) return;
  const scanBtn = $('scanBtn');
  scanBtn.disabled = true;
  $('scanProgress').classList.remove('hidden');
  $('resultsSection').classList.add('hidden');
  const scannedFiles = [...state.selectedFiles];
  const form = new FormData();
  scannedFiles.forEach((file) => form.append('files', file, file.name));
  try {
    const data = await api('/api/scan', { method: 'POST', body: form });
    state.currentScan = data;
    state.patchFiles = scannedFiles;
    renderCurrentScan(data);
    $('resultsSection').classList.remove('hidden');
    $('scanProgress').classList.add('hidden');
    $('downloadFixes').parentElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
    let historyAvailable = true;
    try { await refreshHistory(); } catch { historyAvailable = false; }
    toast(state.language === 'en'
      ? historyAvailable ? `Scan complete. Findings: ${data.findingsCount}.` : `Scan complete. Findings: ${data.findingsCount}; history could not be refreshed.`
      : historyAvailable ? `Проверка завершена. Найдено проблем: ${data.findingsCount}.` : `Проверка завершена. Найдено проблем: ${data.findingsCount}; историю пока не удалось обновить.`);
  } catch (error) {
    toast(error.message);
  } finally {
    $('scanProgress').classList.add('hidden');
    scanBtn.disabled = state.selectedFiles.length === 0;
  }
}
function renderCurrentScan(scan) {
  state.currentScan = scan;
  const high = (scan.summary.critical || 0) + (scan.summary.high || 0);
  $('metricScore').textContent = scan.score;
  $('metricScoreCaption').textContent = t(scan.score >= 85 ? 'Найдено мало проблем' : scan.score >= 60 ? 'Проверьте список найденного' : 'Есть проблемы, требующие внимания');
  $('scoreTrack').style.width = `${scan.score}%`;
  $('metricFindings').textContent = scan.findingsCount;
  $('metricHigh').textContent = state.language === 'en' ? `${high} critical and high` : `${high} критических и высоких`;
  $('metricFiles').textContent = scan.totalFiles;
  $('metricSkipped').textContent = state.language === 'en' ? `${scan.skippedFiles || 0} skipped` : `${scan.skippedFiles || 0} пропущено`;
  $('metricScans').textContent = state.history.length || Number($('metricScans').textContent) + 1;
  $('resultTitle').textContent = scan.label ? (state.language === 'en' ? `Report: ${scan.label}` : `Отчёт: ${scan.label}`) : t('Отчёт проверки');
  $('resultMeta').textContent = state.language === 'en'
    ? `${scan.totalFiles} files checked · ${dateTime(scan.createdAt)} · score ${scan.score}/100`
    : `${scan.totalFiles} файлов проверено · ${dateTime(scan.createdAt)} · оценка ${scan.score}/100`;
  $('severityFilter').value = 'all';
  $('resultSummary').replaceChildren();
  severityOrder.forEach((severity) => {
    const box = el('div', 'severity-box');
    const label = el('div', 'severity-label');
    label.append(el('i', `sev-dot sev-${severity}`), document.createTextNode(severityName(severity)));
    box.append(label, el('strong', '', scan.summary?.[severity] || 0));
    $('resultSummary').append(box);
  });
  const dependencyStatus = $('dependencyStatus');
  const checks = scan.checks || {};
  dependencyStatus.className = 'dependency-status';
  dependencyStatus.textContent = state.language === 'en'
    ? checks.status === 'completed' ? 'Dependency check completed using the online database. Only package names and versions were sent; source code was not uploaded.'
      : checks.status === 'unavailable' ? 'The online dependency database could not be reached. The local scan still completed.'
        : 'The optional dependency check did not finish, but the local scan completed.'
    : checks.message || 'Дополнительная проверка библиотек не завершилась; локальный анализ всё равно выполнен.';
  dependencyStatus.classList.toggle('hidden', !checks.status || checks.status === 'not-requested');
  if (checks.status === 'unavailable') dependencyStatus.classList.add('warning');
  else dependencyStatus.classList.remove('warning');
  $('downloadPatchPack').disabled = !state.patchFiles || !state.patchFiles.length;
  renderActionPlan(scan);
  renderFindings(scan);
}
function renderActionPlan(scan) {
  const root = $('actionPlanSteps');
  root.replaceChildren();
  const summary = scan.summary || {};
  const groups = [
    {
      filter: 'urgent',
      count: (summary.critical || 0) + (summary.high || 0),
      title: 'Сначала — самые серьёзные',
      description: 'Проверьте найденный фрагмент и рекомендацию. Если в проект попал настоящий пароль или ключ, отзовите его и создайте новый.',
    },
    {
      filter: 'medium',
      count: summary.medium || 0,
      title: 'Затем — важные',
      description: 'После срочных проблем проверьте обработку данных, настройки и поведение приложения.',
    },
    {
      filter: 'low-info',
      count: (summary.low || 0) + (summary.info || 0),
      title: 'После этого — низкие и дополнительные',
      description: 'Ознакомьтесь с рекомендациями. Некоторые совпадения могут быть ожидаемыми для проекта.',
    },
  ];
  const total = (scan.findings || []).length;
  if (!total) {
    const empty = el('article', 'action-plan-empty');
    empty.append(el('strong', '', 'Проблем не найдено'), el('p', '', 'Это не подтверждает полную безопасность: проверка ищет знакомые ошибки и может что-то пропустить.'));
    root.append(empty);
  } else {
    groups.filter((group) => group.count > 0).forEach((group, index) => {
      const card = el('article', 'action-step');
      const number = el('span', 'action-step-number', String(index + 1).padStart(2, '0'));
      const content = el('div', 'action-step-content');
      content.append(el('h4', '', group.title), el('p', '', group.description));
      const footer = el('div', 'action-step-footer');
      footer.append(el('span', 'action-step-count', `${group.count} ${pluralRu(group.count, 'проблема', 'проблемы', 'проблем')}`));
      const button = el('button', 'text-link action-step-link', 'Показать проблемы →');
      button.type = 'button';
      button.addEventListener('click', () => {
        $('severityFilter').value = group.filter;
        renderFindings(scan);
        $('findingsList').scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
      footer.append(button);
      content.append(footer);
      card.append(number, content);
      root.append(card);
    });
  }
  if (scan.skippedFiles) {
    const noteText = state.language === 'en'
      ? `${scan.skippedFiles} file${scan.skippedFiles === 1 ? '' : 's'} skipped. Check file type and size.`
      : `${scan.skippedFiles} ${pluralRu(scan.skippedFiles, 'файл пропущен', 'файла пропущены', 'файлов пропущено')}. Проверьте формат и размер файлов.`;
    const note = el('p', 'action-plan-note', noteText);
    root.append(note);
  }
}
function renderFindings(scan) {
  const root = $('findingsList');
  root.replaceChildren();
  if (!scan) return;
  const filter = $('severityFilter').value;
  const severityGroups = { urgent: ['critical', 'high'], 'low-info': ['low', 'info'] };
  const findings = (scan.findings || []).filter((finding) => filter === 'all' || (severityGroups[filter] || [filter]).includes(finding.severity));
  $('findingsCountLabel').textContent = state.language === 'en'
    ? `Showing ${findings.length} of ${(scan.findings || []).length} findings`
    : `Показано: ${findings.length} из ${(scan.findings || []).length}`;
  if (!findings.length) {
    const empty = el('div', 'empty-state show');
    empty.append(el('div', '', '✓'), el('h3', '', (scan.findings || []).length ? 'Нет проблем этого уровня' : 'Проблем не найдено'), el('p', '', (scan.findings || []).length ? 'Выберите другой уровень важности.' : 'Это не гарантирует безопасность: проверка ищет только знакомые ошибки.'));
    root.append(empty); return;
  }
  findings.forEach((finding, index) => {
    const details = el('details', 'finding');
    if (index === 0 && ['critical', 'high'].includes(finding.severity)) details.open = true;
    const summary = el('summary');
    summary.append(el('span', `sev-pill ${finding.severity}`, severityName(finding.severity).toUpperCase()));
    summary.append(el('span', 'finding-title', findingTitle(finding)));
    summary.append(el('span', 'finding-location', `${finding.file}:${finding.line}`));
    details.append(summary);
    const body = el('div', 'finding-body');
    body.append(el('p', '', findingDescription(finding)));
    body.append(el('h4', '', 'Рекомендация'));
    body.append(el('p', '', findingRecommendation(finding)));
    body.append(el('h4', '', 'Пример исправления'));
    body.append(el('pre', 'code-block', findingExample(finding)));
    body.append(el('h4', '', 'Найденный фрагмент'));
    body.append(el('pre', 'code-block danger', findingSnippet(finding)));
    const foot = el('div', 'finding-foot');
    foot.append(el('span', '', state.language === 'en'
      ? `Confidence: ${finding.confidence === 'low' ? 'low' : finding.confidence === 'high' ? 'high' : 'medium'}`
      : `Насколько это похоже на проблему: ${finding.confidence === 'low' ? 'не очень' : finding.confidence === 'high' ? 'очень' : 'возможно'}`));
    body.append(foot);
    details.append(body);
    root.append(details);
  });
}
async function downloadPatchPack() {
  if (!state.patchFiles || !state.patchFiles.length) { toast('Чтобы скачать исправленную копию, загрузи файлы и запусти проверку.'); return; }
  const button = $('downloadPatchPack');
  button.disabled = true;
  const previous = button.textContent;
  button.textContent = t('Готовим файл…');
  try {
    const form = new FormData();
    state.patchFiles.forEach((file) => form.append('files', file, file.name));
    const response = await fetch('/api/fixpack', { method: 'POST', body: form, credentials: 'same-origin' });
    if (!response.ok) {
      const data = await response.json().catch(() => null);
      const message = data?.error || `Не удалось подготовить архив (${response.status})`;
      throw new Error(state.language === 'en' ? (t(message) !== message ? t(message) : `Could not prepare the project copy (${response.status}).`) : message);
    }
    const blob = await response.blob();
    const filename = filenameFromDisposition(response.headers.get('Content-Disposition'), 'проект_исправленный.zip');
    saveBlob(blob, filename);
    const base = filename.toLowerCase().endsWith('.zip')
      ? t('Архив проекта скачан. Дважды щёлкни по нему, чтобы открыть папку. Исходный проект не заменён.')
      : t('Исправленный файл скачан в исходном формате. Исходный файл не заменён.');
    // The server re-scans the corrected copy; show the real result instead of implying that everything was fixed.
    const before = response.headers.get('X-ShieldCode-Before');
    const after = response.headers.get('X-ShieldCode-After');
    const fixed = response.headers.get('X-ShieldCode-Fixed');
    let summary = '';
    if (before !== null && after !== null && fixed !== null) {
      summary = state.language === 'en'
        ? ` Fixed automatically: ${fixed} of ${before}. Still needs a manual decision: ${after}.`
        : ` Исправлено автоматически: ${fixed} из ${before}. Требуют вашего решения: ${after}.`;
    }
    toast(base + summary, summary ? 11000 : 3600);
  } catch (error) {
    toast(error.message || 'Не удалось скачать архив исправлений.');
  } finally {
    button.disabled = !state.patchFiles || !state.patchFiles.length;
    button.textContent = previous;
  }
}
async function downloadCurrent(kind) {
  if (!state.currentScan) { toast('Сначала запусти проверку.'); return; }
  const button = kind === 'fixes' ? $('downloadFixes') : $('downloadReport');
  const previous = button.textContent;
  button.disabled = true;
  button.textContent = t('Готовим PDF…');
  try {
    const response = await fetch(`/api/scans/${encodeURIComponent(state.currentScan.id)}/${kind}?lang=${state.language}`, { credentials: 'same-origin' });
    if (!response.ok) {
      const data = await response.json().catch(() => null);
      const message = data?.error || 'Не удалось подготовить PDF. Попробуй ещё раз.';
      throw new Error(state.language === 'en' ? (t(message) !== message ? t(message) : 'Could not prepare the PDF. Please try again.') : message);
    }
    const filename = filenameFromDisposition(response.headers.get('Content-Disposition'), state.language === 'en' ? (kind === 'fixes' ? 'Fix_Plan.pdf' : 'Full_Report.pdf') : (kind === 'fixes' ? 'план_исправлений.pdf' : 'полный_отчёт.pdf'));
    saveBlob(await response.blob(), filename);
    toast(t('PDF скачан. На Mac открой его двойным щелчком — он откроется в приложении «Просмотр».'));
  } catch (error) {
    toast(error.message || 'Не удалось скачать PDF.');
  } finally {
    button.disabled = false;
    button.textContent = previous;
  }
}
function filenameFromDisposition(header, fallback) {
  const encoded = /filename\*=UTF-8''([^;]+)/i.exec(header || '');
  if (encoded) { try { return decodeURIComponent(encoded[1]); } catch {} }
  const plain = /filename="?([^";]+)"?/i.exec(header || '');
  return plain?.[1] || fallback;
}
function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}
async function refreshHistory() {
  if (!state.user) return;
  const data = await api('/api/scans');
  state.history = data.scans || [];
  $('metricScans').textContent = state.history.length;
  renderHistory();
}
function renderHistory() {
  const root = $('historyList'); root.replaceChildren();
  $('historyEmpty').classList.toggle('show', state.history.length === 0);
  state.history.forEach((scan) => {
    const row = el('div', 'history-row');
    const name = el('div', 'history-name');
    name.append(el('span', 'history-file-icon', '⌕'));
    const nameText = el('div');
    const scanName = document.createElement('strong');
    scanName.textContent = scan.label || t('Исходный код');
    nameText.append(scanName, el('small', '', state.language === 'en'
      ? `${dateTime(scan.createdAt)} · ${scan.totalFiles} files · ${scan.findingsCount} ${scan.findingsCount === 1 ? 'finding' : 'findings'}`
      : `${dateTime(scan.createdAt)} · ${scan.totalFiles} файлов · ${scan.findingsCount} ${pluralRu(scan.findingsCount, 'проблема', 'проблемы', 'проблем')}`));
    name.append(nameText);
    const score = el('div', 'history-score'); score.append(el('strong', '', scan.score), el('small', '', t('из 100')));
    const open = el('button', 'history-open', 'Открыть отчёт →'); open.type = 'button';
    open.addEventListener('click', () => loadScan(scan.id));
    row.append(name, score, open); root.append(row);
  });
}
async function loadScan(id) {
  try {
    const scan = await api(`/api/scans/${encodeURIComponent(id)}`);
    state.patchFiles = null;
    renderCurrentScan(scan);
    $('resultsSection').classList.remove('hidden');
    setView('dashboard');
    $('resultsSection').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (error) { toast(error.message); }
}

window.addEventListener('DOMContentLoaded', init);
