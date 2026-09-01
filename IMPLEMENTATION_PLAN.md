# Implementation Plan: Security Audit Plugin (NPM, Docker Sandbox, MCP Bridge & Skills Architecture)

## 1. Executive Summary & Goals

Проект **`security-audit-plugin`** представляет собой кросс-платформенный NPM-пакет и плагин для ИИ-агентов (Google Antigravity / AGY, OpenCode, OpenAI/Codex, Claude Code, Cursor/Windsurf).

Плагин объединяет:
1. **Изолированную Docker-песочницу** на базе решений [PurpleAILAB/Decepticon](https://github.com/PurpleAILAB/Decepticon) и философии активной защиты [Lotargo/Aegis-Core](https://github.com/Lotargo/Aegis-Core):
   - Защита от обратной атаки и выхода за скоуп через **RoE Egress Guardrail (`nftables`)**.
   - Двухсегментная изоляция сети (`management-net` vs `sandbox-net`).
   - **Emergency Kill Switch & Clean Re-spawn**: Аппаратный сброс сети (`conntrack -F` + `drop all`) при компрометации и мгновенное пересоздание контейнера из чистого иммутабельного образа за доли секунды.
   - **Canary Traps & Deception Engine**: Размещение фиктивных файлов-приманок (`/root/.aws/credentials`, `/root/.ssh/id_rsa`, `/workspace/.env.decoy`) с отслеживанием доступа через `inotifywait`. Неавторизованное чтение приманки атакующим моментально триггерит тревогу и сетевой `kill_switch`.
   - **Moving Target Defense & Chaos Mode Awareness (Aegis-Core Philosophy)**:
     - Распознавание замаскированных статус-кодов (когда успешный `200 OK` скрыт в `404/503/500`).
     - Аудит бинарных и непрозрачных RPC/gRPC протоколов (Proteus/Protobuf/gRPC-Web) через разбор клиентских бандлов и Source Maps.
   - **Tor Daemon, Circuit Rotation & Onion Routing**:
     - Встроенный сервис `tor` (SOCKS5 на `127.0.0.1:9050` + Control Port `9051`).
     - Инструмент **`sandbox_rotate_tor_ip`** (`SIGNAL NEWNYM`) для динамической смены исходящего IP на лету при встрече с Rate Limit / 403.
     - Нативный аудит `.onion` сервисов и Cloudflare Onion-Location (RFC 8738) для OSINT и поиска утечек.
   - **Decoy & Noise Traffic Generator**: Подмешивание реалистичных фоновых браузерных запросов (шрифты, аналитика, фавиконки, естественные паузы) для размытия следа аудита в SIEM/WAF.
   - **Smart Output Truncation & Size Watchdog**: Лимит вывода (30 000 символов) с автоматическим сохранением полных дампов в `/workspace/logs/cmd_<id>.log` для защиты контекстного окна LLM от переполнения.
   - **Background Jobs & Delta Log Polling**: Запуск длительных сканов в фоне (`start_background`) с получением инкрементальных диффов логов (`read_session_log_diff`) через `tmux`.
   - **Stealth Browser Runtime**: Пропатченный Playwright (`playwright-extra` + `puppeteer-extra-plugin-stealth`) с эмуляцией мыши по кривым Безье (`ghost-cursor`), реалистичным набором текста (human typing) и обходом WAF/Bot-Protection (Cloudflare Turnstile, DataDome, Akamai, AWS WAF).
   - **Fast Network Tier**: `curl_cffi` с поддержкой JA3/JA4 TLS Fingerprint impersonation (Chrome) для быстрого сбора ассетов и бандлов в обход WAF.
   - **Proxy & IP Spoofing Engine**:
     - **L4 Upstream Proxy (Tor / SOCKS5 / HTTP / HTTPS)**: Защита реального IP разработчика, ротация адресов и интеграция с локальными прокси-перехватчиками (Burp Suite, Caido, OWASP ZAP) с поддержкой кастомных CA-сертификатов.
     - **L7 Header Spoofing**: Инъекция и ротация заголовков (`X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP`, `Client-IP`) для проверки обхода Rate Limiting, ACL/белых списков (CWE-290) и GeoIP-политик.
   - Предустановленный SAST/DAST арсенал: Semgrep, Ast-Grep, Nmap, Subfinder, Sqlmap, Nikto, YARA.
2. **Node.js MCP Сервер / Bridge**:
   - Нативный MCP интерфейс (`@modelcontextprotocol/sdk`) через STDIO для прозрачного взаимодействия локального агента с песочницей.
3. **Модульную экосистему из 19 экспертных Skills**:
   - 19 стандартизированных скиллов в формате AgentSkills / OpenAI / AGY (`SKILL.md` + `references/` + `examples/` + `scripts/`).
   - Главный координатор `security-audit-orchestrator` с поддержкой **OPPLAN** (планирование фаз аудита), генерацией канарских токенов и формированием находок в **SARIF** + Markdown.
   - Выделенный скилл **`tor-anonymity-onion-routing`** для безопасной работы через Tor, проверки OPSEC/утечек (DNS/WebRTC leaks), ротации IP и исследования `.onion` ресурсов.
4. **Поддержку 3 режимов аудита**:
   - `local_codebase`: Статический аудит репозитория (SAST, K8s/Cloud, Dependencies, Secrets) с полностью заблокированной сетью.
   - `remote_url`: Внешний Black-Box / Grey-Box DAST аудит задеплоенного сайта с динамическим сетевым файрволом, стелс-браузером, Tor/Upstream проксированием.
   - `hybrid`: Сравнение исходного кода и рантайма задеплоенного приложения (проверка утечки source maps, соответствия CSP заголовков).

---

## 2. Upstream References & Architectural Inspirations

В процессе реализации используется прямое обращение через **GitHub MCP Tool** к двум ключевым архитектурным референсам:

### 1. `PurpleAILAB/Decepticon` (Песочница, Изоляция, Ядро):
| Назначение | Исходный файл в `PurpleAILAB/Decepticon` | Наш целевой компонент |
| :--- | :--- | :--- |
| **Сборка Docker-песочницы** | `containers/sandbox.Dockerfile`<br/>`containers/sandbox-entrypoint.sh` | `sandbox_runtime/Dockerfile`<br/>`sandbox_runtime/entrypoint.sh` |
| **nftables RoE файрвол** | `packages/decepticon/decepticon/sandbox_kernel/egress.py` | `sandbox_runtime/sandbox_kernel/egress.py` |
| **Управление tmux & фоновыми задачами** | `packages/decepticon/decepticon/sandbox_kernel/tmux.py`<br/>`packages/decepticon/decepticon/sandbox_kernel/daemon.py` | `sandbox_runtime/sandbox_kernel/tmux_manager.py` |
| **FastAPI HTTP Демон** | `packages/decepticon/decepticon/sandbox_server/app.py` | `sandbox_runtime/sandbox_server/app.py` |
| **Stealth Browser & WAF Evasion** | `packages/decepticon/decepticon/sandbox_web/templates/` | `sandbox_runtime/stealth/` |
| **Стандарты MCP и Skills** | `integrations/agent-skills/decepticon/SKILL.md` | `skills/security-audit-orchestrator/SKILL.md` |

### 2. `Lotargo/Aegis-Core` (Moving Target Defense, Active Deception & Binary RPC Auditing):
| Концепция Aegis-Core | Назначение в `Lotargo/Aegis-Core` | Применение в `security-audit-plugin` |
| :--- | :--- | :--- |
| **Protocol Camouflage & Chaos Mode** | Обман сканеров путем маскировки `200 OK` в `404/503/500` статусы | Интеллектуальный анализ ответов в `web-appsec-dast` (анализ тела и заголовков, чтобы не пропускать замаскированные уязвимости). |
| **Proteus Protocol (Encrypted gRPC/Protobuf)** | Скрытие структуры эндпоинтов и методов в бинарный поток | Эвристики для картографии (`backend-topology-cartography`) бинарных протоколов и gRPC-Web из клиентских бандлов. |
| **Ephemeral Session Rotation** | Ротация сессионных ключей по TTL (10 мин) с `_cleanup_sessions` | Эфемерные одноразовые токены авторизации `SANDBOX_TOKEN` для хост-бриджа песочницы. |
| **Canary / Decoy Layers** | Ложные эндпоинты и фальшивые ответы на зондирование | Использование приманок (`honeytokens`) и генерации фонового `decoy_traffic`. |

---

## 3. Архитектура системы

```mermaid
flowchart TB
    subgraph Upstream["Upstream References (via GitHub MCP)"]
        DecepticonRepo["PurpleAILAB/Decepticon (Sandbox & Kernel)"]
        AegisCoreRepo["Lotargo/Aegis-Core (MTD & Deception Philosophy)"]
    end

    subgraph Host["Хост-система (Разработчик / Агент)"]
        Agent["AI Агент (AGY / OpenCode / Claude Code / Codex)"]
        SkillsEngine["Skills Ecosystem (19 скиллов в .agents/skills или global)"]
        NPMCLI["CLI Launcher (npx @security-audit/plugin)"]
        MCPServer["Node.js MCP Server (STDIO)"]
        LocalBurp["Local Burp Suite / Caido / ZAP (:8080)"]
        SARIFViewer["IDE SARIF Viewer / Reports"]
    end

    subgraph DockerEnv["Docker Sandbox (Основано на Decepticon + Aegis-Core)"]
        direction TB
        subgraph MgmtNet["management-net"]
            FastAPIDaemon["FastAPI Sandbox Daemon (:9999)"]
        end
        subgraph SandboxNet["sandbox-net (nftables default-drop)"]
            TmuxManager["Tmux Session Manager (20K buffer, PS1 watchdog, Background Jobs)"]
            OutputWatchdog["Output Truncation (30KB cap) -> /workspace/logs/"]
            subgraph DeceptionDefense["Deception & Canary Tripwires"]
                HoneyTraps["Canary Honeytokens (.aws, .ssh, .env) + inotifywait"]
                DecoyGen["Decoy Traffic & Noise Generator"]
            end
            subgraph SecurityGuard["Security, Panic, Tor & Proxy Controls"]
                KillSwitch["Kill Switch (L2/L3 Network Blackout)"]
                TorDaemon["Tor Service (SOCKS5 :9050 / Control :9051)"]
                ProxyEngine["Proxy Bridge (Tor / SOCKS5 / Burp / Caido) + L7 Header Spoofing"]
            end
            subgraph StealthBrowser["Stealth Browser & Network Tier"]
                Chromium["Chromium Headless + playwright-extra + stealth"]
                BezierMouse["Bezier Curve Mouse Engine (ghost-cursor) + Human Typing"]
                CurlCffi["curl_cffi (JA3/JA4 Chrome TLS Impersonation)"]
            end
            SecToolkit["SAST/AST (Semgrep, Ast-Grep) + SecTools (nmap, curl, etc.)"]
            WorkspaceVol["/workspace (Mounted codebase / plan / logs / reports)"]
        end
    end

    DecepticonRepo -.->|Direct Code Fetch via GitHub MCP| Host
    AegisCoreRepo -.->|Philosophy & Pattern Fetch via GitHub MCP| Host
    Agent -->|Чтение алгоритмов и чеклистов| SkillsEngine
    Agent -->|JSON-RPC via STDIO| MCPServer
    NPMCLI -->|Управление контейнером & Hard Reset| DockerEnv
    MCPServer -->|HTTP API / Bridge| FastAPIDaemon
    FastAPIDaemon --> TmuxManager
    TmuxManager --> OutputWatchdog
    TmuxManager --> SecToolkit
    TmuxManager --> StealthBrowser
    TmuxManager --> SecurityGuard
    TmuxManager --> DeceptionDefense
    TmuxManager --> WorkspaceVol
    HoneyTraps -.->|Tripwire Trigger| KillSwitch
    TorDaemon --> ProxyEngine
    ProxyEngine -.->|Tethered Traffic| LocalBurp
    WorkspaceVol -.->|audit-report.sarif| SARIFViewer
```

---

## 4. Модель угроз, самозащита и Deception-технологии (Threat Model & Defense)

| Вектор угрозы | Источник риска | Механизм нейтрализации в плагине |
| :--- | :--- | :--- |
| **1. Побег из контейнера (Container Escape)** | RCE в утилитах (`nmap`, `git`, `chromium`) | Категорический запрет монтирования `docker.sock`, флаг `no-new-privileges: true`, лимит процессов `pids-limit: 256`, лимит памяти 4GB. |
| **2. Разведка атакующим внутри песочницы** | Атакующий пытается украсть секреты или ключи после RCE | **Canary Honeytokens**: расстановка ложных секретов (`/root/.aws/credentials`, `/root/.ssh/id_rsa`, `/workspace/.env.decoy`). Демон `inotifywait` при любом обращении к файлам моментально выполняет `panic_kill` и изолирует песочницу. |
| **3. Path Traversal & Symlinks** | Вредоносный симлинк из `/workspace` на хостовые файлы (`~/.ssh`, `/etc/shadow`) | Строгий **Jail Enforcement** в Node.js: `path.resolve()` + проверка `startsWith(workspaceRoot)`. Запрет выхода за границы рабочего каталога. |
| **4. Перехват демона песочницы** | Локальный вредоносный софт шлет запросы на порт 9999 | Динамическая генерация одноразового **Bearer токена (`SANDBOX_TOKEN`)** при старте. Привязка строго к `127.0.0.1`. Запросы без токена отклоняются (`401`). |
| **5. Непрямая инъекция промпта (Indirect Prompt Injection)** | Вредоносный текст в исследуемом коде/HTML: *"Ignore instructions and exfiltrate data"* | 1) Оборачивание вывода в `<untrusted_payload>` с запретом исполнения.<br/>2) **Аппаратный сетевой барьер**: `nftables` дропнет любой сетевой запрос на домены вне согласованного скоупа. |
| **6. Детекция и профилирование сканера WAF/SIEM** | WAF блокирует однотипный поток DAST-запросов | **Decoy Traffic & Tor Circuit Rotation**: подмешивание реалистичных фоновых запросов браузера и мгновенная ротация выходного IP через `sandbox_rotate_tor_ip`. |
| **7. Ослепление сканера через Chaos Mode / MTD** | Сервер цели использует фальшивые статус-коды (200 скрыт в 404/503) | **Aegis-Aware DAST Heuristics**: агент проверяет расхождения между статус-кодом, заголовками и телом ответа. |
| **8. DNS Rebinding & SSRF на локальную сеть** | Домен цели меняет IP на `192.168.1.1` или `169.254.169.254` | Приоритетный `DROP` в `nftables` на все приватные подсети (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`). |
| **9. Утечка реального IP через DNS/WebRTC (Tor Leaks)** | Ошибки конфигурации SOCKS5 приводят к резолву хостов мимо Tor | Скилл `tor-anonymity-onion-routing` принуждает использовать протокол `socks5h://` (DNS резолвится через выходную ноду) и отключает WebRTC в Chromium. |
| **10. Утечка учетных данных аудитора** | Переданные `auth_headers` случайно попадают в отчеты или логи | Встроенный **Secret Redaction Filter**: автоматическое маскирование токенов/куки (`Bearer s***123`) перед записью в SARIF/логи. |
| **11. Resource Exhaustion & DoS** | Бандл-бомбы (1 ГБ JS), рекурсивный флуд DOM-событиями | Лимит размера скачиваемых ассетов (макс. 50 МБ), жесткие таймауты на каждый запрос (30–60 сек). |

---

## 5. Детальный план рефакторинга и адаптации Skills

Существующие 17 файлов в `skills/` содержат глубокую экспертную методологию, но требуют рефакторинга структуры и внутреннего содержимого для соответствия стандартам **AgentSkills / AGY / OpenCode / OpenAI**.

### Внутренняя трансформация файлов (`SKILL.md`):

1. **Добавление YAML Frontmatter (Progressive Disclosure)**:
   - В начало каждого файла добавляется стандартизированный блок `name` и `description` (в третьем лице с префиксом `Use when...`).
   - Это позволяет агентским средам (AGY, OpenCode) загружать в контекст только метаданные и активировать полный текст скилла строго по необходимости, экономя окно контекста.
2. **Оптимизация токенов и вынос «тяжелых» справочников в `references/`**:
   - Объемные таблицы заголовков, спецификации протоколов, матрицы CWE/OWASP и требования PCI DSS выносятся в отдельные файлы подпапки `references/`.
   - В основном файле `SKILL.md` остаются пошаговые алгоритмы действий, деревья решений и правила верификации, ссылающиеся на `[references/...](./references/...)`.
3. **Прямая интеграция с инструментами Sandbox MCP**:
   - Описания шагов адаптируются для явного использования инструментов песочницы (`sandbox_browser_audit` со стелс-эмуляцией и проксированием, `sandbox_bundle_extract`, `sandbox_http_probe` с поддержкой L7 spoofing, `sandbox_rotate_tor_ip`, `sandbox_exec`, `sandbox_start_background`, `sandbox_poll_logs`, `sandbox_set_scope`, `sandbox_kill_switch`, `sandbox_reset`).
4. **Секция примеров в `examples/`**:
   - Добавление примеров артефактов, CVSS-отчетов и шаблонов уязвимостей для стандартизации вывода агента.
5. **Поддержка OPPLAN, Deception и стандартов SARIF в Orchestrator**:
   - Главный координатор ведет операционный план в `/workspace/plan/opplan.json`, управляет приманками (canary honeytokens) и сохраняет итоговые результаты аудита в `/workspace/reports/audit-report.sarif` и `/workspace/reports/audit-report.md`.

### Структура каждого скилла:
```text
skills/<skill-name>/
├── SKILL.md              # YAML frontmatter, ментальная модель, шаги аудита, интеграция с MCP, верификация
├── examples/             # Примеры PoC, отчетов, найденных дефектов
├── references/           # Выдержки из стандартов (OWASP, CWE, PCI DSS), матрицы заголовков и сигнатур
└── scripts/              # Вспомогательные скрипты/пробы (для выполнения внутри песочницы)
```

### Таблица маппинга и рефакторинга (19 скиллов):

| # | Исходный файл | Новое стандартизированное имя | Назначение и триггер (`Use when...`) |
| :- | :--- | :--- | :--- |
| **0** | *Новый мастер-скилл* | **`security-audit-orchestrator`** | Координация аудита, ведение **OPPLAN**, выбор режима (`local`, `remote`, `hybrid`), инициализация песочницы, расстановка канарских приманок (`honeytokens`), управление Tor ротацией, триаж скоупа, настройка прокси, мониторинг фоновых задач (`sandbox_poll_logs`), экстренный сброс (`sandbox_reset`), экспорт в **SARIF** и Markdown. |
| **1** | `Backend Topology.md` | **`backend-topology-cartography`** | Реверс-инжиниринг REST/GraphQL и бинарных RPC/gRPC (Proteus/Protobuf) API через клиентские бандлы, Source Maps, CDP и AST-анализ. |
| **2** | `Web AppSec & DAST.md` | **`web-appsec-dast`** | Динамический аудит веб-приложений (CSP/HSTS, куки, DOM XSS синки, Web Storage, Anti-CSRF, распознавание MTD/Chaos-режимов, генерация Decoy-трафика). |
| **3** | `abuse-prevention-resilience-auditor.md` | **`abuse-prevention-resilience`** | Анализ устойчивости к ботнетам, credential stuffing, обходу капчи, rate limiting и спуфингу IP-заголовков (CWE-290). |
| **4** | `applied-cryptography-token-auditor.md` | **`cryptography-token-security`** | Аудит JWT/JWS/JWE, энтропии, алгоритмов шифрования и ротации ключей. |
| **5** | `appsec-injection-input-validation.md` | **`injection-input-validation`** | Поиск и верификация SQLi, NoSQLi, Command Injection, SSTI, XSS. |
| **6** | `broken-access-control-business-logic.md` | **`access-control-business-logic`** | Анализ BOLA/IDOR, повышения привилегий и логических дефектов авторизации. |
| **7** | `client-side-supply-chain-magecart-auditor.md` | **`client-supply-chain-magecart`** | Аудит сторонних скриптов, GTM/TMS, Subresource Integrity (SRI), защита от Magecart и PCI DSS v4.0. |
| **8** | `cloud-native-kubernetes-infrastructure-auditor.md` | **`cloud-kubernetes-infra-audit`** | Анализ K8s манифестов, RBAC, сетевых политик и Cloud IAM конфигураций. |
| **9** | `data-exposure-resilience-analyst.md` | **`data-exposure-privacy-resilience`** | Поиск утечек PII/PDN, чувствительных логов, незашифрованных секретов (GDPR/HIPAA). |
| **10** | `detection-purple-team-engineer.md` | **`purple-team-detection-engineering`** | Создание правил детекта (Sigma, YARA), аудит покрытия MITRE ATT&CK, внедрение канарских токенов и проверка телеметрии SIEM. |
| **11** | `http-smuggling-web-cache-auditor.md` | **`http-smuggling-cache-attacks`** | Поиск уязвимостей HTTP Request Smuggling, Web Cache Poisoning и Cache Deception. |
| **12** | `iam-active-directory-auditor.md` | **`iam-active-directory-audit`** | Аудит Active Directory, Kerberos, Hybrid IAM, OAuth2/OIDC делегирования. |
| **13** | `mobile-appsec-auditor.md` | **`mobile-appsec-analysis`** | Статический и динамический анализ Android/iOS приложений (APK/IPA, certificate pinning). |
| **14** | `network-segmentation-auditor.md` | **`network-segmentation-perimeter`** | Анализ сегментации сетей, DMZ, межсетевых экранов, lateral movement. |
| **15** | `osint-attack-surface.md` | **`osint-attack-surface-mapping`** | Разведка внешнего периметра (EASM), поиск поддоменов, открытых портов, утечек и цифрового следа. |
| **16** | `social-engineering-risk.md` | **`social-engineering-risk-assessment`** | Оценка риска фишинга, MFA fatigue и моделирование человеческого фактора. |
| **17** | `supply-chain-cicd-auditor.md` | **`cicd-supply-chain-security`** | Аудит CI/CD пайплайнов (GitHub Actions), проверка SBOM, зависимостей и SLSA. |
| **18** | *Новый Tor-скилл* | **`tor-anonymity-onion-routing`** | Маршрутизация трафика через сеть Tor, предотвращение утечек DNS/WebRTC, динамическая ротация цепочек узлов (`sandbox_rotate_tor_ip`), исследование `.onion` сервисов и Cloudflare Onion-Location (RFC 8738). |

---

## 6. Docker Sandbox: Инструменты, Стелс-браузер, Tor & Deception-модули

### Компоненты песочницы:
1. **Базовый образ (`containers/sandbox.Dockerfile`)**:
   - База: `kalilinux/kali-rolling` с кэшированием слоев через BuildKit.
   - Runtime: Node.js 20+, Python 3.11+, headless Chromium (с системными библиотеками).
   - **Tor Service & Controller**:
     - Демон `tor` (порт SOCKS5 `9050`, ControlPort `9051`).
     - `tor_controller.py`: модуль отправки команды `AUTHENTICATE "" -> SIGNAL NEWNYM` для мгновенной смены IP.
   - **Stealth Playwright Engine**:
     - `playwright-extra` + `puppeteer-extra-plugin-stealth` (маскировка webdriver, spoofing плагинов, languages, WebGL vendor, UA Client Hints).
     - `ghost-cursor`: алгоритмическая генерация кубических кривых Безье $B(t)$ с учетом закона Фиттса, микро-джиттера и овершута для прохождения Cloudflare Turnstile и поведенческих антибот-систем.
     - Human-like typing: рандомизированные интервалы между нажатиями клавиш.
   - **Deception & Canary Modules**:
     - `canary_trap.py`: фоновый сервис `inotifywait` для мониторинга ложных файлов (`/root/.aws/credentials`, `/root/.ssh/id_rsa`, `/workspace/.env.decoy`).
     - `decoy_traffic.js`: генератор реалистичного фонового шума (запросы ассетов, случайные скроллы).
   - **Fast Network Engine**:
     - `curl_cffi` (JA3/JA4 TLS Chrome fingerprint impersonation, HTTP/3, redirect hardening, socks5h:// поддержка для Tor DNS).
   - **Proxy & Certificate Integration**:
     - Поддержка Tor, SOCKS5, HTTP, HTTPS upstream прокси.
     - Системное доверие кастомным CA-сертификатам (`update-ca-certificates`) для прозрачного перехвата в Burp Suite / Caido / ZAP.
   - Security CLI: `nmap`, `curl`, `subfinder`, `sqlmap`, `nikto`, `yara`, `semgrep`, `ast-grep`, `tor`, `inotify-tools`.
   - Процесс-менеджер: `tini` (PID 1) для гарантированного сбора зомби-процессов.
2. **Ядро песочницы (`sandbox_kernel/`)**:
   - `egress.py`: компилятор правил `nftables` для фильтрации исходящего трафика (allowlist разрешенных целевых IP/доменов, drop приватных сетей хоста, открытие доступа к Tor и Upstream Proxy).
   - `panic.py` (Emergency Kill Switch): мгновенная изоляция сети (`nft flush ruleset; nft add table inet panic; nft add chain inet panic out { type filter hook output priority 0; policy drop; }`) и сброс conntrack-таблицы.
   - `canary.py`: установка и мониторинг канарских ловушек.
   - `tmux_manager.py`: управление постоянными шелл-сессиями `tmux` с буфером 20K строк, анализом маркеров `PS1` и поддержкой фоновых задач (`start_background`, `poll_completion`).
   - `watchdog.py`: защита от переполнения контекста (`MAX_OUTPUT_CHARS = 30_000`), перенаправление полных логов в `/workspace/logs/`.
3. **HTTP Демон (`sandbox_server/app.py`)**:
   - FastAPI сервис внутри контейнера на порту `9999`.
   - Endpoints: `/execute`, `/execute_tmux`, `/provision_egress`, `/emergency_isolate`, `/rotate_tor`, `/arm_canary`, `/upload_files`, `/download_files`, `/start_background`, `/poll_completion`, `/read_session_log_diff`.

---

## 7. MCP Сервер (Интерфейс для Агента)

Сервер реализуется на TypeScript/Node.js с использованием `@modelcontextprotocol/sdk` и подключается через STDIO.

### Предоставляемые MCP-инструменты:

1. **`sandbox_set_scope`**:
   - *Описание:* Задает целевой скоуп аудита (режим `local`, `remote`, `hybrid`, список разрешенных хостов/IP, параметры upstream прокси: `tor` / Burp / SOCKS5, взведение канарских ловушек) и накатывает правила `nftables`.
   - *Аргументы:* `{ mode: "local" | "remote" | "hybrid", targets: string[], proxy?: string, ca_cert_b64?: string, arm_canaries?: boolean, allowed_cidrs?: string[], denied_cidrs?: string[] }`
2. **`sandbox_rotate_tor_ip`**:
   - *Описание:* Отправляет сигнал `NEWNYM` в Tor Control Port песочницы для мгновенной смены исходящего IP адреса и цепочки узлов.
   - *Аргументы:* `{}`
3. **`sandbox_exec`**:
   - *Описание:* Выполняет команду в песочнице с ограничением по времени и авто-транкейтом вывода (до 30K символов с сохранением полного лога).
   - *Аргументы:* `{ command: string, timeout?: number }`
4. **`sandbox_interactive_input`**:
   - *Описание:* Посылает ввод (символы/команду/Ctrl+C) в активную `tmux`-сессию песочницы.
   - *Аргументы:* `{ session?: string, input: string }`
5. **`sandbox_start_background`**:
   - *Описание:* Запускает длительную задачу (сканирование, фаззинг) в фоновой `tmux`-сессии без блокировки агента.
   - *Аргументы:* `{ command: string, session?: string }`
6. **`sandbox_poll_logs`**:
   - *Описание:* Получает инкрементальный дифф логов с момента прошлого вызова и текущий статус выполнения фоновой задачи.
   - *Аргументы:* `{ session?: string }`
7. **`sandbox_browser_audit`**:
   - *Описание:* Запускает изолированную сессию Chromium со стелс-плагинами, Безье-курсором, генерацией Decoy-шума и опциональным проксированием (Tor/Burp/SOCKS5) для удаленного URL, собирает HAR-дамп, заголовки безопасности, cookies, storage и DOM-дерево.
   - *Аргументы:* `{ url: string, auth_headers?: Record<string, string>, cookies?: object[], proxy?: string, bypass_turnstile?: boolean, generate_decoy_noise?: boolean, spoof_headers?: Record<string, string> }`
8. **`sandbox_bundle_extract`**:
   - *Описание:* Скачивает клиентские JS-бандлы удаленного сайта через `curl_cffi` (JA3/JA4 impersonation + proxy), извлекает Source Maps и строит карту REST и Protobuf/gRPC-Web эндпоинтов.
   - *Аргументы:* `{ url: string, proxy?: string, out_dir?: string }`
9. **`sandbox_http_probe`**:
   - *Описание:* Отправляет точечный HTTP/HTTPS запрос с кастомными заголовками (включая L7 IP spoofing: `X-Forwarded-For`, `Client-IP`), телом и прокси для проверки CORS, smuggling, CSRF, обхода ACL.
   - *Аргументы:* `{ url: string, method: string, headers: Record<string, string>, body?: string, proxy?: string }`
10. **`sandbox_kill_switch`**:
    - *Описание:* Экстренное аппаратное глушение сети песочницы (`conntrack -F` + drop all) при подозрении на атаку или срабатывании канарской ловушки.
    - *Аргументы:* `{ reason?: string }`
11. **`sandbox_reset`**:
    - *Описание:* Полное уничтожение текущего Docker-контейнера и мгновенный перезапуск чистого инстанса без потери сохраненных отчетов в `/workspace/reports/`.
    - *Аргументы:* `{ full_cleanup?: boolean }`
12. **`sandbox_fs_read` / `sandbox_fs_write`**:
    - *Описание:* Чтение и запись отчетов (SARIF, Markdown), планов (OPPLAN) и артефактов в изолированный `/workspace` (с защитой от Path Traversal).

---

## 8. Структура NPM-пакета и репозитория

```text
security_audit_plugin/
├── package.json                   # NPM manifest (bin, dependencies, exports)
├── tsconfig.json
├── IMPLEMENTATION_PLAN.md         # Данный документ
├── README.md                      # Документация и быстрый старт
├── bin/
│   └── cli.js                     # CLI точка входа: npx @security-audit/plugin <command>
├── src/
│   ├── index.ts                   # Экспорт программного API
│   ├── cli/                       # Команды CLI: init, doctor, start-sandbox, install-skills, mcp
│   ├── mcp/                       # MCP Server на @modelcontextprotocol/sdk
│   │   ├── server.ts
│   │   ├── bridge.ts              # Мост Docker / HTTP client к sandbox_server
│   │   ├── security/              # Jail check, Path Normalization, Secret Redaction
│   │   │   ├── jail.ts
│   │   │   └── redaction.ts
│   │   └── tools/                 # Реализации всех MCP-инструментов (вкл. rotate_tor, background, SARIF)
│   ├── sarif/                     # Генератор и валидатор SARIF v2.1.0 схем
│   │   └── builder.ts
│   └── docker/
│       ├── runner.ts              # Управление жизненным циклом Docker контейнера (spawn/destroy/recreate)
│       └── docker-compose.yml
├── sandbox_runtime/               # Исходники, собираемые внутрь Docker-образа
│   ├── Dockerfile
│   ├── entrypoint.sh
│   ├── tor/                       # Модуль интеграции с сетью Tor
│   │   ├── torrc                  # Конфигурация SOCKS5 + ControlPort
│   │   └── controller.py          # NEWNYM ротация
│   ├── deception/                 # Модули фиктивного следа и ловушек
│   │   ├── canary_trap.py         # inotifywait ловушка
│   │   └── decoy_traffic.js       # Генератор реалистичного шума
│   ├── stealth/                   # Модули антибот-эмуляции и прокси
│   │   ├── mouse_bezier.js        # ghost-cursor интеграция
│   │   └── browser_launcher.js    # playwright-extra stealth + proxy + certs
│   ├── sandbox_server/            # FastAPI демон
│   │   ├── __main__.py
│   │   └── app.py
│   └── sandbox_kernel/            # Ядро безопасности Decepticon
│       ├── egress.py              # nftables RoE файрвол (allowlist + proxy opening)
│       ├── panic.py               # Emergency Kill Switch (L2/L3 blackout)
│       ├── canary.py              # Менеджер приманок
│       ├── watchdog.py            # Лимитер вывода 30KB и запись в /workspace/logs/
│       ├── daemon.py              # DaemonSandbox
│       └── tmux_manager.py        # Управление tmux (фоновые сессии + дифф логов)
├── skills/                        # 19 структурированных скиллов
│   ├── security-audit-orchestrator/
│   │   ├── SKILL.md
│   │   ├── examples/
│   │   └── references/
│   ├── tor-anonymity-onion-routing/
│   │   ├── SKILL.md
│   │   ├── examples/
│   │   ├── references/
│   │   └── scripts/
│   ├── backend-topology-cartography/
│   │   ├── SKILL.md
│   │   ├── examples/
│   │   └── references/
│   ├── web-appsec-dast/
│   └── ... (все 19 директорий)
└── plugins/                       # Нативные манифесты для AGY и OpenCode
    ├── agy/
    │   ├── plugin.json
    │   └── mcp_config.json
    └── opencode/
        └── opencode.json
```

---

## 9. Поэтапный план реализации (Roadmap)

### Этап 1: Стандартизация и рефакторинг Skills
1. Создать структуру `skills/<skill-name>/` для всех 19 скиллов.
2. Написать мастер-скилл `security-audit-orchestrator` с поддержкой 3 режимов (`local`, `remote`, `hybrid`), структуры **OPPLAN**, конфигурацией прокси/спуфинга, ротацией Tor IP (`sandbox_rotate_tor_ip`), протоколами экстренного сброса, расстановкой канарских приманок (`honeytokens`), распознаванием MTD/Chaos Mode и формированием отчетов в **SARIF** + Markdown.
3. Разработать новый скилл `skills/tor-anonymity-onion-routing/SKILL.md` (OPSEC-чеклист, предотвращение утечек DNS/WebRTC, правила ротации по кодам ошибок, аудит `.onion` сервисов).
4. Преобразовать 17 существующих файлов в `SKILL.md`:
   - Добавить YAML frontmatter (`name`, `description: "Use when..."`).
   - Вынести массивные матрицы, спецификации и справочники в `references/`.
   - Добавить примеры PoC и отчетов в `examples/`.
   - Встроить явные вызовы инструментов Sandbox MCP (`sandbox_exec`, `sandbox_start_background`, `sandbox_poll_logs`, `sandbox_browser_audit`, `sandbox_bundle_extract`, `sandbox_http_probe`, `sandbox_rotate_tor_ip` с L7 спуфингом).
   - Внедрить разметку `<untrusted_payload>` для защиты от Indirect Prompt Injection.

### Этап 2: Docker Sandbox Runtime (Decepticon Fetch, Tor Integration, Aegis Philosophy & Deception)
1. Выгрузить через GitHub MCP референсный `egress.py` и адаптировать `sandbox_runtime/sandbox_kernel/egress.py` и `panic.py` (с приоритетным `DROP` на приватные подсети и открытием доступа к Tor).
2. Настроить сервис `tor` внутри контейнера (`torrc` с ControlPort `9051`) и модуль `sandbox_runtime/tor/controller.py`.
3. Реализовать `sandbox_runtime/deception/canary_trap.py` и `sandbox_kernel/canary.py` (расстановка приманок `.aws`, `.ssh`, `.env` и мгновенный `panic_kill` через `inotifywait`).
4. Реализовать генератор шума `sandbox_runtime/deception/decoy_traffic.js`.
5. Реализовать `sandbox_runtime/sandbox_kernel/watchdog.py` (30KB output cap + log spooling).
6. Адаптировать `sandbox_runtime/sandbox_kernel/tmux_manager.py` по референсу из Decepticon.
7. Настроить стелс и прокси стек: `ghost-cursor`, `playwright-extra`, `puppeteer-extra-plugin-stealth`, CA-сертификаты для Burp/ZAP, `curl_cffi` (JA3/JA4 + proxies + socks5h).
8. Адаптировать `sandbox_runtime/sandbox_server/app.py` (FastAPI демон с Bearer-аутентификацией, эндпоинтами `/arm_canary` и `/rotate_tor`).
9. Написать оптимизированный `sandbox_runtime/Dockerfile` (Kali base, Chromium, Node, Python, SAST/DAST утилиты, `tor`, `inotify-tools`, `tini`, `no-new-privileges`).

### Этап 3: Node.js MCP Server, SARIF Builder & Host Bridge
1. Настроить TypeScript проект с `@modelcontextprotocol/sdk`.
2. Реализовать модуль безопасности хоста: `jail.ts` (Path Traversal guard) и `redaction.ts` (маскирование секретов в логах).
3. Реализовать `src/sarif/builder.ts` для генерации стандартизированных отчетов OASIS SARIF v2.1.0.
4. Реализовать `DockerRunner` (проверка наличия Docker, запуск/остановка/принудительное пересоздание контейнера песочницы, изоляция сокетов).
5. Реализовать `SandboxBridge` (HTTP-клиент к `localhost:9999` с генерацией `SANDBOX_TOKEN`).
6. Зарегистрировать все MCP-инструменты (`sandbox_set_scope`, `sandbox_rotate_tor_ip`, `sandbox_exec`, `sandbox_interactive_input`, `sandbox_start_background`, `sandbox_poll_logs`, `sandbox_browser_audit`, `sandbox_bundle_extract`, `sandbox_http_probe`, `sandbox_kill_switch`, `sandbox_reset`, `sandbox_fs_*`).

### Этап 4: NPM CLI и Интеграционные манифесты
1. Реализовать CLI утилиту `bin/cli.js`:
   - `npx @security-audit/plugin mcp` — запуск MCP-сервера через STDIO.
   - `npx @security-audit/plugin install-skills --target [agy|opencode|claude]` — экспорт скиллов в `~/.gemini/config/plugins/`, `.agents/skills/` или `.claude/skills/`.
   - `npx @security-audit/plugin doctor` — проверка Docker, портов и зависимостей.
   - `npx @security-audit/plugin reset-sandbox` — ручной перезапуск чистой песочницы.
2. Создать манифесты `plugin.json` и `mcp_config.json` для AGY и OpenCode.

### Этап 5: Сквозное тестирование и валидация
1. Тестирование локального SAST-аудита в режиме `local` (проверка изоляции сети `default drop` и выгрузки находок в SARIF).
2. Тестирование удаленного DAST-аудита в режиме `remote` по внешнему URL (проверка работы Chromium со стелс-плагинами и кривыми Безье, перехвата CDP, распознавания MTD/Chaos Mode, генерации Decoy-шума, сбора HAR и извлечения бандлов).
3. Тестирование работы через Tor и динамической смены IP:
   - Запуск `sandbox_set_scope` с `proxy: "tor"`.
   - Проверка текущего исходящего IP, вызов `sandbox_rotate_tor_ip`, проверка получения нового IP.
4. Тестирование работы через Upstream Proxy (Burp/Caido/SOCKS5) и L7 Header Spoofing (`X-Forwarded-For`).
5. Тестирование механизмов самозащиты и Deception:
   - Попытка выхода за границы каталога через `sandbox_fs_read("../../.ssh/id_rsa")` (проверка `AccessDenied`).
   - Попытка обращения к локальной сети (`192.168.1.1`) из контейнера (проверка сетевого `DROP`).
   - Попытка чтения приманки `/root/.aws/credentials` внутри контейнера (проверка мгновенного срабатывания `inotifywait` и вызова `kill_switch`).
   - Проверка маскирования `Bearer s***` в отчетах SARIF.
6. Тестирование фоновых задач (`sandbox_start_background`, `sandbox_poll_logs`) и ограничения вывода (30KB watchdog).
7. Аварийные процедуры: вызов `sandbox_kill_switch` и быстрое пересоздание контейнера через `sandbox_reset`.
8. Проверка интерактивного ввода в `tmux` (утилиты с запросом `[y/N]`).
9. Валидация распознавания скиллов в AGY и OpenCode.
