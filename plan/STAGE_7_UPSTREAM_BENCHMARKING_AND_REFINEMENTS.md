# Stage 7: Upstream Benchmarking, Architectural Comparison & Refinement Backlog

## 1. Executive Summary & Context

В рамках проекта **`security-audit-plugin`** была завершена базовая реализация всех 6 основных этапов:
1. **Stage 1**: Рефакторинг 19 скиллов под стандарты AgentSkills / AGY / OpenCode с выносом справочников в `references/`, примеров в `examples/` и скриптов в `scripts/`.
2. **Stage 2**: Rust Sandbox Runtime Core (`sandbox-kernel` и `sandbox-daemon` на Axum/Tokio) с поддержкой `zeroize`, `inotify` canary приманок, `nftables` RoE файрвола, `tmux` сессий и watchdog усечения логов.
3. **Stage 3**: Host MCP Bridge на TypeScript (`@modelcontextprotocol/sdk`) со скользящим рэтчетом Ed25519/ChaCha20-Poly1305, jail-гвардом путей и SARIF v2.1.0 генератором.
4. **Stage 4**: NPM CLI (`@security-audit/plugin`) с командами `audit`, `sandbox`, `doctor`, `install`, `uninstall`, `init`.
5. **Stage 5**: Модульное и интеграционное тестирование (35 тестов Jest, 10 тестов Cargo).
6. **Stage 6**: Универсальный установщик и манифесты для всех платформ (AGY, Claude Code, OpenCode, Cursor, Gemini CLI).

Для обеспечения промышленного уровня качества и надежности был проведен глубокий аудит и сравнительный анализ нашей реализации с двумя исходными референсными кодовыми базами через GitHub MCP коннектор:
* **`PurpleAILAB/Decepticon`** (промышленная песочница, изоляция сетевого уровня, отказоустойчивый tmux, WAF-детектор с профилями, стелс-браузер с защитой от SSRF);
* **`Lotargo/Aegis-Core`** (Moving Target Defense, криптографический протокол Proteus, ротация сессионных ключей с авто-реконнектом, рандомизация фальшивых статус-кодов для обмана сканеров).

Настоящий документ фиксирует результаты детального сравнительного анализа и формирует исчерпывающий бэклог доработок **Stage 7**.

---

## 2. Архитектурная сравнительная матрица

| Подсистема | Реализация в `security-audit-plugin` (Текущее состояние) | Референс `PurpleAILAB/Decepticon` | Референс `Lotargo/Aegis-Core` | Выявленные дефициты и точки улучшения |
| :--- | :--- | :--- | :--- | :--- |
| **1. Egress RoE Firewall & Network Boundary** | `sandbox-kernel/src/egress.rs` генерирует правила `nftables` на основе статического конфига (`allowed_cidrs`, `denied_cidrs`). Порт управления захардкожен (9999). | `sandbox_kernel/egress.py`: динамический парсинг `/proc/net/route` (чтение hex без зависимости от бинарника `ip`) для авто-разрешения on-link subnets (`sandbox-net`); авто-поиск DNS в `/etc/resolv.conf`; разделение IPv4 и IPv6 (`_split_family`) для предотвращения ошибок загрузки `inet` таблиц. | Отсутствует (Aegis работает на L7). | 1. Добавить динамический дискавери on-link подсетей из `/proc/net/route` в Rust.<br/>2. Разделять IPv4 и IPv6 адресные множества в `egress.rs`.<br/>3. Предотвратить разрыв связи с хостом при применении кастомных политик. |
| **2. Tmux Session & Process Management** | `sandbox-kernel/src/tmux.rs` запускает сессии с лимитом 20K строк, отправляет команды через `send-keys` и опрашивает статус. | `sandbox_kernel/tmux.py` + `app.py`: авто-зачистка зависших сокетов (`reap_orphaned_tmux_sessions`) при старте демона; инкрементальный diff логов по байтовому/строковому смещению (`read_session_log_diff`); предотвращение гонок сигналов `SIGCHLD` через делегирование `tini` (PID 1). | Отсутствует. | 1. Добавить метод очистки осиротевших tmux-сокетов при рестарте контейнера.<br/>2. Реализовать инкрементальное чтение diff логов (`read_session_log_diff`, `reset_session_log_offset`) по смещению.<br/>3. Оптимизировать детекцию завершения фоновых команд. |
| **3. Stealth Browser & WAF Evasion** | `sandbox_runtime/stealth/browser_launcher.js` запускает Chromium через `playwright-extra` + `puppeteer-extra-plugin-stealth` и мышь Безье. | `sandbox_web/` + `templates/playwright_real_chrome.js`: многосигнальный WAF-детектор (`waf_detector.py`) с базой сигнатур (`waf_profiles.yaml`); `launchPersistentContext`; проход warmup-страницы (Site Root) для сбора сенсорных куки; внутрибраузерный L7 SSRF guard (`ipaddr.js` + `dns.lookup`); структурированный JSON-конверт. | `core_b/main.py`: эмуляция обманных статус-кодов (`DECEPTION_RATIO`, 200 под видом 404/503). | 1. Интегрировать WAF Multi-Signal Detector & Profiles (Cloudflare, Akamai, AWS WAF, DataDome, F5, PerimeterX) в probe/stealth.<br/>2. Добавить warmup-навигацию (разогрев сенсоров WAF перед переходом на целевой URL).<br/>3. Встроить SSRF/DNS-rebinding фильтрацию прямо в перехватчик запросов браузера (`page.route`). |
| **4. Cryptography, Rolling BYOK & MTD** | `src/mcp/security/ratchet_bridge.ts` и `sandbox-daemon/src/auth.rs`: Ed25519 подписи запросов, ChaCha20-Poly1305 шифрование тела, `zeroize` в памяти, ротация ключей 15–30с. | Простая токен-аутентификация `Authorization: Bearer <SANDBOX_TOKEN>` в `app.py`. | `aegis_core/crypto.py` + `core_a/main.py`: AEAD с привязкой метаданных (Associated Data); фоновый таск очистки сессий (`_cleanup_sessions`, TTL 600с); автоматический ре-хэндшейк при получении `UNAUTHENTICATED`. | 1. Внедрить автоматический transparent retry и renegotiation ключей при рассинхронизации эпох/сессий.<br/>2. Привязать криптографический AAD (Associated Authenticated Data) к метаданным пакета.<br/>3. Добавить эвристику распознавания Chaos Mode / замаскированных статус-кодов в DAST. |
| **5. Deception & Honeypot Tripwires** | `sandbox-kernel/src/canary.rs`: Rust inotify следит за `/root/.aws`, `/root/.ssh`, `/workspace/.env.decoy` и триггерит `panic_kill`. | Использует ложные маркеры и honeytokens для обнаружения вмешательства в ход аудита. | Архитектура ложных ответов, decoy endpoints и сокрытия структуры API. | 1. Расширить реестр канарских файлов динамическими ловушками (GCP credentials, Kubeconfig, Git config).<br/>2. Поддержать генерацию decoy-трафика с естественными паузами прямо во время фонового DAST сканирования. |
| **6. Output Truncation & Context Protection** | `sandbox-kernel/src/watchdog.rs`: лимит 30KB, сохранение дампа в `/workspace/logs/cmd_<id>.log`, выдача Head 15KB + Tail 10KB. | `sandbox_kernel/base.py`: лимит 30 000 символов, сохранение полных дампов, логирование в `session_log_path`. | Лимит размера запроса `MAX_REQUEST_SIZE` (10MB) с защитой от DoS/бомб памяти. | 1. Синхронизировать формат сообщений watchdog с Decepticon.<br/>2. Добавить стриминг больших дампов через скачивание по частям в MCP-инструментах. |

---

## 3. Детальный разбор компонентов референсов

### 3.1. Уроки из `PurpleAILAB/Decepticon`

#### А. Автономное обнаружение интерфейсов управления в `egress.py`
В Decepticon обнаружение подсетей управления происходит напрямую через разбор `/proc/net/route`:
```python
def _proc_route_onlink_cidrs(proc_route_path: str) -> set[str]:
    # Чтение hex-полей Destination, Gateway, Mask без внешних бинарников (ip/ifconfig)
    # Гарантирует, что loopback и bridge-сеть Docker никогда не будут заблокированы
```
**Вывод для нас:** В `sandbox-kernel/src/egress.rs` необходимо реализовать нативный Rust-парсер `/proc/net/route`, чтобы автоматически добавлять подключенную подсеть контейнера в список разрешенных قبل применения правил `drop`.

#### Б. Разделение адресных семейств IPv4 и IPv6 в `nftables`
Попытка поместить IPv6 адрес в набор типа `ipv4_addr` в таблице `inet` вызывает фатальную ошибку `nft load`:
```python
def _split_family(addrs: Iterable[str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    # Разделение адресов на v4 и v6 с генерацией отдельных правил ip daddr и ip6 daddr
```
**Вывод для нас:** В Rust-генераторе `compile_nftables_rules` необходимо типизировать наборы `allowed_hosts_v4` и `allowed_hosts_v6`.

#### В. Многосигнальный WAF-детектор и база `waf_profiles.yaml`
Decepticon не полагается на один признак, а ранжирует WAF-системы по совокупности сигналов:
* **Cookies**: `_abck`, `bm_sz`, `cf_clearance`, `__cf_bm`, `aws-waf-token`, `BigIPServer`, `datadome`, `_px3`;
* **Headers**: `X-Akamai-*`, `cf-ray`, `cf-cache-status`, `x-amzn-waf-*`;
* **Server**: `AkamaiGHost`, `cloudflare`;
* **Body strings**: `sec-if-cpt-container`, `Just a moment...`, `cf-chl-bypass`, `The requested URL was rejected`, `px-captcha`.

**Вывод для нас:** Встроить полнофункциональный модуль `WafDetector` в `sandbox_runtime/stealth` и Rust probe-роуты с поддержкой базы профилей WAF для автоматической адаптации стратегии обхода (выбор TLS-отпечатка JA3/JA4, стратегия Referer, Warmup-навигация).

#### Г. In-Browser SSRF Protection в `playwright_real_chrome.js`
Перехват запросов `page.route('**/*')` с валидацией IP-адресов через `dns.lookup` и блокировкой приватных диапазонов (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, IPv4-mapped IPv6 `64:ff9b::`).
**Вывод для нас:** Добавить аналогичный L7 перехватчик в `sandbox_runtime/stealth/browser_launcher.js`.

---

### 3.2. Уроки из `Lotargo/Aegis-Core`

#### А. Автоматическая ре-синхронизация ключей при `UNAUTHENTICATED`
В `core_a/main.py`:
```python
if e.code() == grpc.StatusCode.UNAUTHENTICATED:
    logger.info("Core A: Session expired. Renewing key...")
    if await perform_handshake():
        # Повторное шифрование и прозрачный ретрай запроса без ошибки для пользователя
```
**Вывод для нас:** Если Rust Sandbox Daemon возвращает `401 Unauthorized` из-за рассинхронизации скользящего окна или дрейфа времени, `SandboxBridge` в TypeScript должен выполнить автоматический handshake/re-sign и повторить запрос один раз без падения MCP-инструмента.

#### Б. Привязка метаданных (Authenticated Associated Data - AAD)
В `crypto.py`:
```python
associated_data = json.dumps(dict(metadata), sort_keys=True).encode()
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
```
**Вывод для нас:** В `src/mcp/security/ratchet_bridge.ts` и `sandbox-daemon/src/auth.rs` при шифровании ChaCha20-Poly1305 использовать канонический JSON с заголовками (`epoch`, `nonce`, `path`) в качестве AAD для гарантии криптографической неизменяемости заголовков пакета.

#### В. Учет Active Deception (Chaos Mode) в логике DAST-аудита
В Aegis Core сервер случайным образом маскирует успешный ответ под `404/503/500/403` со статусом `DECEPTION_RATIO`.
**Вывод для нас:** В скилле `web-appsec-dast` и инструменте `sandbox_http_probe` реализовать эвристику «расхождения статуса и контента» (Content-Length, Title, JSON Error Schema), чтобы агент не пропускал уязвимости на серверах с активной MTD-защитой.

---

## 4. Комплексный план доработок Stage 7 (Actionable Backlog)

### Блок 1: Доработка Rust Sandbox Kernel & Daemon

#### 1.1. Интеллектуальный Egress Resolver (`sandbox_runtime/crates/sandbox-kernel/src/egress.rs`)
* [ ] Реализовать парсер `/proc/net/route` для чтения on-link подсетей в little-endian hex формате.
* [ ] Реализовать авто-парсинг `/etc/resolv.conf` для извлечения IP DNS-резолверов.
* [ ] Разделить правила и наборы `nftables` на `ipv4_addr` и `ipv6_addr` (`allowed_hosts_v4`, `allowed_hosts_v6`).
* [ ] Добавить приоритетный `accept` для обнаруженных интерфейсов управления перед правилами `drop`.

#### 1.2. Отказоустойчивый менеджер Tmux (`sandbox_runtime/crates/sandbox-kernel/src/tmux.rs`)
* [ ] Добавить функцию `reap_orphaned_tmux_sessions()`, сканирующую `/tmp/tmux-*` и удаляющую брошенные сокеты при старте.
* [ ] Реализовать инкрементальное чтение логов `read_session_log_diff(session, offset)` с отслеживанием байтового смещения в `/workspace/logs/tmux_<session>.log`.
* [ ] Реализовать метод `reset_session_log_offset()`.

#### 1.3. Расширенный Deception & Canary Engine (`sandbox_runtime/crates/sandbox-kernel/src/canary.rs`)
* [ ] Добавить генерацию расширенного пула приманок:
  * `/root/.aws/credentials`
  * `/root/.ssh/id_rsa`
  * `/root/.kube/config`
  * `/root/.gcp/credentials.json`
  * `/workspace/.env.decoy`
  * `/workspace/config/database.decoy.yml`
* [ ] Встроить метрики триггеров канареек в общий статус демона (`/healthz`).

---

### Блок 2: WAF Multi-Signal Detection & Stealth Browser Engine

#### 2.1. База WAF-профилей и детектор (`sandbox_runtime/stealth/waf_detector.js` + `waf_profiles.json`)
* [ ] Портировать базу сигнатур WAF (Akamai, Cloudflare Turnstile, AWS WAF, F5 Big-IP, DataDome, PerimeterX, Imperva) в JSON-манифест.
* [ ] Реализовать класс `WafDetector` с ранжированием вероятностей на основе куки, заголовков, заголовка `Server` и тела ответа.
* [ ] Передавать вердикт WAF в результат инструмента `sandbox_http_probe` и `sandbox_browser_audit`.

#### 2.2. Усиление Stealth Browser (`sandbox_runtime/stealth/browser_launcher.js`)
* [ ] Добавить `launchPersistentContext` с изоляцией временного профиля пользователя.
* [ ] Внедрить фазу **Warmup Hop** (авто-посещение корневого домена для прохождения первичного сенсорного JS-скрипта до перехода к целевому URL).
* [ ] Реализовать In-Browser L7 SSRF Guard (`page.route('**/*')`) с проверкой DNS и блокировкой локальных/приватных адресов.
* [ ] Добавить эмуляцию человеческого набора текста и задержек для полей ввода (Human Typing Engine).
* [ ] Формировать структурированный JSON-конверт с куки, User-Agent и заголовками для передачи в fast tier.

---

### Блок 3: Криптография Host-Bridge, AAD и Rolling Retry

#### 3.1. Привязка AAD и прозрачный Retry (`src/mcp/security/ratchet_bridge.ts` и `src/mcp/bridge.ts`)
* [ ] Включить канонические метаданные запроса (`method`, `path`, `epoch`, `nonce`) в состав AAD при вычислении ChaCha20-Poly1305 / AES-GCM MAC.
* [ ] Реализовать в `SandboxBridge.request()` автоматический перехват `401 / 403` с перегенерацией ключа/эпохи и одиночным повтором запроса.
* [ ] Добавить валидацию и маскирование секретов (`SecretRedactor`) на исходящих и входящих потоках.

#### 3.2. Поддержка Deception / Chaos Mode в DAST (`src/mcp/tools/probe.ts` и `src/mcp/tools/browser.ts`)
* [ ] Добавить в результаты пробы флаг `potential_deception_detected: boolean`, если код ответа `404/503`, но тело содержит валидный HTML/JSON с бизнес-логикой.
* [ ] Включить в вывод рекомендации по обходу MTD для ИИ-агента.

---

### Блок 4: Синхронизация Skills и SARIF генератора

#### 4.1. Оркестратор и OPPLAN (`skills/security-audit-orchestrator/SKILL.md`)
* [ ] Обновить структуру `/workspace/plan/opplan.json` с явной фиксацией фаз: `RECON`, `SAST`, `DAST`, `ABUSE`, `DECEPTION_CHECK`, `REPORTING`.
* [ ] Включить в чеклисты вызов WAF-детектора и управление ротацией Tor IP.

#### 4.2. SARIF v2.1.0 Enhancements (`src/sarif/builder.ts`)
* [ ] Добавить поле `fixes` и `remediationMarkdown` в генерируемые правила SARIF.
* [ ] Добавить секцию `graph` для визуализации траектории атаки (Attack Path) в отчете.
* [ ] Добавить экспорт метаданных WAF и используемых канареек в `run.invocations`.

---

## 5. План валидации и верификации Stage 7

| Тест / Проверка | Описание сценария | Ожидаемый результат |
| :--- | :--- | :--- |
| **Тест 7.1 (Dynamic Egress Onlink Discovery)** | Запуск `compile_nftables_rules` с симуляцией маршрутов `/proc/net/route`. | Подсеть управления и DNS автоматически попадают в правила `accept` перед `drop`. |
| **Тест 7.2 (WAF Detection Multi-Signal)** | Передача ответов с куки `_abck` и заголовком `cf-ray`. | `WafDetector` возвращает правильный `profile_id` и `confidence >= 0.9`. |
| **Тест 7.3 (In-Browser SSRF Protection)** | Попытка загрузить `http://169.254.169.254/latest/meta-data` из `browser_launcher.js`. | Запрос мгновенно блокируется на уровне `page.route` со статусом `blockedbyclient`. |
| **Тест 7.4 (Ratchet AAD & Auto-Retry)** | Симуляция устаревшей эпохи (дрейф > 30 сек) с последующим ретраем моста. | Мост обновляет сессионный контекст и успешно доставляет запрос без падения. |
| **Тест 7.5 (Tmux Delta Log Polling)** | Запуск фонового процесса с генерацией 100 строк и вызовом `read_session_log_diff`. | Чтение возвращает только новые строки с обновлением смещения. |
| **Тест 7.6 (End-to-End Regression Test Suite)** | Запуск `npm test` и `cargo test`. | 100% тестов проходят успешно (все модули TS и Rust зелёные). |

---

## 6. Контрольный чеклист приемки Stage 7

- [ ] 1. Обновлен `sandbox-kernel/src/egress.rs` с динамическим дискавери `/proc/net/route` и разделением v4/v6.
- [ ] 2. Реализована зачистка сокетов и чтение diff логов в `sandbox-kernel/src/tmux.rs`.
- [ ] 3. Реализован модуль WAF детектирования (`waf_detector.js` + `waf_profiles.json`) в `sandbox_runtime/stealth/`.
- [ ] 4. Внедрены Warmup Hop и In-Browser SSRF Guard в `browser_launcher.js`.
- [ ] 5. Реализована привязка AAD и автоматический повтор при рассинхронизации в `ratchet_bridge.ts` и `bridge.ts`.
- [ ] 6. Обновлен `src/sarif/builder.ts` с поддержкой remediation fixes и attack graphs.
- [ ] 7. Все тесты Jest и Cargo актуализированы и успешно пройдены.
