# Changelog

Все заметные изменения в проекте **`security-audit-plugin`** документируются в этом файле.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.0.0/), и проект придерживается [Семантического версионирования](https://semver.org/lang/ru/).

---

## [Unreleased]

---

## [0.5.0] - 2026-09-01

### Added & Enhanced
- **Rust Sandbox Kernel & Daemon Refinements**:
  - Реализован встроенный парсер `/proc/net/route` (`discover_onlink_cidrs_from_route`) для нативного извлечения подсетей on-link (Docker bridge / host network) в шестнадцатеричном формате little-endian без внешних утилит `ip`/`route`;
  - Добавлен парсер `/etc/resolv.conf` (`discover_resolvers_from_resolv_conf`) для динамического обнаружения DNS-серверов;
  - Реализовано строгое разделение семейств адресов IPv4 (`ipv4_addr`) и IPv6 (`ipv6_addr`) в наборах `nftables` для предотвращения сбоев компиляции правил;
  - В `tmux.rs` внедрен сборщик брошенных сокетов `reap_orphaned_tmux_sessions()` и сброс оффсетов `reset_session_log_offset()`;
  - Расширены канарские ловушки `canary.rs` (добавлены `.kube/config` и `.gcp/credentials.json`), а в `/health` эндпоинт демона добавлен мониторинг состояния триггеров.
- **WAF Multi-Signal Detection & Stealth Browser Hardening**:
  - Создана база сигнатур WAF в формате JSON (`sandbox_runtime/stealth/waf_profiles.json`) для Akamai Bot Manager, Cloudflare Turnstile, AWS WAF, F5 Big-IP, DataDome, PerimeterX, Imperva Incapsula;
  - Разработан движок мультисигнального скоринга `WafDetector` (`sandbox_runtime/stealth/waf_detector.js`) с поддержкой wildcard-паттернов заголовков/кук и рекомендациями по обходу;
  - Модернизирован `browser_launcher.js` с добавлением фазы **Warmup Hop** (предварительное посещение корня домена для инициализации сенсоров) и **In-Browser L7 SSRF Guard** (`page.route('**/*')`) с проверкой DNS и блокировкой приватных диапазонов;
  - Добавлены эвристики детекции активного обмана (MTD / Chaos Mode) в `sandbox-daemon/src/routes/probe.rs`.
- **Cryptographic Host-Bridge Hardening**:
  - В `RatchetBridge` внедрены функции шифрования/дешифрования с привязкой Authenticated Associated Data (`encryptPayloadWithAad` / `decryptPayloadWithAad`) на ChaCha20-Poly1305 / AES-256-GCM;
  - В `SandboxBridge.request` добавлен прозрачный механизм **Rolling Retry on 401/403** с автоматической синхронизацией эпохи при рассинхронизации таймстампов.
- **Skills Ecosystem & SARIF v2.1.0 Enhancements**:
  - В `SarifReportBuilder` и `AuditFindingInput` добавлена поддержка предлагаемых исправлений кода (`fixes`), структурированных руководств по устранению (`remediationMarkdown`) и визуализации цепочек атак (`attackGraph` в формате диаграмм Mermaid);
  - Обновлен центральный оркестратор `skills/security-audit-orchestrator/SKILL.md` с синхронизацией 6-фазного оперативного плана (ROE, OSINT, SAST, DAST, Attack Graph Synthesis, SARIF Reporting).
- **Zero-Touch Docker Delivery & Bootstrapping**:
  - В `DockerRunner` внедрен автоматический механизм разрешения образов `ensureImageAvailable()`: автоматический pull из GitHub Container Registry (`ghcr.io/lotargo/security-audit-sandbox:latest`) с прозрачным fallback-биcycle `docker build` из встроенных исходников `sandbox_runtime/Dockerfile`;
  - Добавлен метод `findSandboxRuntimeDir()` для локализации исходников рантайма в установленном NPM-пакете;
  - В CLI добавлены команды `pull-sandbox` и `build-sandbox`, а также флаг `--docker` для предварительного прогрева и кэширования образа во время `install` и `init`.
- **Comprehensive Testing Suite**:
  - Добавлены тесты `tests/waf.test.ts`, расширены `tests/ratchet.test.ts`, `tests/sarif.test.ts` и `tests/cli.test.ts`: 42/42 TypeScript тестов и 12/12 Rust тестов успешно пройдены.

---

## [0.4.0] - 2026-09-01

### Added
- Разработан и внедрен расширенный набор тестов CLI (`tests/cli.test.ts`):
  - Проверка работы `doctor` (диагностика Docker, рантайма, доступности портов 9999, 9050, 9051 и структуры каталога скиллов);
  - Проверка работы `install-skills` (установка всех 19 скиллов в целевые директории и валидация манифестов `SKILL.md`).
- Разработан модульный тестовый слой для 12 MCP-инструментов (`tests/tools.test.ts`):
  - Регистрация и валидация схем для `sandbox_set_scope`, `sandbox_rotate_tor_ip`, `sandbox_exec`, `sandbox_start_background`, `sandbox_poll_logs`, `sandbox_kill_switch`, `sandbox_reset`, `sandbox_fs_read`, `sandbox_fs_write`;
  - Проверка прозрачной маршрутизации запросов через `SandboxBridge` и форматирования JSON-RPC ответов.
- Реализован сквозной интеграционный тест полного цикла аудита (`tests/e2e_workflow.test.ts`):
  - Сценарий задания гибридного скоупа с приманками;
  - Запуск фонового сканирования и чтение дельта-логов через `tmux`;
  - Генерация отчета OASIS SARIF v2.1.0 с CVSS v3.1 скорингом;
  - Автоматическое маскирование секретов и учетных данных в URI (`postgres://admin:se***@host`);
  - Валидация файловых операций в рабочей области через `JailGuard`;
  - Срабатывание канарской ловушки и сетевой blackout через `sandbox_kill_switch`.
- Реализован автономный package-relative резолв путей к каталогу `skills/` (`findSourceSkillsDir`) для бесшовной работы через `npx @security-audit/plugin` без необходимости клонирования репозитория.
- Добавлены универсальные CLI-команды `install` (с флагами выборочной установки `--skills` и генерацией конфигурации `--mcp`), `init` (мастер настройки) и `uninstall` (чистое выборочное или полное удаление скиллов и очистка каталогов).
- Созданы нативные манифесты совместимости для ведущих агентских экосистем:
  - Google Antigravity (`plugins/agy/plugin.json`, `plugins/agy/mcp_config.json`);
  - Claude Code (`.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`);
  - OpenCode (`.opencode/INSTALL.md`, `plugins/opencode/opencode.json`);
  - Gemini CLI (`gemini-extension.json`);
  - Cursor / Windsurf (`.cursor-plugin/plugin.json`).

---

## [0.3.0] - 2026-09-01

### Added
- Инициализирован хостовый проект TypeScript (`package.json`, `tsconfig.json`) со строгой типизацией и сборкой в ESM.
- Реализован криптографический мост `src/mcp/security/ratchet_bridge.ts`:
  - Генерация ключевой пары Ed25519 хоста;
  - Подпись каждого RPC-запроса (`X-Signature-Host`, `X-Ratchet-Epoch`, `X-Nonce`);
  - Скользящий рэтчет с микро-ротацией эпох (окно 30 сек);
  - Защита от Replay-атак и затирание временных буферов памяти.
- Реализованы модули хостовой безопасности:
  - `src/mcp/security/jail.ts`: строгий JailGuard для изоляции путей рабочей области и предотвращения Path Traversal и Symlink-атак;
  - `src/mcp/security/redaction.ts`: маскирование чувствительных секретов (JWT, Bearer, API-ключи AWS/OpenAI/GitHub, приватные ключи SSH/RSA, пароли и куки).
- Реализован движок отчетов OASIS SARIF v2.1.0 (`src/sarif/`):
  - Полная типизация спецификации SARIF v2.1.0 (`types.ts`);
  - Построитель отчетов `SarifReportBuilder` (`builder.ts`) с авто-регистрацией правил, скорингом CVSS v3.1, таксономиями CWE/OWASP/MITRE и генератором Markdown сводок.
- Реализован контроллер жизненного цикла Docker-песочницы `src/docker/runner.ts` (запуск с монтированием `/workspace`, лимитами памяти/pids, health check и Hard Reset).
- Реализован клиент связи `src/mcp/bridge.ts` для вызова всех HTTP-эндпоинтов Rust демона с автоматической криптографической подписью.
- Зарегистрированы и реализованы все 12 MCP-инструментов песочницы (`src/mcp/tools/`):
  - `sandbox_set_scope`, `sandbox_rotate_tor_ip`, `sandbox_exec`, `sandbox_interactive_input`, `sandbox_start_background`, `sandbox_poll_logs`, `sandbox_browser_audit`, `sandbox_bundle_extract`, `sandbox_http_probe`, `sandbox_kill_switch`, `sandbox_reset`, `sandbox_fs_read`, `sandbox_fs_write`.
- Реализован MCP STDIO сервер `src/mcp/server.ts` на базе `@modelcontextprotocol/sdk`.
- Реализован полнофункциональный CLI интерфейс (`bin/cli.js`, `src/cli/`):
  - `security-audit mcp`: запуск STDIO MCP сервера;
  - `security-audit doctor`: диагностика Docker, портов, образов и окружения;
  - `security-audit install-skills`: экспорт 19 скиллов в агентские среды (`agy`, `opencode`, `claude`, `custom`);
  - `security-audit start-sandbox`, `stop-sandbox`, `reset-sandbox`: управление контейнером.
- Сгенерированы нативные манифесты плагина:
  - Google Antigravity (`plugins/agy/plugin.json`, `plugins/agy/mcp_config.json`);
  - OpenCode (`plugins/opencode/opencode.json`).
- Разработан набор модульных тестов Vitest (`tests/jail.test.ts`, `tests/redaction.test.ts`, `tests/sarif.test.ts`, `tests/ratchet.test.ts`): 19/19 тестов успешно пройдены.

### Changed
- Синхронизирован алгоритм хеширования SHA-256 между Rust `sandbox-daemon` (`sha2::Sha256`) и Node.js `RatchetBridge` (`crypto.createHash('sha256')`).

---

## [0.2.0] - 2026-09-01

### Added
- Создан Rust Workspace в `sandbox_runtime/Cargo.toml` с крейтами `sandbox-kernel` и `sandbox-daemon`.
- Реализована библиотека ядра безопасности `sandbox-kernel`:
  - `egress.rs`: генератор и правоприменитель правил `nftables` RoE с изоляцией приватных CIDR, поддержкой Tor и белых списков целей;
  - `panic.rs`: аппаратный аварийный Kill Switch (`conntrack -F` + drop all);
  - `canary.rs`: система активной децепции (расстановка канарских honeytoken-файлов `.aws/credentials`, `.ssh/id_rsa`, `.env.decoy` и фоновый watcher доступа с триггером сетевого blackout);
  - `tmux.rs`: менеджер фоновых шелл-сессий `tmux` с буфером истории 20K строк и чтением дельта-логов;
  - `watchdog.rs`: смарт-лимитер вывода на 30K символов с сохранением полных дампов в `/workspace/logs/cmd_<id>.log`.
- Реализован легковесный HTTP демон `sandbox-daemon` на базе `Axum` / `Tokio` (порт 9999):
  - Middleware `RatchetGuard` с верификацией Ed25519 подписей хоста, контролем эпохи $K(t)$ (окно 30 сек), защитой от Replay-атак по кэшу nonces и затиранием RAM памяти через `zeroize`;
  - Маршруты: `/execute`, `/execute_tmux`, `/provision_egress`, `/emergency_isolate`, `/isolation_status`, `/start_background`, `/poll_logs`, `/kill_background`, `/rotate_tor`, `/arm_canary`, `/canary_status`, `/http_probe`.
- Реализован модуль Node.js Stealth Browser (`sandbox_runtime/stealth`):
  - `mouse_bezier.js`: эмуляция движений мыши по кубическим кривым Безье (`ghost-cursor`) с джиттером и человекоподобным набором текста (human typing);
  - `browser_launcher.js`: стелс-раннер Chromium (`playwright-extra` + `puppeteer-extra-plugin-stealth`), блокировка WebRTC (защита от Tor IP leaks), сбор HAR, CSP/HSTS и детект Turnstile;
  - `decoy_traffic.js`: генератор фонового синтетического шума для размытия следа аудита в WAF/SIEM.
- Настроена конфигурация Tor (`torrc`) с SOCKS5 (9050) и ControlPort (9051).
- Созданы `sandbox_runtime/entrypoint.sh` и multi-stage `sandbox_runtime/Dockerfile` (сборщик на `rust:1.85-slim` + рантайм на `kalilinux/kali-rolling`).
- Разработаны и успешно пройдены 9/9 автоматических юнит-тестов Rust ядра и демона.

---

## [0.1.0] - 2026-09-01

### Added
- Создана стандартизированная структура AgentSkills для всех 19 экспертных скиллов (`SKILL.md` + `references/` + `examples/` + `scripts/`).
- Реализован мастер-скилл координатор `skills/security-audit-orchestrator` с поддержкой операционного плана (OPPLAN), скоупинга и экспортного формата OASIS SARIF v2.1.0.
- Реализован скилл анонимности и темного веба `skills/tor-anonymity-onion-routing` (Tor OPSEC, ротация IP адресов на лету по `SIGNAL NEWNYM`, проверка утечек DNS/WebRTC, аудит .onion v3 и RFC 8738 Onion-Location).
- Добавлены справочники, чеклисты и практические скрипты для каждого из 19 направлений аудита.
- Внедрена защита от Indirect Prompt Injection: все невалидированные внешние данные и дампы трафика изолируются в теги `<untrusted_payload>`.
- Сформированы правила игнорирования `.gitignore`, `.npmignore` и `.dockerignore`.
- Настроен слой CI/CD (`.github/workflows/ci.yml`, `.github/workflows/security.yml`) с автоматической валидацией скиллов, проверками Rust/TypeScript/Docker и сканированием секретов (Gitleaks).

### Changed
- Отрефакторены и приведены к стандартам Progressive Disclosure 17 существующих скиллов с выделением тяжелых спецификаций в директории `references/`.

### Removed
- Удалены 17 устаревших неструктурированных плоских файлов `skills/*.md`.
