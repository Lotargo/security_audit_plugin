# Changelog

Все заметные изменения в проекте **`security-audit-plugin`** документируются в этом файле.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.0.0/), и проект придерживается [Семантического версионирования](https://semver.org/lang/ru/).

---

## [Unreleased]

---

## [0.3.0] - 2026-09-01 (Stage 3 & 4: TypeScript Host MCP Server, Ratchet Bridge, SARIF Builder, CLI & Manifests)

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
- Разработан набор модульных тестов Vitest (`tests/jail.test.ts`, `tests/redaction.test.ts`, `tests/sarif.test.ts`, `tests/ratchet.test.ts`) — 19/19 тестов успешно пройдены.

### Changed
- Синхронизирован алгоритм хеширования SHA-256 между Rust `sandbox-daemon` (`sha2::Sha256`) и Node.js `RatchetBridge` (`crypto.createHash('sha256')`).

---

## [0.2.0] - 2026-09-01 (Stage 2: Docker Sandbox Runtime — Rust Kernel, Node.js Stealth Browser, Tor & Deception)

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

## [0.1.0] - 2026-09-01 (Stage 1: Skills Ecosystem Refactoring & Standardization)

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


<!-- 
================================================================================
ОБРАЗЕЦ / ШАБЛОН ДЛЯ ЗАПОЛНЕНИЯ (УДАЛИТЬ ПОСЛЕ ПЕРВОЙ РЕАЛЬНОЙ ЗАПИСИ РЕЛИЗА)
================================================================================

## [1.0.0] - 2026-09-01

### Added (Добавлено)
- Новые функции, скиллы, MCP-инструменты или модули ядра.
- Пример: Добавлен MCP-инструмент `sandbox_rotate_tor_ip` для динамической ротации цепочек Tor.

### Changed (Изменено)
- Изменения в существующей функциональности, контрактах API или схемах скиллов.
- Пример: Стек песочницы переведен с Python на Rust (Axum/Tokio) для изоляции памяти.

### Deprecated (Устарело)
- Функции, которые скоро будут удалены в следующих версиях.

### Removed (Удалено)
- Удаленные модули или устаревшие файлы.
- Пример: Удалены неструктурированные markdown-файлы скиллов из корня папки `skills/`.

### Fixed (Исправлено)
- Любые исправления багов, уязвимостей или ошибок компиляции.
- Пример: Устранена уязвимость Replay-атак в RatchetGuard путем проверки временных меток эпохи.

### Security (Безопасность)
- Улучшения в модели угроз, правилах файрвола или защите от эксплойтов.
- Пример: Внедрен крейт `zeroize` для затирания приватных ключей в оперативной памяти.

> [!NOTE]
> **Инструкция**: Удалите этот закомментированный блок и образец версии [1.0.0] после фиксации первой релизной версии этапа.
================================================================================
-->
