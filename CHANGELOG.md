# Changelog

Все заметные изменения в проекте **`security-audit-plugin`** документируются в этом файле.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.0.0/), и проект придерживается [Семантического версионирования](https://semver.org/lang/ru/).

---

## [Unreleased]

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
