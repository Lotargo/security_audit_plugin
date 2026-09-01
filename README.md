# Security Audit Plugin

Комплексный плагин аудита информационной безопасности и изолированная среда исполнения для ИИ-агентов (Google Antigravity / AGY, OpenCode, Claude Code, OpenAI Codex, Cursor).

## Обзор

Проект предоставляет изолированную Docker-песочницу, защищенный канал управления, стелс-браузер, анонимную маршрутизацию и библиотеку из 19 экспертных скиллов для проведения статического (SAST) и динамического (DAST) аудита безопасности.

Стек технологий:
- Хост: TypeScript / Node.js (MCP Server, CLI, SARIF v2.1.0, Ratchet Bridge).
- Песочница: Rust (Axum/Tokio демон, zeroize память, nftables файрвол, panic сброс сети, rquest TLS имперсонация) + Node.js (Playwright стелс-браузер с кривыми Безье ghost-cursor).
- Сеть и анонимность: Tor сервис (SOCKS5 :9050, ControlPort :9051) и поддержка upstream-прокси (Burp Suite, Caido, OWASP ZAP, SOCKS5).

---

## Ключевые возможности

1. Ratchet Bridge и двусторонний BYOK:
   - Асимметричная подпись команд хоста (Ed25519) с изоляцией приватного ключа на хосте.
   - Скользящий рэтчет: ротация сессионных ключей (ChaCha20-Poly1305) каждые 15-30 секунд.
   - Физическое затирание ключей в памяти (zeroize) в Rust ядре.
   - Невозможность выполнения обратной атаки из песочницы на локальную машину разработчика.

2. Изоляция и сетевой контроль:
   - Сетевой файрвол nftables (RoE guardrail) с запретом доступа к приватным подсетям (192.168.x.x, 10.x.x.x, 172.16.x.x).
   - Аварийный выключатель сети (Emergency Kill Switch): мгновенный сброс соединений (conntrack -F) и изоляция контейнера.
   - Чистый перезапуск (Clean Re-spawn): пересоздание контейнера из иммутабельного образа за доли секунды.

3. Активная детекция и Deception:
   - Расстановка канарских приманок (.aws, .ssh, .env) внутри песочницы с мониторингом через Linux inotify в Rust.
   - Генератор реалистичного фонового шума (Decoy Traffic) для маскировки аудита от систем WAF/SIEM.
   - Эвристики для распознавания режима хаоса (Chaos Mode) и сокрытия статусов ответов (философия Aegis-Core).

4. Стелс-браузер и обход WAF:
   - Пропатченный Playwright со стелс-плагинами и эмуляцией отпечатков.
   - Генератор движения мыши по кубическим кривым Безье (ghost-cursor) с учетом закона Фиттса и джиттера для обхода Cloudflare Turnstile и DataDome.
   - Имперсонация TLS отпечатков Chrome (JA3/JA4) через Rust rquest.
   - Инъекция заголовков L7 IP Spoofing (X-Forwarded-For, Client-IP) для проверки обхода ACL (CWE-290).

5. Tor и маршрутизация трафика:
   - Встроенный демон Tor для анонимизации запросов и предотвращения утечек DNS/WebRTC.
   - Инструмент динамической ротации цепочек узлов и IP адреса (SIGNAL NEWNYM).
   - Поддержка разведки скрытых сервисов .onion и Cloudflare Onion-Location (RFC 8738).

6. Стандартизация отчетов:
   - Генерация машиночитаемых отчетов в формате OASIS SARIF v2.1.0.
   - Формирование структурированных Markdown отчетов с оценками по шкале CVSS v3.1.

---

## Реестр скиллов (19 экспертных модулей)

| # | Скилл | Назначение |
| :- | :--- | :--- |
| 0 | security-audit-orchestrator | Главный координатор аудита, ведение OPPLAN, выбор режима, управление песочницей, экспорт в SARIF. |
| 1 | tor-anonymity-onion-routing | Маршрутизация через Tor, предотвращение утечек DNS/WebRTC, ротация IP, аудит .onion сервисов. |
| 2 | backend-topology-cartography | Реверс-инжиниринг REST/GraphQL и бинарных RPC/gRPC (Proteus/Protobuf) API через бандлы и Source Maps. |
| 3 | web-appsec-dast | Динамический аудит веб-приложений (CSP, куки, DOM XSS, эвристики Chaos Mode, Decoy трафик). |
| 4 | abuse-prevention-resilience | Устойчивость к ботнетам, credential stuffing, обход капчи, rate limiting и L7 IP спуфинг (CWE-290). |
| 5 | cryptography-token-security | Аудит JWT/JWS/JWE, энтропии, криптографических алгоритмов и ротации ключей. |
| 6 | injection-input-validation | Поиск и верификация SQLi, NoSQLi, Command Injection, SSTI, XSS. |
| 7 | access-control-business-logic | Анализ BOLA/IDOR, повышения привилегий и логических дефектов авторизации. |
| 8 | client-supply-chain-magecart | Аудит сторонних скриптов, GTM/TMS, Subresource Integrity (SRI), защита от Magecart, PCI DSS v4.0. |
| 9 | cloud-kubernetes-infra-audit | Анализ K8s манифестов, RBAC, сетевых политик и Cloud IAM конфигураций. |
| 10 | data-exposure-privacy-resilience | Поиск утечек PII/PDN, чувствительных логов, незашифрованных секретов (GDPR/HIPAA). |
| 11 | purple-team-detection-engineering | Создание правил детекта (Sigma, YARA), аудит покрытия MITRE ATT&CK, канарские токены. |
| 12 | http-smuggling-cache-attacks | Поиск уязвимостей HTTP Request Smuggling, Web Cache Poisoning и Cache Deception. |
| 13 | iam-active-directory-audit | Аудит Active Directory, Kerberos, Hybrid IAM, OAuth2/OIDC делегирования. |
| 14 | mobile-appsec-analysis | Статический и динамический анализ Android/iOS приложений (APK/IPA, certificate pinning). |
| 15 | network-segmentation-perimeter | Анализ сегментации сетей, DMZ, межсетевых экранов, lateral movement. |
| 16 | osint-attack-surface-mapping | Разведка внешнего периметра (EASM), поиск поддоменов, открытых портов, цифрового следа. |
| 17 | social-engineering-risk-assessment | Оценка риска фишинга, MFA fatigue и моделирование человеческого фактора. |
| 18 | cicd-supply-chain-security | Аудит CI/CD пайплайнов (GitHub Actions), проверка SBOM, зависимостей и SLSA. |

---

## Быстрый старт

### Требования
- Node.js 20+
- Docker (для запуска изолированной песочницы)

### Установка и запуск через CLI

1. Проверка системного окружения:
```bash
npx @security-audit/plugin doctor
```

2. Экспорт скиллов в целевую платформу (Google Antigravity, OpenCode, Claude Code):
```bash
# Для Google Antigravity (AGY):
npx @security-audit/plugin install-skills --target agy

# Для OpenCode:
npx @security-audit/plugin install-skills --target opencode
```

3. Запуск MCP сервера по протоколу STDIO:
```bash
npx @security-audit/plugin mcp
```

---

## Структура репозитория

- `skills/` - 19 стандартизированных скиллов (инструкции, примеры, справочники).
- `sandbox_runtime/` - исходный код Docker-песочницы (Rust ядро, демон, стелс-браузер, Tor).
- `src/` - TypeScript исходники MCP сервера, Ratchet моста, SARIF генератора и CLI.
- `plugins/` - манифесты интеграции для AGY (`plugins/agy/`) и OpenCode (`plugins/opencode/`).
- `plan/` - пошаговые планы реализации этапов (1-5).
- `IMPLEMENTATION_PLAN.md` - генеральный архитектурный план и карта проекта.
- `CHANGELOG.md` - журнал изменений проекта.

---

## Документация этапов реализации

Подробные спецификации каждого этапа зафиксированы в директории `plan/`:
- [Этап 1: Рефакторинг и стандартизация 19 Skills](./plan/STAGE_1_SKILLS_REFACTORING.md)
- [Этап 2: Docker Sandbox Runtime (Rust + Node.js Stealth + Tor)](./plan/STAGE_2_RUST_SANDBOX_RUNTIME.md)
- [Этап 3: TypeScript MCP Server, Ratchet Bridge & SARIF Builder](./plan/STAGE_3_HOST_MCP_BRIDGE.md)
- [Этап 4: NPM CLI, Packaging & Manifests](./plan/STAGE_4_NPM_CLI_AND_PACKAGING.md)
- [Этап 5: Сквозное тестирование и валидация безопасности](./plan/STAGE_5_TESTING_AND_VALIDATION.md)
