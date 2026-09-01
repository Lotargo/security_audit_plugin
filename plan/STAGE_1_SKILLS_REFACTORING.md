# Stage 1: Skills Ecosystem Refactoring & Standardization

## 1. Цели и назначение этапа

Цель первого этапа — преобразовать 17 существующих файлов из папки `skills/` и создать 2 новых мастер-скилла (`security-audit-orchestrator` и `tor-anonymity-onion-routing`), приведя все 19 скиллов к строгим современным стандартам **AgentSkills / Google Antigravity (AGY) / OpenCode / OpenAI Codex**.

---

## 2. Архитектурные требования к каждому скиллу

Каждый скилл должен быть оформлен в виде отдельной директории со структурой:
```text
skills/<skill-name>/
├── SKILL.md              # Основной документ скилла (YAML frontmatter, алгоритм, вызовы MCP)
├── examples/             # Примеры PoC, отчетов, найденных дефектов и артефактов
├── references/           # Вынесенные спецификации (OWASP, CWE, PCI DSS, матрицы заголовков)
└── scripts/              # Вспомогательные скрипты/пробы (для выполнения внутри песочницы)
```

### Требования к `SKILL.md`:
1. **YAML Frontmatter (Progressive Disclosure)**:
   ```yaml
   ---
   name: <skill-name>
   description: "Use when <четкие условия в 3-м лице>. Triggers: <ключевые слова>. Do NOT use when <исключения>."
   version: 1.0.0
   ---
   ```
2. **Оптимизация токенов**:
   - Основной текст `SKILL.md` содержит алгоритм принятия решений, фазы работы и критерии верификации.
   - Массивные таблицы (CWE, матрицы заголовков, RFC) выносятся в `[references/...](./references/...)`.
3. **Прямая интеграция с MCP-инструментами песочницы**:
   - Явное описание использования: `sandbox_set_scope`, `sandbox_rotate_tor_ip`, `sandbox_exec`, `sandbox_start_background`, `sandbox_poll_logs`, `sandbox_browser_audit`, `sandbox_bundle_extract`, `sandbox_http_probe`, `sandbox_kill_switch`, `sandbox_reset`.
4. **Защита от Indirect Prompt Injection**:
   - Все внешние данные (HTML, заголовки, дампы ответов) оборачиваются в теги `<untrusted_payload>` с явным запретом исполнения команд внутри них.

---

## 3. Реестр и спецификация 19 скиллов

### Скилл 0: `security-audit-orchestrator` (Новый Мастер-координатор)
* **Назначение:** Главный диспетчер аудита.
* **Ключевые функции:**
  - Определение режима (`local_codebase`, `remote_url`, `hybrid`);
  - Ведение операционного плана **OPPLAN** (`/workspace/plan/opplan.json`);
  - Инициализация скоупа в `sandbox_set_scope` (включая выбор `proxy: "tor"` или Burp/Caido);
  - Взведение канарских ловушек (`arm_canaries: true`);
  - Маршрутизация задач в специализированные скиллы (1–18);
  - Мониторинг фоновых задач (`sandbox_poll_logs`);
  - Экстренный сброс (`sandbox_reset`);
  - Формирование отчетов: **SARIF v2.1.0** (`audit-report.sarif`) и Markdown (`audit-report.md`).

### Скилл 1: `tor-anonymity-onion-routing` (Новый Скилл анонимности и Tor)
* **Назначение:** Маршрутизация через сеть Tor, предотвращение утечек DNS/WebRTC, ротация IP при WAF-блокировках, аудит `.onion` сервисов.
* **Ключевые функции:**
  - Проверка утечек DNS (принудительное использование `socks5h://`);
  - Проверка отключения WebRTC в Chromium;
  - Протокол ротации: вызов `sandbox_rotate_tor_ip` при получении 403 / 429 от целевого сервера;
  - Аудит скрытых служб Tor v3 Onion Services и Cloudflare `Onion-Location` (RFC 8738).

### Скилл 2: `backend-topology-cartography` (из `Backend Topology.md`)
* **Назначение:** Реверс-инжиниринг API бэкенда через клиентские бандлы, Source Maps, CDP и AST-анализ.
* **Адаптация:** Поиск REST/GraphQL, а также бинарных RPC/gRPC/Protobuf протоколов (философия Aegis-Core).

### Скилл 3: `web-appsec-dast` (из `Web AppSec & DAST.md`)
* **Назначение:** Динамический анализ веб-приложений через стелс-браузер (`sandbox_browser_audit`), проверка CSP/HSTS, куки, DOM XSS, распознавание MTD/Chaos Mode (Aegis-Core).

### Скилл 4: `abuse-prevention-resilience` (из `abuse-prevention-resilience-auditor.md`)
* **Назначение:** Устойчивость к ботнетам, credential stuffing, обход капчи, rate limiting и спуфинг IP-заголовков (CWE-290).

### Скилл 5: `cryptography-token-security` (из `applied-cryptography-token-auditor.md`)
* **Назначение:** Аудит JWT/JWS/JWE, энтропии, симметричного/асимметричного шифрования, ротации ключей.

### Скилл 6: `injection-input-validation` (из `appsec-injection-input-validation.md`)
* **Назначение:** Поиск и безопасная верификация SQLi, NoSQLi, Command Injection, SSTI, XSS.

### Скилл 7: `access-control-business-logic` (из `broken-access-control-business-logic.md`)
* **Назначение:** Анализ BOLA/IDOR, повышения привилегий и дефектов бизнес-логики.

### Скилл 8: `client-supply-chain-magecart` (из `client-side-supply-chain-magecart-auditor.md`)
* **Назначение:** Аудит сторонних скриптов, GTM/TMS, Subresource Integrity (SRI), защита от Magecart и PCI DSS v4.0.

### Скилл 9: `cloud-kubernetes-infra-audit` (из `cloud-native-kubernetes-infrastructure-auditor.md`)
* **Назначение:** Анализ манифестов K8s, RBAC, сетевых политик и Cloud IAM.

### Скилл 10: `data-exposure-privacy-resilience` (из `data-exposure-privacy-resilience-analyst.md`)
* **Назначение:** Поиск утечек PII/PDN, чувствительных логов, незашифрованных секретов (GDPR/HIPAA).

### Скилл 11: `purple-team-detection-engineering` (из `detection-purple-team-engineer.md`)
* **Назначение:** Создание правил детекта (Sigma, YARA), аудит покрытия MITRE ATT&CK, внедрение канарских токенов и проверка телеметрии SIEM.

### Скилл 12: `http-smuggling-cache-attacks` (из `http-smuggling-web-cache-auditor.md`)
* **Назначение:** Поиск уязвимостей HTTP Request Smuggling, Web Cache Poisoning и Cache Deception.

### Скилл 13: `iam-active-directory-audit` (из `iam-active-directory-auditor.md`)
* **Назначение:** Аудит Active Directory, Kerberos, Hybrid IAM, OAuth2/OIDC делегирования.

### Скилл 14: `mobile-appsec-analysis` (из `mobile-appsec-auditor.md`)
* **Назначение:** Статический и динамический анализ Android/iOS приложений (APK/IPA, certificate pinning).

### Скилл 15: `network-segmentation-perimeter` (из `network-segmentation-auditor.md`)
* **Назначение:** Анализ сегментации сетей, DMZ, межсетевых экранов, lateral movement.

### Скилл 16: `osint-attack-surface-mapping` (из `osint-attack-surface.md`)
* **Назначение:** Разведка внешнего периметра (EASM), поиск поддоменов, открытых портов, утечек и цифрового следа.

### Скилл 17: `social-engineering-risk-assessment` (из `social-engineering-risk.md`)
* **Назначение:** Оценка риска фишинга, MFA fatigue и моделирование человеческого фактора.

### Скилл 18: `cicd-supply-chain-security` (из `supply-chain-cicd-auditor.md`)
* **Назначение:** Аудит CI/CD пайплайнов (GitHub Actions), проверка SBOM, зависимостей и SLSA.

---

## 4. Порядок выполнения и контрольные точки

1. [ ] Создать структуру директорий `skills/<skill_name>/` для всех 19 скиллов.
2. [ ] Написать мастер-скилл `skills/security-audit-orchestrator/SKILL.md` (OPPLAN, SARIF, триаж скоупа).
3. [ ] Написать скилл `skills/tor-anonymity-onion-routing/SKILL.md` (Tor OPSEC, ротация, Onion v3).
4. [ ] Поочередно отрефакторить 17 существующих файлов:
   - Выделить YAML frontmatter;
   - Вынести таблицы в `references/`;
   - Добавить примеры в `examples/`;
   - Внедрить вызовы Sandbox MCP и обертку `<untrusted_payload>`.
5. [ ] Удалить устаревшие файлы верхнего уровня в `skills/*.md`.
6. [ ] Валидация: проверить синтаксис и корректность markdown-ссылок во всех 19 директориях.
