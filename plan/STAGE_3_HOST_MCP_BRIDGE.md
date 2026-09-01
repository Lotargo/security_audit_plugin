# Stage 3: TypeScript MCP Server, Ratchet Bridge & SARIF Builder

## 1. Цели и назначение этапа

Цель третьего этапа — реализовать хостовый уровень на **TypeScript / Node.js**, обеспечивающий:
1. **Node.js MCP Server** на базе `@modelcontextprotocol/sdk` (STDIO транспорт);
2. **Ratchet Bridge**: клиент криптографического рэтчета (Ed25519 подпись, микро-ротация сессионных ключей каждые 15–30 секунд, морфинг конвертов);
3. **Модули безопасности хоста**:
   - `jail.ts`: строгая изоляция путей (защита от Path Traversal и вредоносных симлинков);
   - `redaction.ts`: автоматическое маскирование секретов и учетных данных в логах и отчетах;
4. **SARIF Builder**: генератор и валидатор отчетов по спецификации **OASIS SARIF v2.1.0**;
5. **DockerRunner & SandboxBridge**: управление жизненным циклом контейнера (запуск, мониторинг здоровья, экстренный перезапуск `reset-sandbox`) и вызов RPC-эндпоинтов песочницы;
6. **Реализацию всех 12 MCP-инструментов**.

---

## 2. Структура директории `src/`

```text
src/
├── index.ts                       # Экспорт программного API
├── mcp/
│   ├── server.ts                  # Точка входа MCP STDIO сервера
│   ├── bridge.ts                  # Клиент связи с sandbox-daemon
│   ├── security/
│   │   ├── ratchet_bridge.ts      # Ed25519 генератор, микро-ротация 15-30s, морфинг конвертов
│   │   ├── jail.ts                # Защита от Path Traversal
│   │   └── redaction.ts           # Маскирование секретов (Bearer, куки, токены)
│   └── tools/                     # Реализация 12 MCP-инструментов
│       ├── index.ts               # Регистрация схем и хэндлеров
│       ├── scope.ts               # sandbox_set_scope
│       ├── tor.ts                 # sandbox_rotate_tor_ip
│       ├── exec.ts                # sandbox_exec, sandbox_interactive_input
│       ├── background.ts          # sandbox_start_background, sandbox_poll_logs
│       ├── browser.ts             # sandbox_browser_audit
│       ├── bundle.ts              # sandbox_bundle_extract
│       ├── probe.ts               # sandbox_http_probe (с L7 spoofing)
│       ├── panic.ts               # sandbox_kill_switch, sandbox_reset
│       └── fs.ts                  # sandbox_fs_read, sandbox_fs_write
├── sarif/
│   ├── builder.ts                 # Построитель SARIF v2.1.0
│   └── types.ts                   # Типы находок (SARIF schema)
└── docker/
    ├── runner.ts                  # Запуск / остановка / сброс Docker-контейнера
    └── docker-compose.yml
```

---

## 3. Детальная спецификация модулей

### 1. `src/mcp/security/ratchet_bridge.ts` (Host Ratchet Client)
* **Задачи:**
  - Генерация ключевой пары хоста (Ed25519) при старте сессии;
  - Передача открытого ключа `Host_Pub` в песочницу при инициализации;
  - Приватный ключ `Host_Priv` хранится строго в памяти процесса Node.js на хосте;
  - Скользящий рэтчет: перегенерация симметричного ключа $K(t)$ (ChaCha20-Poly1305) каждые 15–30 секунд;
  - Подпись каждого исходящего HTTP-запроса к песочнице: `X-Signature-Host`, `X-Ratchet-Epoch`.

### 2. `src/mcp/security/jail.ts` & `redaction.ts`
* **`jail.ts`**: Проверка любых путей через `path.resolve` и `path.relative`. Запрет любых обращений за пределы рабочей директории проекта.
* **`redaction.ts`**: Регулярные выражения для поиска JWT, паролей, API-ключей, Authorization заголовков и автоматическая замена их на маски (например, `eyJh***123`).

### 3. `src/sarif/builder.ts` (SARIF v2.1.0 Engine)
* **Задачи:**
  - Формирование валидного JSON-документа по схеме `sarif-schema-2.1.0.json`;
  - Сопоставление находок с правилами (CWE, OWASP Top 10, MITRE ATT&CK);
  - Формирование локаций (файлы, строки кода, URL эндпоинтов);
  - Расчет CVSS v3.1 базовых и temporal оценок;
  - Экспорт в `/workspace/reports/audit-report.sarif`.

### 4. `src/docker/runner.ts` (Контроллер контейнера)
* **Задачи:**
  - Проверка доступности Docker демона на машине разработчика;
  - Подъем контейнера `security-audit-sandbox` с сетевой изоляцией;
  - `hard_reset`: мгновенное удаление скомпрометированного контейнера и подъем чистого инстанса за доли секунды.

---

## 4. Спецификация 12 MCP-инструментов

1. **`sandbox_set_scope`**: Режим (`local`, `remote`, `hybrid`), целевые хосты/IP, прокси (`tor`, Burp/Caido/SOCKS5), CA-сертификаты, канарские ловушки.
2. **`sandbox_rotate_tor_ip`**: Мгновенная ротация выходного узла Tor через `SIGNAL NEWNYM`.
3. **`sandbox_exec`**: Выполнение шелл-команд с таймаутом и 30KB watchdog.
4. **`sandbox_interactive_input`**: Отправка интерактивного ввода (`y/N`, пароли, Ctrl+C) в tmux.
5. **`sandbox_start_background`**: Запуск фоновых задач (Nmap, Nikto, фаззинг).
6. **`sandbox_poll_logs`**: Получение инкрементальных дельта-логов фоновой задачи.
7. **`sandbox_browser_audit`**: Запуск Playwright со стелс-плагинами, Безье-курсором, проксированием, Decoy-шумом и сбором HAR/DOM/Security Headers.
8. **`sandbox_bundle_extract`**: Скачивание JS-бандлов, извлечение Source Maps и построение карты REST/Protobuf эндпоинтов.
9. **`sandbox_http_probe`**: Точечные HTTP-пробы с кастомными заголовками (L7 IP Spoofing: `X-Forwarded-For`), телом и прокси.
10. **`sandbox_kill_switch`**: Аварийное глушение сети песочницы (`conntrack -F` + drop all).
11. **`sandbox_reset`**: Полное пересоздание чистого контейнера без потери отчетов.
12. **`sandbox_fs_read` / `sandbox_fs_write`**: Безопасная работа с файлами в `/workspace` с защитой от Path Traversal.

---

## 5. Порядок выполнения и контрольные точки

1. [ ] Инициализировать TypeScript проект (`package.json`, `tsconfig.json`).
2. [ ] Реализовать модули безопасности хоста:
   - `ratchet_bridge.ts` (Ed25519, ротация ключей, морфинг);
   - `jail.ts` (проверка путей);
   - `redaction.ts` (маскирование секретов).
3. [ ] Реализовать `sarif/builder.ts` для генерации SARIF v2.1.0 отчетов.
4. [ ] Реализовать `docker/runner.ts` (управление жизненным циклом Docker-песочницы).
5. [ ] Реализовать `mcp/bridge.ts` (клиент вызова Rust демона).
6. [ ] Реализовать все 12 MCP-инструментов в `src/mcp/tools/`.
7. [ ] Реализовать MCP STDIO сервер в `src/mcp/server.ts`.
8. [ ] Валидация: выполнить компиляцию TypeScript (`npm run build`).
