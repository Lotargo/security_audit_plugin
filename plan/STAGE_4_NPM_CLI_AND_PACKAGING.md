# Stage 4: NPM CLI, Packaging & Multi-Platform Manifests

## 1. Цели и назначение этапа

Цель четвертого этапа — упаковать проект в стандартизированный NPM-пакет и предоставить удобный интерфейс командной строки (CLI), а также сгенерировать готовые нативные манифесты для подключения плагина во все поддерживаемые агентские среды:
1. **Google Antigravity (AGY)** (`plugins/agy/`);
2. **OpenCode** (`plugins/opencode/`);
3. **Claude Code / Cursor / Windsurf**.

---

## 2. Структура директории packaging & CLI

```text
security_audit_plugin/
├── package.json                   # NPM manifest (bin, dependencies, exports)
├── tsconfig.json
├── bin/
│   └── cli.js                     # CLI роутер: npx @security-audit/plugin <command>
├── src/
│   └── cli/
│       ├── index.ts               # Commander / CAC парсер аргументов
│       ├── commands/
│       │   ├── mcp.ts             # Запуск MCP сервера через STDIO
│       │   ├── install_skills.ts  # Экспорт 19 скиллов в целевую платформу
│       │   ├── doctor.ts          # Диагностика окружения (Docker, Tor, порты)
│       │   ├── start_sandbox.ts   # Фоновый запуск песочницы
│       │   ├── stop_sandbox.ts    # Остановка песочницы
│       │   └── reset_sandbox.ts   # Экстренное пересоздание чистого контейнера
└── plugins/
    ├── agy/
    │   ├── plugin.json            # Манифест плагина для Antigravity
    │   └── mcp_config.json        # MCP конфигурация для Antigravity
    └── opencode/
        └── opencode.json          # Манифест для OpenCode
```

---

## 3. Детальная спецификация команд CLI (`bin/cli.js`)

### 1. `npx @security-audit/plugin mcp`
* **Назначение:** Основная команда для подключения к ИИ-агентам.
* **Поведение:** Запускает MCP-сервер по протоколу STDIO. При первом вызове инструмента песочницы автоматически проверяет статус Docker и поднимает контейнер при необходимости.

### 2. `npx @security-audit/plugin install-skills --target <target> [--path <custom_path>]`
* **Назначение:** Копирует и настраивает 19 экспертных скиллов в каталог конкретной агентской среды.
* **Поддерживаемые цели (`--target`):**
  - `agy` $\rightarrow$ экспорт в `~/.gemini/config/plugins/security-audit/skills/` или `.agents/skills/`;
  - `opencode` $\rightarrow$ экспорт в `.opencode/skills/`;
  - `claude` $\rightarrow$ экспорт в `.claude/skills/`;
  - `custom` $\rightarrow$ экспорт по указанному пути `--path`.

### 3. `npx @security-audit/plugin doctor`
* **Назначение:** Проверка системных требований и окружения.
* **Проверяет:**
  - Наличие и версию Docker (`docker version`);
  - Доступность портов (9999, 9050, 9051);
  - Наличие собранного образа `security-audit-sandbox:latest`;
  - Поддержку аппаратных/сетевых драйверов;
  - Выводит понятные рекомендации по исправлению ошибок.

### 4. `npx @security-audit/plugin reset-sandbox`
* **Назначение:** Ручной сброс песочницы.
* **Поведение:** Принудительно останавливает и удаляет текущий контейнер, зачищает временные сокеты и запускает новый чистый контейнер без удаления файлов из `/workspace/reports/`.

---

## 4. Спецификация манифестов плагинов

### 1. `plugins/agy/plugin.json` (Google Antigravity)
```json
{
  "name": "security-audit-plugin",
  "version": "1.0.0",
  "description": "Comprehensive Security Audit Plugin with isolated Docker sandbox, Rust kernel, stealth browser, Tor routing and 19 standardized skills.",
  "author": "Lotargo",
  "skills": "../../skills",
  "mcpServers": {
    "security-audit-sandbox": {
      "command": "node",
      "args": ["${pluginDir}/../../dist/src/mcp/server.js"]
    }
  }
}
```

### 2. `plugins/opencode/opencode.json` (OpenCode)
```json
{
  "plugin": "security-audit-plugin",
  "version": "1.0.0",
  "skills_dir": "../../skills",
  "mcp": {
    "command": "npx",
    "args": ["@security-audit/plugin", "mcp"]
  }
}
```

---

## 5. Порядок выполнения и контрольные точки

1. [ ] Написать `package.json` с секцией `bin`, скриптами сборки (`build`, `prepublishOnly`) и зависимостями.
2. [ ] Написать CLI роутер в `bin/cli.js` и команды в `src/cli/commands/`.
3. [ ] Реализовать команду `doctor` для проверки Docker и зависимостей.
4. [ ] Реализовать команду `install-skills` для автоматического копирования 19 скиллов.
5. [ ] Создать манифесты `plugins/agy/plugin.json`, `plugins/agy/mcp_config.json` и `plugins/opencode/opencode.json`.
6. [ ] Валидация: протестировать запуск CLI команд (`npm run build`, `node bin/cli.js doctor`).
