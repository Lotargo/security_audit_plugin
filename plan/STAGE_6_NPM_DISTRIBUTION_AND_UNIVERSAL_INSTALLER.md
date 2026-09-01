# Stage 6: Zero-Setup Web & NPM Distribution, Universal Manifests, Interactive Installer & Uninstaller

## 1. Цели и назначение этапа

Цель шестого этапа — обеспечить полную и бесшовную дистрибуцию плагина через **NPM**, **NPX** и нативные менеджеры плагинов всех ведущих ИИ-агентов (Google Antigravity, Claude Code, OpenCode, Gemini CLI, Cursor, Windsurf, Codex) с возможностью **установки в 1 клик**, **выборочной установки** и **чистого удаления (uninstall)** без необходимости ручного клонирования Git-репозитория.

---

## 2. Ключевые компоненты и задачи

### 1. Автономный резолв ассетов NPM-пакета (Package-Relative Asset Resolution)
* Резолв директории `skills/` относительно установленного NPM-пакета (`import.meta.url` $\rightarrow$ `packageRoot/skills`) с fallback на локальный `process.cwd()/skills`.
* Поддержка запуска `npx @security-audit/plugin install` и `uninstall` из любой произвольной директории на машине пользователя.

### 2. Универсальные команды `install`, `init` и `uninstall` в CLI
* **`security-audit install`** (alias: `install-skills`):
  * Выбор целевой среды: `--target agy | opencode | claude | local-agents | custom | all`.
  * Выборочная установка скиллов: `--skills <comma-separated-list | all>`.
  * Автоматическое конфигурирование / генерация сниппета MCP: `--mcp`.
* **`security-audit uninstall`** (alias: `uninstall-skills`):
  * Выбор целевой среды для удаления: `--target agy | opencode | claude | local-agents | custom | all`.
  * Выборочное удаление скиллов: `--skills <comma-separated-list | all>`.
  * Очистка директорий плагина и конфигураций MCP: `--mcp`.
* **`security-audit init`**:
  * Интерактивный терминальный мастер (Wizard) с автоопределением установленных IDE и выбором платформ.

### 3. Нативные манифесты для всех экосистем (Multi-Agent Compatibility)
* **Google Antigravity (AGY)**: `plugins/agy/plugin.json`, `plugins/agy/mcp_config.json`, поддержка `agy plugin install`.
* **Claude Code**: `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, поддержка `/plugin install`.
* **OpenCode**: `.opencode/INSTALL.md`, `plugins/opencode/opencode.json`, поддержка `opencode.json` plugin array.
* **Gemini CLI**: `gemini-extension.json` (`gemini extensions install`).
* **Cursor / Windsurf**: `.cursor-plugin/plugin.json` и инструкции по STDIO MCP.

---

## 3. Матрица тестовых сценариев Stage 6

* **Тест 6.1 (NPM Package Assets Discovery):** Проверка нахождения встроенных скиллов из node_modules/директории пакета при выполнении в пустом временном каталоге.
* **Тест 6.2 (Selective Skills Installation):** Проверка установки подмножества скиллов (например, `--skills web-appsec-dast,injection-input-validation`).
* **Тест 6.3 (Multi-Target Installation):** Проверка пакетной установки сразу для нескольких платформ (`--target all`).
* **Тест 6.4 (Clean Uninstallation):** Проверка удаления установленных скиллов и очистки целевых папок через `runUninstallSkills`.
* **Тест 6.5 (Selective Uninstallation):** Проверка удаления только указанных скиллов с сохранением остальных.

---

## 4. Контрольные точки

1. [x] Реализовать package-relative резолв путей в `src/cli/commands/install_skills.ts`.
2. [x] Добавить поддержку фильтра `--skills`, опции `--mcp` и `--target all`.
3. [x] Реализовать модуль деинсталляции `src/cli/commands/uninstall_skills.ts`.
4. [x] Зарегистрировать команды `install`, `init`, `uninstall` в `src/cli/index.ts`.
5. [x] Создать манифесты `gemini-extension.json`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `.opencode/INSTALL.md`, `.cursor-plugin/plugin.json`.
6. [x] Добавить тесты установки и удаления в `tests/cli.test.ts` (8 / 8 passed).
7. [x] Проверить компиляцию (`npm run build`) и тесты (`npm test` — 35/35 passed).
