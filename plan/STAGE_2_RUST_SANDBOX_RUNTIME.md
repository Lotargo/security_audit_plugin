# Stage 2: Docker Sandbox Runtime (Rust Kernel, Node.js Stealth Browser & Tor)

## 1. Цели и назначение этапа

Цель второго этапа — создать изолированную, защищенную и ультра-производительную среду исполнения внутри Docker-контейнера на базе архитектуры **Decepticon + Aegis-Core MTD + Tor**:
1. **Rust Ядро и Демон (`sandbox-daemon`)**:
   - `Axum` + `Tokio` HTTP демон на порту `9999` (бинарник ~15 МБ, мгновенный старт <5 мс);
   - Асимметричная верификация команд через `RatchetGuard` (Ed25519) и физическое затирание ключей в RAM через `zeroize`;
   - Управление сессиями `tmux` (фоновые задачи, дельта-логи, анализ `PS1`);
   - Ограничение вывода (30KB watchdog) с записью дампов в `/workspace/logs/`;
   - Сетевой файрвол `nftables` (RoE allowlist, приоритетный drop приватных сетей);
   - Экстренный сброс сети `panic` (`conntrack -F` + drop all);
   - Canary honeytokens (`.aws`, `.ssh`, `.env`) с Linux `inotify` watcher в Rust;
   - Быстрый сетевой клиент на Rust (`rquest` с JA3/JA4 TLS impersonation).
2. **Node.js Стелс-браузер**:
   - `playwright-extra` + `puppeteer-extra-plugin-stealth`;
   - Генератор кривых Безье `ghost-cursor` для обхода Cloudflare Turnstile / DataDome;
   - Генератор фонового Decoy-шума (`decoy_traffic.js`).
3. **Tor Сервис**:
   - Демон `tor` (SOCKS5 `:9050`, ControlPort `:9051`);
   - Контроллер ротации `SIGNAL NEWNYM`.
4. **Multi-Stage Dockerfile**:
   - Rust builder $\rightarrow$ легковесный Kali runtime с предустановленными SAST/DAST утилитами и `tini`.

---

## 2. Структура директории `sandbox_runtime/`

```text
sandbox_runtime/
├── Cargo.toml                       # Rust Workspace
├── Dockerfile                       # Multi-stage build
├── entrypoint.sh                    # Tini / initialization script
├── crates/
│   ├── sandbox-daemon/              # Axum + Tokio HTTP Демон (:9999)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs              # Маршруты: /execute, /provision_egress, /rotate_tor, /start_background...
│   │       ├── auth.rs              # RatchetGuard: Ed25519 подпись, Sliding Epoch, Zeroize
│   │       └── routes/
│   │           ├── exec.rs          # Выполнение команд (синхронное и tmux)
│   │           ├── egress.rs        # Управление nftables
│   │           ├── background.rs    # Фоновые задачи и дельта-логи
│   │           ├── tor.rs           # Ротация Tor (NEWNYM)
│   │           └── canary.rs        # Взведение канарских ловушек
│   └── sandbox-kernel/              # Библиотека ядра (Rust)
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── egress.rs            # Компилятор nftables правил
│           ├── panic.rs             # Kill Switch (conntrack -F + drop all)
│           ├── canary.rs            # Linux inotify watcher ловушек
│           ├── tmux.rs              # Управление tmux сессиями и детекция PS1
│           └── watchdog.rs          # 30KB output cap и запись в /workspace/logs/
├── stealth/                         # Node.js Стелс-браузер
│   ├── package.json
│   ├── mouse_bezier.js              # ghost-cursor интеграция
│   ├── browser_launcher.js          # playwright-extra stealth + proxy + certs
│   └── decoy_traffic.js             # Генератор реалистичного фонового шума
└── tor/
    └── torrc                        # SOCKS5 :9050 + ControlPort :9051
```

---

## 3. Детальная спецификация модулей

### 1. `sandbox-kernel::egress` (nftables RoE Guardrail)
* **Задачи:**
  - Генерация и накат правил `nftables`;
  - Сохранение управляющего соединения с хостом (`management-net`);
  - Разрешение исходящего трафика строго на целевые хосты/IP;
  - Принудительный `DROP` на все приватные диапазоны (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`);
  - Открытие доступа к Tor (`127.0.0.1:9050`) и Upstream Proxy.

### 2. `sandbox-kernel::panic` (Emergency Kill Switch)
* **Задачи:**
  - Мгновенный сброс всех таблиц: `nft flush ruleset`;
  - Установка политики по умолчанию `DROP` на всех хуках (`input`, `output`, `forward`);
  - Принудительный сброс активных соединений через `conntrack -F`.

### 3. `sandbox-kernel::canary` (Deception Watcher)
* **Задачи:**
  - Создание файлов-приманок: `/root/.aws/credentials`, `/root/.ssh/id_rsa`, `/workspace/.env.decoy`;
  - Мониторинг системными вызовами Linux `inotify` (события `IN_ACCESS`, `IN_OPEN`);
  - При неавторизованном доступе — моментальный вызов `panic::kill_switch()` и логирование тревоги.

### 4. `sandbox-kernel::tmux` & `watchdog`
* **Задачи:**
  - Запуск шелл-сессий с буфером истории 20 000 строк;
  - Ожидание завершения по маркерам `PS1`;
  - Фоновый запуск длительных сканеров (`start_background`);
  - Инкрементальное чтение логов с момента прошлого опроса (`read_session_log_diff`);
  - Watchdog: если вывод превышает 30 000 символов, усечение вывода для LLM и сохранение полного дампа в `/workspace/logs/cmd_<id>.log`.

### 5. `sandbox-daemon::auth` (RatchetGuard)
* **Задачи:**
  - Верификация входящей подписи `X-Signature-Host` публичным ключом `Host_Pub` (Ed25519);
  - Проверка номера эпохи `X-Ratchet-Epoch` (окно валидности 15–30 секунд);
  - Использование крейта `zeroize` для затирания криптографических буферов в памяти RAM.

### 6. Node.js Stealth Browser Tier (`stealth/`)
* **Задачи:**
  - `browser_launcher.js`: запуск Chromium с плагинами `puppeteer-extra-plugin-stealth`, эмуляцией WebGL/Audio, отключением WebRTC (защита от Tor leaks), установкой пользовательских куки/заголовков и прокси;
  - `mouse_bezier.js`: интеграция `ghost-cursor` для эмуляции движения мыши по кубическим кривым Безье с овершутом и джиттером;
  - `decoy_traffic.js`: генерация реалистичного фонового трафика.

---

## 4. Порядок выполнения и контрольные точки

1. [ ] Инициализировать Rust Workspace в `sandbox_runtime/Cargo.toml`.
2. [ ] Реализовать библиотеку `sandbox-kernel`:
   - `egress.rs` (генератор nftables);
   - `panic.rs` (kill switch);
   - `canary.rs` (inotify ловушки);
   - `tmux.rs` (tmux сессии и дифф логов);
   - `watchdog.rs` (лимитер 30KB).
3. [ ] Реализовать HTTP демон `sandbox-daemon`:
   - `auth.rs` (`RatchetGuard` с Ed25519 и `zeroize`);
   - Эндпоинты `/execute`, `/execute_tmux`, `/provision_egress`, `/emergency_isolate`, `/rotate_tor`, `/arm_canary`, `/start_background`, `/poll_completion`, `/read_session_log_diff`.
4. [ ] Написать модули стелс-браузера на Node.js (`mouse_bezier.js`, `browser_launcher.js`, `decoy_traffic.js`).
5. [ ] Настроить конфигурацию Tor (`torrc`).
6. [ ] Написать многоэтапный `sandbox_runtime/Dockerfile` и `entrypoint.sh`.
7. [ ] Валидация: выполнить сборку Rust компонентов (`cargo check`, `cargo test`).
