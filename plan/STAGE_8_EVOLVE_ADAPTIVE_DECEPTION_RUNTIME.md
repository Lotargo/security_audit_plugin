# Stage 8: Evolve Adaptive Deception Runtime

## 1. Цель этапа

Stage 8 вводит в `security-audit-plugin` механизм **Evolve**: адаптивный защитный контур, который не ограничивается немедленной блокировкой подозрительного поведения.

Целевая схема:

```text
observe
 ↓
classify behavior
 ↓
estimate risk
 ↓
engage deception
 ↓
move suspicious session into a Shadow Attack Path
 ↓
record TTP, commands, tools and action sequence
 ↓
build AttackTrace
 ↓
generate CandidateDefenseMutation
 ↓
validate
 ↓
apply safe restrictive mutation
 ↓
observe again
 ↺
```

Evolve строится поверх существующих `canary`, `containment`, `egress`, `KillSwitch`, sandbox daemon и Host MCP Bridge. Он не заменяет текущие security boundaries.

Подробная архитектура вынесена в [evolve/ARCHITECTURE.md](./evolve/ARCHITECTURE.md).

---

## 2. Текущий baseline

Stage 8 должен опираться на фактическое состояние `main`.

Уже реализованы:

- Rust `sandbox-kernel` и `sandbox-daemon`;
- fail-closed `nftables` egress policy;
- process identity containment для agent, browser и Tor;
- canary honeytokens;
- emergency isolation через `KillSwitch`;
- signed host-to-sandbox control plane;
- host-side active network scope;
- managed browser и HTTP probe с RoE enforcement;
- hard reset sandbox runtime;
- live Docker adversarial regression tests.

Важное ограничение текущего baseline:

`sandbox-kernel/src/canary.rs` сейчас проверяет filesystem metadata по таймеру и при срабатывании напрямую вызывает `KillSwitch::trigger(...)`.

Для Evolve detection и containment должны быть разделены.

---

## 3. Основные security invariants

1. Evolve может автоматически делать runtime policy строже, но не расширять исходный RoE.
2. Deception environment не получает реальные credentials, host secrets, management keys или реальные infrastructure endpoints.
3. Shadow Attack Path содержит только shadow resources.
4. AI или classifier не изменяет `nftables`, privileges или KillSwitch напрямую.
5. Любая CandidateDefenseMutation проходит deterministic validation.
6. Ошибка Evolve приводит к fail-closed состоянию.
7. KillSwitch доступен из любого Evolve state.
8. Путь `deception -> real infrastructure` запрещён архитектурно.

Полный набор инвариантов описан в [evolve/ARCHITECTURE.md](./evolve/ARCHITECTURE.md).

---

## 4. State machine

Основные состояния:

```text
OBSERVE
   ↓
SUSPECT
   ↓
ENGAGE
   ↓
DECEIVE
   ↓
LEARN
   ↓
ADAPT
   ↓
OBSERVE
```

Аварийный переход:

```text
ANY STATE
   ↓
critical violation / escape attempt / control-plane interaction
   ↓
ISOLATE
```

Назначение состояний и допустимые transitions описаны в [evolve/ARCHITECTURE.md](./evolve/ARCHITECTURE.md).

---

## 5. Целевая структура

```text
sandbox_runtime/
└── crates/
    └── sandbox-kernel/
        └── src/
            ├── evolve/
            │   ├── mod.rs
            │   ├── event.rs
            │   ├── state.rs
            │   ├── session.rs
            │   ├── behavior.rs
            │   ├── risk.rs
            │   ├── deception.rs
            │   ├── narrative.rs
            │   ├── attack_path.rs
            │   ├── recorder.rs
            │   ├── policy.rs
            │   ├── mutation.rs
            │   └── guard.rs
            ├── canary.rs
            ├── containment.rs
            ├── egress.rs
            └── panic.rs
```

В `sandbox-daemon` добавляется shared `EvolveManager`.

---

## 6. Документы Stage 8

Детальные контракты вынесены из Stage-файла:

- [ARCHITECTURE.md](./evolve/ARCHITECTURE.md) - state machine, trust boundaries, runtime integration и security invariants;
- [EVENT_MODEL.md](./evolve/EVENT_MODEL.md) - `SecurityEvent`, `BehaviorTrace`, sessions и TTP recording;
- [DECEPTION_MODEL.md](./evolve/DECEPTION_MODEL.md) - Deception Fabric, EnvironmentNarrative и Shadow Attack Path;
- [TESTING.md](./evolve/TESTING.md) - unit, integration и live Docker adversarial validation.

---

## 6.1. Текущий implementation status

Рабочая ветка:

```text
stage-8-evolve-event-core
```

Текущее состояние:

### Phase 8.1 - Event Core

Реализовано:

- `SecurityEvent`, `RiskLevel`, `EvolveState`, `EvolveSession`, `EvolveManager`;
- единый daemon event sink;
- event ingestion для canary, sync exec, background execution, browser и HTTP probe;
- route-level `PolicyViolation` events для RoE violations;
- единый `evolve_session_id` на audit scope со стороны Host MCP Bridge;
- canary trigger correlation с текущей behavioral session;
- устранён старый contract mismatch `token_label` / `base_dir`;
- stale canary watcher invalidation при повторном arm;
- manual emergency isolation синхронизирует `EvolveState::Isolate`;
- daemon observability routes для status, events, sessions и trace;
- live Docker Evolve regression scenario добавлен в CI.

### Draft integration

После объединения раннего Evolve prototype и Stage 8 runtime сохранены:

- persistent generation/profile memory;
- deterministic recommendations;
- containment-first materialization of the inert `.deployment/prod/` deception surface;
- recursive `inotifywait` telemetry for the deeper decoy;
- MCP `sandbox_evolve_status` and `sandbox_evolve_observe`;
- emergency-isolation latch that forbids egress re-provisioning in the same runtime.

Эти возможности больше не используют отдельный Evolve controller. Они встроены как feedback/deception subsystem нового `EvolveManager`.

### Phase 8.2 - Behavior Layer

Реализован baseline:

- `BehaviorProfiler`;
- ordered `BehaviorTrace`;
- deterministic behavior tags;
- process lineage;
- resource lineage;
- destination lineage;
- deterministic risk score;
- contextual sequence correlation;
- conservative separation между credential interest и confirmed credential access;
- decision layer использует effective contextual risk.

Текущая политика до появления Deception Fabric:

```text
LOW      -> OBSERVE
MEDIUM   -> SUSPECT / enhanced telemetry
HIGH     -> existing KillSwitch
CRITICAL -> existing KillSwitch
```

Это временный fail-closed режим. После Phase 8.3 безопасный `HIGH` path сможет переходить в `ENGAGE -> DECEIVE`.

### Validation status

GitHub Actions для текущего PR создаёт jobs, но runner не назначается:

```text
runner_id: 0
steps: []
```

Поэтому CI сейчас завершается до checkout и не выполняет Rust/TypeScript/Docker код. Unit и live regression tests уже добавлены в ветку и должны быть прогнаны до merge при восстановлении runner availability.

---

## 7. Implementation phases

### Phase 8.1 - Event Core

Реализовать:

- `SecurityEvent`;
- `EvolveState`;
- `EvolveSession`;
- `EvolveManager`;
- deterministic state transitions;
- event storage;
- перевод canary detection на event model.

Canary больше не должен напрямую вызывать KillSwitch для любого события.

### Phase 8.2 - Behavior Layer

Реализовать:

- `BehaviorTrace`;
- event correlation;
- process lineage;
- resource lineage;
- базовый deterministic risk scoring.

### Phase 8.3 - Deception Fabric

Текущий baseline уже реализует:

- отдельную reserved identity `audit-deception` (UID/GID 65533);
- identity-based deny rules для любого non-loopback egress deception workloads;
- отдельный deny для daemon management port, Tor SOCKS/control и DNS;
- те же deny-инварианты внутри emergency KillSwitch ruleset;
- `DeceptionProfile`, `DeceptionInstance` и `DeceptionFabric`;
- session-scoped synthetic filesystem root;
- deterministic profile selection на основе `BehaviorTrace`;
- loopback-only planned synthetic service descriptors;
- validation, запрещающую unsafe session paths и non-loopback service endpoints;
- hidden staging permissions для prepared filesystem surface;
- отдельный `deception-service` binary;
- запуск synthetic services через `setpriv` под UID/GID `audit-deception`;
- статические HTTP, SSH-banner и PostgreSQL-auth decoy protocols;
- authenticated prepare/status/destroy lifecycle routes для runtime validation;
- `bubblewrap`-based synthetic shell surface с отдельными mount/PID/IPC/UTS namespaces;
- synthetic `/workspace`, `/etc/hosts`, passwd/group/hostname вместо реальной workspace surface;
- выполнение shell-команд после `setpriv` до UID/GID 65533;
- resource limits через `prlimit`;
- deception UID network access ограничен только TCP shadow range `18000-18999` на loopback;
- live regression проверяет отсутствие доступа к daemon management port и внешнему egress.

Автоматический redirect `HIGH -> ENGAGE -> DECEIVE` пока не включён. До появления безопасного redirect boundary HIGH/CRITICAL продолжают fail-closed через KillSwitch.

Осталось реализовать:

- `DeceptionProfile`;
- `DeceptionInstance`;
- отдельную runtime identity для deception workloads;
- filesystem deception;
- базовые synthetic services;
- жёсткое отсутствие пути к real targets и management plane.

### Phase 8.4 - Shadow Attack Path

Реализовать:

- shadow graph;
- session-specific topology;
- `EnvironmentNarrative`;
- динамический выбор следующего shadow node;
- ограничения на допустимые типы узлов.

### Phase 8.5 - TTP Learning

Реализовать:

- `TtpRecorder`;
- `AttackTrace`;
- command/tool sequence;
- связь observation -> action -> result -> next action;
- export для последующего ATT&CK и purple-team enrichment.

### Phase 8.6 - Defense Mutation

Реализовать фиксированный набор mutation types:

```text
BLOCK_DESTINATION
BLOCK_BEHAVIOR
INCREASE_TELEMETRY
ARM_NEW_CANARY
SPAWN_DECOY
ALTER_SHADOW_PATH
RESTRICT_IDENTITY
ADD_DETECTION_RULE
ISOLATE_SESSION
```

Добавить:

- `CandidateDefenseMutation`;
- `MutationValidator`;
- `MutationController`;
- запрет автоматического расширения capability и RoE.

### Phase 8.7 - MCP and Observability

Добавить управляющий MCP surface:

```text
sandbox_evolve_enable
sandbox_evolve_status
sandbox_evolve_sessions
sandbox_evolve_events
sandbox_evolve_policy
sandbox_evolve_export
```

Evolve должен продолжать работать внутри daemon/kernel независимо от MCP polling.

### Phase 8.8 - Kernel Telemetry Expansion

После стабилизации event contract добавить расширенные Linux telemetry sources.

Планируемые источники:

```text
execve
connect
openat
ptrace
setuid
mount
```

Предпочтительный дальнейший backend - eBPF, без изменения верхнего Evolve API.

---

## 8. Explicit non-goals

Stage 8 не включает:

- public internet-facing honeynet;
- offensive counterattack;
- атаку инфраструктуры атакующего;
- автоматическое расширение RoE;
- копирование реальных credentials в deception;
- произвольный shell execution из defense mutation;
- прямое управление kernel policy со стороны LLM;
- замену существующего KillSwitch или sandbox isolation.

---

## 9. Definition of Done

Stage 8 завершён, когда:

1. существует единый `SecurityEvent` contract;
2. canary detection больше не связан напрямую с KillSwitch;
3. работает deterministic Evolve state machine;
4. `BehaviorProfiler` формирует последовательный `BehaviorTrace`;
5. suspicious session может быть переведена в отдельную deception environment;
6. deception runtime не имеет пути к host, management plane или real target infrastructure;
7. работает Shadow Attack Path из нескольких типов shadow nodes;
8. `TtpRecorder` сохраняет TTP, команды, инструменты и последовательность действий;
9. формируется экспортируемый `AttackTrace`;
10. defense mutation ограничена фиксированным набором операций;
11. каждая mutation проходит deterministic validation;
12. Evolve не может расширить исходный RoE;
13. KillSwitch доступен из любого Evolve state;
14. ошибки Evolve обрабатываются fail-closed;
15. MCP предоставляет управление и observability, но не является Evolve controller;
16. Stage 8 tests проходят в CI;
17. существующие security boundary regression tests проходят без регрессий.
