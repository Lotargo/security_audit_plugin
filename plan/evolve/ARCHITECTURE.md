# Evolve Architecture

## 1. Назначение

Evolve является runtime subsystem внутри доверенной Rust boundary `sandbox-kernel + sandbox-daemon`.

Он отвечает за цикл:

```text
SecurityEvent
 ↓
BehaviorProfiler
 ↓
Risk Evaluation
 ↓
State Transition
 ↓
Deception Fabric
 ↓
TTP Recorder
 ↓
CandidateDefenseMutation
 ↓
Validation
 ↓
Kernel Enforcement
```

AgentSkills и default MCP surface считаются частью agent-facing execution plane и не получают Evolve control/observability. Управление Evolve, status, traces, feedback и lifecycle доступны только через authenticated trusted host/operator control plane. Ни один из этих интерфейсов не является источником kernel authority.

---

## 2. Trust boundaries

### Trusted

- `sandbox-kernel`;
- authenticated `sandbox-daemon`;
- Ratchet-protected host bridge;
- deterministic mutation validator;
- existing `egress`, `containment` and `panic` enforcement.

### Untrusted

- agent-controlled shell processes;
- target responses;
- browser content;
- downloaded artifacts;
- executed tools and scripts;
- generated files;
- external network responses;
- deception workloads after compromise;
- AI-generated classifications and policy proposals.

---

## 3. Security invariants

### 3.1. One-way deception boundary

Разрешено:

```text
trusted runtime state
 ↓
synthetic projection
 ↓
deception environment
```

Запрещено:

```text
deception environment
 ↓
trusted runtime state
```

Shadow resource никогда не должен содержать ссылку, route или credential, который даёт доступ к real infrastructure.

### 3.2. Restrictive adaptation only

Автоматическая адаптация может:

- блокировать;
- ограничивать identity;
- усиливать telemetry;
- добавлять synthetic canary;
- создавать shadow node;
- менять shadow graph;
- добавлять detection candidate;
- изолировать session.

Автоматическая адаптация не может:

- добавлять новый real target;
- расширять CIDR allowlist;
- повышать privilege;
- давать доступ к management plane;
- восстанавливать ранее закрытый egress без trusted host action.

### 3.3. AI proposes, kernel validates

```text
classifier / AI
 ↓
CandidateDefenseMutation
 ↓
MutationValidator
 ↓
MutationController
 ↓
existing enforcement backend
```

Никакой AI component не получает прямого доступа к root shell, `nftables` или KillSwitch internals.

### 3.4. Fail-closed

Если невозможно доказать безопасность transition, deception node или mutation, операция не применяется.

Критическая ошибка Evolve должна завершаться состоянием `ISOLATE` или более строгим локальным policy state.

---

## 4. State machine

### OBSERVE

Нормальная работа runtime.

Собираются события, но поверхность не изменяется.

### SUSPECT

Обнаружена значимая последовательность.

Включаются:

- повышенная telemetry;
- behavioral session;
- retention process/resource lineage.

### ENGAGE

Система готовит deception environment и закрывает для suspicious session пути к реальной поверхности.

Transition в `DECEIVE` разрешён только после успешной проверки containment.

### DECEIVE

Session взаимодействует только с synthetic resources и Shadow Attack Path.

### LEARN

Собранные события нормализуются в `AttackTrace`.

### ADAPT

На основе trace формируется `CandidateDefenseMutation`.

Mutation проходит validation до применения.

### ISOLATE

Финальное аварийное состояние.

Использует существующий `KillSwitch`.

---

## 5. EvolveManager

`EvolveManager` является главным runtime coordinator.

Минимальная ответственность:

```text
current state
active sessions
event ingestion
behavior correlation
risk evaluation
deception lifecycle
attack trace lifecycle
candidate mutations
approved mutations
isolation escalation
```

Предпочтительное размещение shared state в daemon:

```rust
Arc<Mutex<EvolveManager>>
```

Event ingestion не должен зависеть от MCP polling.

---

## 6. Runtime identities

Текущие identities:

```text
audit-agent
audit-browser
audit-tor
daemon control plane
```

Stage 8 добавляет:

```text
audit-deception
```

`audit-deception` не должен иметь:

- management access;
- host filesystem access;
- Ratchet keys;
- real target egress;
- Tor control access;
- возможность изменять `nftables`.

Он может взаимодействовать только с разрешёнными shadow resources.

---

## 7. Integration with current modules

### canary

Canary становится sensor.

```text
CanaryAccess
 ↓
SecurityEvent
 ↓
EvolveManager
```

Прямой unconditional вызов `KillSwitch::trigger(...)` должен быть удалён из обычного canary path.

### containment

Используется для изоляции identities и deception workloads.

### egress

Остаётся единственным network enforcement backend.

Evolve не создаёт параллельный firewall.

### panic

Остаётся final emergency boundary.

### sandbox-daemon

Хранит Evolve runtime state и authenticated control routes.

### Host MCP Bridge

Хранит верхнеуровневый trusted scope.

Evolve может только сузить capability относительно активного RoE.

---

## 8. Defense mutation contract

Базовый enum:

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

Каждая mutation должна содержать:

```text
mutation_id
session_id
type
reason
evidence_refs
scope
requested_effect
rollback_metadata
validation_status
```

Validator должен отклонять:

- unknown mutation type;
- network expansion;
- privilege expansion;
- management-plane access;
- real credential injection;
- references to resources outside active RoE;
- malformed or unverifiable evidence references.

---

## 9. Workspace layout

```text
/workspace/evolve/
├── sessions/
├── traces/
├── policies/
├── deception/
└── exports/
```

Artifacts должны быть пригодны для offline analysis и purple-team enrichment, но не должны содержать реальные host secrets.

---

## 10. Control-plane boundary

Default agent-facing MCP registry не должен раскрывать Evolve internals.

Запрещено регистрировать для audit-agent:

```text
sandbox_evolve_enable
sandbox_evolve_status
sandbox_evolve_observe
sandbox_evolve_sessions
sandbox_evolve_events
sandbox_evolve_policy
sandbox_evolve_export
deception lifecycle controls
```

Причина проста: подозрительный агент является частью наблюдаемой стороны. Возможность запросить Evolve state раскрывает deception, а возможность писать observations позволяет отравлять feedback memory.

Допустимый интерфейс:

```text
trusted host/operator
 ↓ authenticated Ratchet control plane
sandbox-daemon
 ↓
EvolveManager
```

Host/operator может читать status, sessions, events, traces, export и выполнять разрешённые lifecycle operations. AgentSkills могут получать только те результаты, которые безопасно проецируются в обычный audit workflow и не раскрывают defensive state.

Kernel authority по-прежнему остаётся только у deterministic runtime. Не должно существовать endpoint вида `apply_arbitrary_evolve_command`.
