# Evolve Testing Strategy

## 1. Цель

Stage 8 добавляет динамическую deception и adaptive policy, поэтому существующих unit tests недостаточно.

Проверка должна охватывать:

```text
state machine
event model
behavior correlation
deception isolation
shadow topology
mutation validation
failure handling
live Docker boundary
```

Существующие security regression tests остаются обязательными.

---

## 2. State machine tests

Проверить разрешённые transitions:

```text
OBSERVE -> SUSPECT
SUSPECT -> ENGAGE
ENGAGE -> DECEIVE
DECEIVE -> LEARN
LEARN -> ADAPT
ADAPT -> OBSERVE
ANY -> ISOLATE
```

Недопустимые transitions должны завершаться ошибкой без изменения state.

---

## 3. Event tests

Для каждого базового source проверить нормализацию в `SecurityEvent`:

- file access;
- process spawn;
- network connect;
- canary trigger;
- browser request;
- HTTP probe;
- policy violation;
- escape attempt.

Проверить стабильный `session_id` и ordering.

---

## 4. Canary tests

Минимальные случаи:

1. Canary access создаёт `SecurityEvent::CanaryAccess`.
2. Обычное canary event не вызывает unconditional KillSwitch.
3. Critical policy может перевести session в `ISOLATE`.
4. Event-driven watcher фиксирует open/read event.
5. Re-arming не создаёт duplicate watcher state.

---

## 5. Behavior tests

Проверить корреляцию последовательностей.

Например:

```text
read .env
enumerate interfaces
read .ssh
spawn curl
connect attempt
```

должна объединяться в один `BehaviorTrace`.

Проверить:

- process lineage;
- event ordering;
- resource lineage;
- deterministic risk baseline.

---

## 6. Deception isolation tests

Каждый `DeceptionInstance` должен пройти negative tests.

Проверить, что shadow workload не может:

- обратиться к host;
- обратиться к management port;
- прочитать Ratchet material;
- обратиться к real audit target;
- изменить `nftables`;
- использовать Tor control port;
- получить agent or daemon identity.

---

## 7. Shadow Attack Path tests

Проверить:

- создание нескольких типов shadow nodes;
- динамический переход между nodes;
- narrative consistency;
- отсутствие real resource в graph;
- session isolation;
- уничтожение topology после session completion.

Graph validation должна отклонить real destination даже если она была предложена classifier или AI.

---

## 8. Mutation tests

Validator должен отклонять:

```text
unknown mutation
network expansion
RoE expansion
privilege expansion
management access
real credential injection
arbitrary shell mutation
invalid evidence refs
```

Validator должен принимать корректные restrictive operations.

Например:

```text
INCREASE_TELEMETRY
ARM_NEW_CANARY
RESTRICT_IDENTITY
ISOLATE_SESSION
```

при валидном scope и evidence.

---

## 9. Failure tests

Обязательные сценарии:

```text
EvolveManager state error
classifier timeout
event source failure
deception startup failure
deception validation failure
mutation validation failure
corrupted session artifact
shadow node crash
```

Ожидаемое поведение:

- capability не расширяется;
- old real path не восстанавливается автоматически;
- unsafe transition не выполняется;
- при критическом boundary uncertainty используется `ISOLATE`.

---

## 10. Live Docker adversarial tests

Расширить существующий Docker roundtrip.

Минимальный end-to-end сценарий:

```text
start sandbox
 ↓
set explicit scope
 ↓
enable Evolve
 ↓
trigger canary
 ↓
enter SUSPECT
 ↓
raise risk to HIGH
 ↓
prepare deception
 ↓
enter DECEIVE
 ↓
move through multiple shadow nodes
 ↓
attempt access to real target
 ↓
verify denial
 ↓
attempt management access
 ↓
verify denial or isolation
 ↓
export AttackTrace
 ↓
generate restrictive CandidateDefenseMutation
 ↓
validate and apply
```

---

## 11. Regression requirements

Stage 8 нельзя считать завершённым, если ломается любой существующий security invariant.

После каждого крупного блока должны проходить:

- TypeScript build;
- Vitest suite;
- Rust `cargo check`;
- Rust unit tests;
- Clippy;
- rustfmt;
- existing live Docker adversarial suite;
- new Evolve live Docker suite.

---

## 12. Definition of testing complete

Testing Stage 8 считается завершённым, когда:

1. state machine покрыта positive и negative transitions;
2. все event sources проходят normalization tests;
3. canary больше не имеет unconditional isolation behavior;
4. shadow runtime не имеет real network or management route;
5. Shadow Attack Path validator не допускает real resources;
6. mutation validator не допускает capability expansion;
7. failure injection сохраняет fail-closed behavior;
8. end-to-end trace и mutation lifecycle воспроизводимы в Docker;
9. existing security regression suite проходит без изменений security guarantees.
