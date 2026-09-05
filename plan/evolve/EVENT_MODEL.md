# Evolve Event Model

## 1. Цель

Evolve должен принимать события от разных sensors в одном нормализованном формате.

Основной контракт:

```rust
SecurityEvent
```

Он описывает наблюдаемый факт, а не окончательный вывод о намерении.

---

## 2. Event categories

Первоначальный набор:

```text
FileOpen
FileRead
FileWrite
FileDelete

ProcessSpawn
ProcessExec
ProcessExit

NetworkConnect
NetworkListen
DnsAttempt

CredentialAccess
CanaryAccess

Discovery
PrivilegeAttempt
PersistenceAttempt
LateralMovementAttempt

BrowserNavigation
HttpRequest

PolicyViolation
EscapeAttempt
ControlPlaneAccess
```

Набор должен быть расширяемым без изменения верхнего Evolve state contract.

---

## 3. SecurityEvent fields

Минимальная структура:

```text
event_id
session_id
timestamp
source
event_type

process_id
parent_process_id
uid

resource
destination

command
arguments
result

risk_hint
metadata
```

Не все поля обязательны для каждого event type.

---

## 4. Event sources

Первый релиз должен собирать события из уже существующих runtime paths:

- `sandbox_exec`;
- background execution;
- tmux;
- managed browser;
- HTTP probe;
- canary;
- egress policy violations;
- process identity violations;
- filesystem event watcher.

После стабилизации контракта можно добавить eBPF sources:

```text
execve
connect
openat
ptrace
setuid
mount
```

Новый sensor обязан преобразовать данные в тот же `SecurityEvent`.

---

## 5. Canary migration

Текущий canary watcher использует metadata polling с интервалом около 500 мс.

Stage 8 должен перевести его на event-driven source, предпочтительно:

```text
fanotify / inotify
 ↓
SecurityEvent::CanaryAccess
```

Canary sensor не должен самостоятельно принимать решение о полном network isolation, кроме отдельного hard-coded critical path при явной попытке нарушить control boundary.

---

## 6. EvolveSession

События объединяются в behavioral session.

Минимальные поля:

```text
session_id
created_at
last_event_at
state
risk_level
event_refs
process_roots
active_deception_profile
shadow_path_id
attack_trace_id
```

Session должна позволять восстановить порядок событий без зависимости от LLM context.

---

## 7. BehaviorTrace

Одиночное событие часто малоинформативно.

`BehaviorProfiler` строит:

```text
BehaviorTrace
```

который включает:

- ordered event sequence;
- process lineage;
- resource lineage;
- network lineage;
- behavior tags;
- confidence;
- risk score.

Пример:

```text
read .env
 ↓
enumerate interfaces
 ↓
read .ssh
 ↓
spawn curl
 ↓
attempt connection
```

рассматривается как одна последовательность, а не пять независимых alerts.

---

## 8. Risk levels

Базовая шкала:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

Начальная policy:

```text
LOW      -> observe
MEDIUM   -> enhanced telemetry
HIGH     -> engage deception
CRITICAL -> isolate
```

Risk evaluation должна иметь deterministic baseline.

AI classifier может добавлять дополнительный сигнал, но не быть единственным источником решения о security boundary.

---

## 9. AttackTrace

`TtpRecorder` формирует долгоживущий результат session.

Пример:

```json
{
  "session_id": "...",
  "stages": [
    {
      "phase": "discovery",
      "events": [],
      "commands": [],
      "tools": [],
      "targets": [],
      "techniques": []
    }
  ]
}
```

Особенно важно сохранять цепочку:

```text
observation
 ↓
action
 ↓
result
 ↓
next action
```

Это позволяет фиксировать стратегию, а не только IOC или список команд.

---

## 10. ATT&CK enrichment

ATT&CK mapping выполняется после построения trace.

Существующий `purple-team-detection-engineering` skill может использовать экспорт для:

- ATT&CK mapping;
- Sigma candidates;
- YARA candidates;
- IOC extraction;
- detection coverage analysis.

Enrichment не является enforcement authority.
