# Evolve Deception Model

## 1. Цель

Deception Fabric создаёт для suspicious session правдоподобную synthetic infrastructure, которая не имеет маршрута к real host, management plane или real audit targets.

Текущие canary files являются первым простым видом deception, но Stage 8 расширяет модель до связанной shadow topology.

---

## 2. Deception classes

Первоначально поддерживаются:

```text
filesystem deception
credential deception
service deception
network deception
host deception
application deception
infrastructure deception
```

Все данные synthetic.

---

## 3. DeceptionProfile

Базовые профили:

```text
developer-workstation
ci-runner
application-server
database-host
kubernetes-node
bastion-host
secrets-service
internal-api
```

Профиль описывает допустимый тип ложной среды, а не произвольный generated container.

---

## 4. DeceptionInstance

Каждый instance содержит:

```text
profile_id
instance_id
session_id
visible_services
visible_files
visible_credentials
network_neighbors
next_shadow_nodes
telemetry_policy
expiration
```

Instance не должен содержать:

- real API keys;
- real SSH keys;
- host paths;
- real service endpoints;
- Ratchet material;
- production credentials.

---

## 5. EnvironmentNarrative

Чтобы deception не раскрывалась из-за противоречий, Evolve хранит уже увиденные session свойства среды.

```text
EnvironmentNarrative
```

Пример:

```text
Linux
Node.js
PostgreSQL
Docker
internal naming convention
observed user names
visible service layout
```

Следующие shadow nodes должны быть совместимы с уже раскрытой легендой.

Synthetic значения могут быть похожи по структуре, но не копировать реальные secrets.

---

## 6. Shadow Attack Path

`ShadowAttackPath` является графом только из shadow resources.

Пример:

```text
fake-web
 ↓
fake-app
 ↓
fake-internal-api
 ↓
fake-database
 ↓
fake-kubernetes
 ↓
fake-secrets
```

Граф создаётся отдельно для behavioral session.

---

## 7. Dynamic path expansion

Следующий node выбирается на основе наблюдаемого поведения.

Примеры:

```text
session searches SSH material
 ↓
expose fake bastion reference
```

```text
session enumerates Kubernetes
 ↓
expose fake kube context
```

```text
session searches database credentials
 ↓
expose fake database endpoint
```

Выбор ограничен заранее разрешёнными `DeceptionProfile`.

LLM не может создать произвольный privileged shadow workload.

---

## 8. Isolation rules

Для `audit-deception` должны действовать отдельные containment rules.

Обязательно запрещены:

- host access;
- daemon management port;
- Ratchet secrets;
- direct real-target egress;
- agent identity impersonation;
- Tor control path;
- direct changes to `nftables`.

Разрешён только explicitly compiled shadow topology traffic.

---

## 9. Real-to-shadow transition

Переход suspicious session в deception должен происходить только после подготовки безопасного shadow environment.

Предпочтительная последовательность:

```text
HIGH risk confirmed
 ↓
prepare shadow topology
 ↓
validate deception isolation
 ↓
restrict real surface for session
 ↓
activate shadow resources
 ↓
transition ENGAGE -> DECEIVE
```

Если preparation или validation завершается ошибкой, transition не выполняется.

При невозможности безопасно продолжить session используется stricter policy или `ISOLATE`.

---

## 10. Forbidden path

Ключевой invariant:

```text
ShadowAttackPath contains only shadow resources
```

Любая ссылка на:

```text
real host
management daemon
real workspace secret
real target
real cloud identity
```

делает shadow graph невалидным.

---

## 11. Lifecycle

Deception instances должны иметь ограниченный lifecycle:

```text
CREATE
 ↓
VALIDATE
 ↓
ACTIVE
 ↓
CAPTURE
 ↓
EXPIRE
 ↓
DESTROY
```

После завершения session instance не должен оставлять reusable credential, stale route или active process, доступный следующей session.
