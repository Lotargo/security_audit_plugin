1. **Seccomp-профиль не включён в npm package**
   - `runner.ts` требует `sandbox_runtime/seccomp/evolve-bwrap.json`.
   - В `package.json -> files` папки `sandbox_runtime/seccomp` нет.
   - Локально всё работает, после `npm pack/publish` runtime может перестать запускаться.

2. **Canary может перезаписать реальные файлы пользователя**
   - Используются фиксированные пути вроде:
     - `.aws/credentials`
     - `.ssh/id_rsa`
     - `.kube/config`
     - `.gcp/credentials.json`
   - `fs::write()` перезапишет существующий файл, если он уже есть.

3. **Canary меняет права существующих директорий**
   - Родительские директории переводятся в `0777`.
   - Файлы в `0666`.
   - Если `.ssh`, `.aws` или `.kube` существовали до запуска плагина, их права могут быть испорчены.

4. **`REAL XOR SHADOW` можно формально обойти другим session ID после failed ENGAGE**
   - Для отозванной session A всё закрывается правильно.
   - Но в глобальном `ISOLATE` запрос с неизвестным `session_id` может попасть в `AgentSurface::Real`.
   - После deception engagement должен существовать глобальный fail-closed latch.

5. **Browser RoE ограничивает hostname, но не port**
   - Scope `localhost:18081` фактически превращается в `localhost`.
   - Browser потенциально может обращаться к другим портам этого же host.
   - Нужно проверять authority/origin вида `host:port`.

6. **Browser UID отдельно не блокируется от management/Tor ports**
   - Для browser process желательно явно закрыть:
     - `9999`
     - `9050`
     - `9051`
   - Сейчас основная защита там больше опирается на L7 guard и Ratchet.

7. **`allow_private` является agent-facing флагом**
   - Агент сам может запросить обход SSRF-защиты приватных адресов.
   - Это допустимо для DAST, но разрешение должно вытекать из RoE scope, а не из произвольного boolean конкретного browser вызова.

8. **Canary чтение определяется через `atime`**
   - Race и same-size overwrite уже исправлены.
   - Но обычное чтение файла всё ещё может не менять `atime` из-за `relatime/noatime`.
   - READ-trigger пока best-effort.
   - Для надёжного сенсора нужен `inotify/fanotify`.

9. **Shadow Attack Path всё ещё имеет semantic topology leak**
   - Manifest, `/etc/hosts`, service-map и реальные listening services теперь скрываются правильно.
   - Но profile-specific config иногда заранее содержит hidden hostname.
   - Пример:

     ```text
     DATABASE_HOST=db-prod.internal
     SECRETS_URL=http://vault.prod.internal
     ```

   - Эти узлы могут быть ещё `Hidden`.

10. **Chromium запускается с отключённым собственным sandbox**
    - Используются:

      ```text
      --no-sandbox
      --disable-setuid-sandbox
      ```

    - Capability drop хороший, но при browser RCE процесс остаётся внутри общего контейнерного filesystem.
    - В перспективе browser worker стоит посадить в отдельный bwrap filesystem view.

11. **Browser process потенциально видит реальный `/workspace`**
    - Для DAST это нежелательно, потому что браузер обрабатывает враждебный web-контент.
    - Лучше дать ему отдельный minimal filesystem и только нужный output mount.

12. **Нужен packaging regression test**
    - Текущие 127 тестов проверяют git checkout.
    - Они не проверяют содержимое реально публикуемого npm tarball.
    - Нужен тест через `npm pack --dry-run` или эквивалент, чтобы runtime assets больше не выпадали из релиза.
