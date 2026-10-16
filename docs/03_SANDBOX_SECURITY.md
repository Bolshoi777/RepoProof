# Безопасность исполнения: threat model и release blockers

## 1. Ключевая модель угроз

Пользователь может указать любой публичный GitHub repo. README и post-install scripts могут содержать произвольный код. Разрешение исполнять эти команды означает потенциально вредоносную активность. Репозиторий НЕ становится доверенным из-за высокого числа Stars, наличия лицензии или successful build.

**Защищаем:** Windows host, файлы пользователя, SSH/GitHub/Cloud credentials, домашнюю сеть, локальные службы, другие запуски, отчёты, runtime/daemon.

**Атакующий контролирует:** содержимое README, package scripts, исходники, имена файлов, environment reads, stdout/stderr, symlinks, архивные пути, сетевые обращения, содержимое ответа localhost.

## 2. Политика доверия (trust boundaries)

| Уровень | Доверие | Запрет |
|---|---|---|
| Windows GUI/Core | trusted | не исполняет repo script, не загружает недоверенный HTML |
| Inspector | read-only untrusted input | shell eval, доступ вне root, вложенные произвольные сетевые URL |
| Planner | proposes data | никакого запуска по тексту README |
| Worker controller | trusted with narrow rights | доступ к пользовательскому $HOME, daemon socket mounts |
| Guest VM | untrusted workload | host mount, host network, persistent credentials, privileged guest->host API |
| Report renderer | untrusted strings | active scripts/HTML из логов |

## 3. Решение для v1

1. `inspect` всегда допустим без исполнения.
2. `execute` выключен до появления отдельного VM worker с задокументированными гарантиями изоляции, поддержкой удаления VM и проверяемыми лимитами.
3. Разрешённый пакет execution plan показывается пользователю до запуска.
4. Никакого fallback на `powershell`, `cmd`, WSL shell или Docker shell хоста.
5. Стандартный Docker-контейнер не считать защищённой песочницей от произвольного вредоносного кода. Docker Desktop ECI — отдельная платная функция Business и зависит от backend; не рассчитывать на неё в бесплатном продукте.
6. Для MVP допускается отдельная VM, созданная пользователем для недоверенных вычислений, с **нулевыми host shared folders**, отдельной виртуальной сетью, snapshot-restore. Изоляция от host и локальной сети проверяется тестами; некоторые гипервизоры/настройки могут требовать поддержки пользователя.
7. Для network installs разрешается egress по узкому policy через контролируемый proxy; затем `no-egress` тестовая фаза. Отсутствие proxy-контроля — нельзя заявлять полную сетевую изоляцию.
8. Не предоставлять guest cloud credentials, SSH agent, Docker socket, host mount или clipboard integration.

## 4. Режимы

- `INSPECT_ONLY` — по умолчанию, нет code execution.
- `EXECUTE_ISOLATED` — только аттестованный VM worker и утверждённый план.
- `DEVELOPER_FIXTURE_TEST` — собственные синтетические приложения, могут запускаться в контролируемой CI среде, но не считаются доказательством достаточности sandbox.

## 5. Политика сетевого доступа

- Clone/metadata: GitHub allowlist только от доверенного контроллера, защита от SSRF/redirect/private CIDR для будущих URL schemes.
- Install: разрешённый список package registries при возможности и явное предупреждение о внешнем egress.
- Behavior: изоляция внешней сети; разрешены только guest-local endpoints.
- Нельзя заявлять «полностью без сети», если во время установки выполнялись dependency hooks с интернетом.

## 6. Ресурсы и восстановление

- Конкретные предельные лимиты configurable; начальные policy examples: CPU 2, RAM 2GB, disk 4GB, max wall time 10m/run, max output 20MB; значения проверить на реальных проектах.
- Cancel завершает guest workload, затем уничтожает/откатывает VM snapshot.
- Worker-controller ведёт журнал жизненного цикла, чтобы после собственного падения очистить orphan instances.
- По умолчанию не использовать данные пользователя внутри VM.

## 7. Блокирующие security tests

1. **host-file-read:** образец пытается читать недоступный путь Windows — отчёт не содержит данных.
2. **host-file-write:** попытка изменения файла на хосте не проходит.
3. **secret-access:** fake credential на host не появляется в worker.
4. **socket-access:** отсутствует доступ к Docker socket/agent sockets.
5. **network-egress:** внешний запрос в offline фазе отклоняется.
6. **local-network:** запрещён доступ к RFC1918/home LAN.
7. **fork-bomb/resource:** ограничения CPU/RAM/process/time срабатывают.
8. **symlink/path-traversal:** extractor не выходит за workspace root.
9. **log-XSS:** HTML/JS строки stdout не выполняются при открытии отчёта.
10. **log-secrets:** искусственный токен и приватные пути исключены из exported HTML/JSON.
11. **cancellation:** при cancel не остаётся дочернего процесса и persistent VM.
12. **renderer-failure:** повреждённый JSON/Unicode не нарушает границы доверия и не запускает код.

Каждый тест выполняется в изолированной тестовой лаборатории. Нельзя запускать потенциально разрушительные/нагрузочные фикстуры на host.

## 8. Принцип fail closed

Если изоляция не доказана, `worker.Attest` упал или невозможно ограничить сеть/ресурсы — `BLOCKED_SECURITY`. UX не должен скрывать это. `VERIFIED` не допускается при нарушении security policy, даже если приложение визуально работает.

## 9. Отчёт о безопасности

Отчёт фиксирует: `worker_kind`, `image_digest`, `policy_digest`, `network_mode`, `host_mounts=0`, `privileges`, `time_limits`, `attested=true/false`, `evidence`. Эти поля нельзя заполнять значениями по умолчанию без наблюдений.

## 10. Ответственность оператора

Пользователь подтверждает запуск недоверенного кода, но этот клик не снимает с продукта обязательства реализовать безопасное исполнение. Предупреждение в интерфейсе не заменяет изоляцию.
