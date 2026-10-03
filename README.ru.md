<div align="center">

<a id="top"></a>

# 🌐 Net Lattice

### Типизированная кроссплатформенная работа с сетью ОС на Rust

[![crates.io](https://img.shields.io/crates/v/net-lattice.svg?cacheSeconds=86400)](https://crates.io/crates/net-lattice)
[![docs.rs](https://img.shields.io/docsrs/net-lattice?cacheSeconds=86400)](https://docs.rs/net-lattice)
[![Downloads](https://img.shields.io/crates/d/net-lattice.svg?cacheSeconds=86400)](https://crates.io/crates/net-lattice)
[![CI](https://github.com/F000NKKK/net-lattice/actions/workflows/ci.yml/badge.svg)](https://github.com/F000NKKK/net-lattice/actions/workflows/ci.yml)
[![License: MPL 2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.99-lightgrey.svg)](Cargo.toml)

![Linux](https://img.shields.io/badge/Linux-supported-success)
![Windows](https://img.shields.io/badge/Windows-supported-success)
![macOS](https://img.shields.io/badge/macOS-supported-success)

🇺🇸 [English](README.md) | 🇷🇺 **Русский**

[Возможности](#-ключевые-возможности) • [Платформы](#-поддерживаемые-платформы) • [Установка](#-установка) • [Быстрый старт](#-быстрый-старт) • [Примеры](#-примеры) • [API](#api-overview) • [Решение проблем](#-решение-проблем)

</div>

---

## 📖 Обзор

**Net Lattice** — современная кроссплатформенная библиотека для Rust,
предназначенная для настройки и анализа сетевой конфигурации операционной
системы через единый строго типизированный API.

Операционные системы предоставляют доступ к сетевой конфигурации и
состоянию через совершенно разные, низкоуровневые и зачастую
платформо-специфичные интерфейсы: Linux Netlink, Windows IP Helper API,
BSD routing facilities в macOS и другие механизмы. Приложениям, которым
нужно анализировать или настраивать сеть — IP-адреса, маршруты,
интерфейсы, соседей и многое другое, — как правило, приходится либо
вызывать внешние утилиты через shell, либо парсить текстовый вывод, либо
писать и поддерживать отдельные платформо-специфичные интеграции.

Кроссплатформенные сетевые инструменты в экосистеме Rust фрагментированы.
Существующие решения зачастую платформо-специфичны, неполны или построены
на вызове системных утилит, таких как `ip`, `netsh` или `route`. Это
хрупко, сложно тестировать и не подходит для надёжного, production-grade
программного обеспечения для управления сетью. Net Lattice закрывает этот
пробел единым, хорошо спроектированным уровнем абстракции над нативными
сетевыми API ОС, чтобы потребителям никогда не приходилось иметь дело с
сырыми платформенными структурами, shell-командами или произвольным
парсингом строк.

### 🎯 Почему Net Lattice?

- **🔤 Строгая типизация вместо строк**: вы работаете с типизированными
  значениями Rust — адресами, префиксами, маршрутами, интерфейсами, — а не
  с сырыми строками или shell-командами.
- **🧩 Нативные API, а не подпроцессы**: Net Lattice обращается напрямую к
  платформенным сетевым API (Netlink, IP Helper API, route sockets), а не
  вызывает внешние CLI-инструменты.
- **🌍 Кроссплатформенность по замыслу**: единая поверхность API с
  платформо-специфичными реализациями, чтобы приложениям не приходилось
  делать особые случаи для каждой ОС.
- **🛡️ Корректность и безопасность прежде всего**: настройка сети —
  чувствительная область; библиотека затрудняет представление
  некорректных состояний. Наблюдаемое состояние и желаемое намерение — это
  разные типы, и каждое изменение возвращает свежее чтение после записи.
- **🧭 Запрашивай, а не предполагай**: флаги `Capability` во время работы
  говорят, что именно поддерживает подключённый backend, а
  неподдерживаемый запрос завершается типизированной ошибкой, а не молча
  делает меньше.
- **🌱 Постепенный, продуманный рост**: функциональность добавляется
  осознанно, с вниманием к дизайну API и долгосрочной поддерживаемости, а
  не поспешно, чтобы покрыть все мыслимые сценарии.

> **Статус:** `1.0` — текущая стабильная линия. Net Lattice предоставляет
> кроссплатформенный просмотр сети, изменение маршрутов, адресов, DNS,
> administrative state и MTU интерфейсов, статических записей ARP/NDP и
> native-firewall, inspectable планы mutation-операций, упорядоченное
> исполнение транзакций с cancellation, snapshots, compensation и фазовыми
> отчётами, декларативные desired-state/diff/apply и снапшоты
> `CurrentState` для всей системы на Linux, Windows и macOS.

## 🌟 Ключевые возможности

### Просмотр
- ✅ **Интерфейсы, адреса, маршруты, соседи (ARP/NDP) и DNS-резолверы** в
  виде типизированных значений
- ✅ **Типы IPv4/IPv6-адресов и префиксов**, не смешивающие два семейства
- ✅ **Снапшоты `CurrentState` для всей системы** одним вызовом

### Изменение
- ✅ **Маршруты, адреса интерфейсов и DNS-резолверы**: добавление,
  удаление и замена
- ✅ **Administrative state и MTU интерфейсов** через частичные патчи
  `InterfaceConfig`
- ✅ **Статические записи соседей ARP/NDP**
- ✅ **Управление native-firewall policy** (`FirewallProvider`/
  `FirewallMutator`) на Linux (nftables), Windows (WFP) и macOS (`pf`),
  интегрированное с `Mutation`, `DesiredState`, `Diff` и `ApplyPlan`

### Транзакции и декларативное состояние
- ✅ **Inspectable планы mutation-операций** для маршрутов, адресов, DNS и
  статических соседей
- ✅ **Упорядоченное исполнение планов** с cancellation, snapshots, явной
  compensation и фазовыми отчётами
- ✅ **Декларативное желаемое состояние**: `DesiredState`, чистый `Diff`,
  вычисляемый относительно `CurrentState`, чистый скомпилированный
  `ApplyPlan` и `Lattice::apply()`/`execute_apply_plan()` для его
  исполнения на backend'е

### Мониторинг
- ✅ **Уведомления об изменениях сети** с фильтрами по доменам и объектам
- ✅ **Bounded-доставка**: отстающий consumer получает `ResyncRequired`, а
  не неограниченный backlog
- ✅ **Опциональный runtime-agnostic async stream событий** (feature
  `async`)
- ✅ **Опциональный уровень `Addition`** для замен с более слабыми
  гарантиями (например, опроса) там, где у платформы нет нативного
  механизма

## 💻 Поддерживаемые платформы

| Возможность | Linux | Windows | macOS |
|---|:---:|:---:|:---:|
| Просмотр маршрутов | ✅ | ✅ | ✅ |
| Изменение маршрутов | ✅ | ✅ | ✅ |
| Просмотр интерфейсов | ✅ | ✅ | ✅ |
| Настройка administrative state/MTU интерфейсов | ✅ | ✅ | ✅ |
| Просмотр адресов интерфейсов | ✅ | ✅ | ✅ |
| Изменение адресов интерфейсов | ✅ | ✅ | ✅ |
| Просмотр таблицы соседей | ✅ | ✅ | ✅ |
| Изменение статических записей соседей (ARP/NDP) | ✅ | ✅ | ✅ |
| Просмотр DNS-резолвера | ✅ | ✅ | ✅ |
| Изменение DNS-резолвера | ✅ | ✅ | ✅ |
| Управление native-firewall policy | ✅ | ✅ | ✅ |
| Мониторинг изменений маршрутов/интерфейсов/адресов | ✅ | ✅ | ✅ |
| Мониторинг изменений соседей | ✅ | ⚠ | ✅ |
| Мониторинг всех доменов (`watch()`) | ✅ | — | ✅ |
| Async-мониторинг маршрутов/интерфейсов/адресов | ✅ | ✅ | ✅ |
| Async-мониторинг соседей/всех доменов | ✅ | — | ✅ |

✅ native `Capability`, — не поддерживается, ⚠ нет native `Capability`, но
есть опциональная замена на уровне `Addition` с более слабыми гарантиями —
см. [уровень Addition](#уровень-addition) ниже.

| Платформа | Backend-крейт | Нативные механизмы | Firewall |
|---|---|---|---|
| **Linux** | `net-lattice-backend-linux` | Netlink, `/etc/resolv.conf` | nftables |
| **Windows** | `net-lattice-backend-windows` | IP Helper API | Windows Filtering Platform (WFP) |
| **macOS** | `net-lattice-backend-darwin` | BSD routing sockets (`PF_ROUTE`), `getifaddrs`, ioctl | `pf` |

Фасад выбирает backend для целевой ОС автоматически. CI собирает,
проверяет линтерами и тестирует workspace на нативных GitHub-раннерах
Linux, Windows и macOS (без кросс-компиляции) тулчейном MSRV и на каждом
из них запускает privileged-тесты backend'а и фасада от root/
Administrator.

### Уровень Addition

`Addition` — отдельный от `Capability` тип флагов: backend сообщает о нём
через `AdditionProvider::additions()`, только если у него нет никакого
native-механизма для соответствующей возможности вообще, а запрос идёт
через `Lattice::watch_with_additions`, а не `watch`/`watch_filtered`.
`Addition` никогда не отображается обычной галочкой `Capability` ни в
одной из таблиц на этой странице.

| Addition | Linux | Windows | macOS |
|---|:---:|:---:|:---:|
| Мониторинг изменений соседей через опрос (`NEIGHBOR_MONITORING_POLLING`) | — | ✅ | — |

У Linux и macOS есть native `Capability::NEIGHBOR_MONITORING` (✅ в
таблице выше), поэтому ни один из них не сообщает об этом `Addition` —
поведение `AdditionProvider` по умолчанию (`additions()` → пусто)
остаётся без изменений на обоих. Windows сообщает
`Addition::NEIGHBOR_MONITORING_POLLING`: опциональную замену, которая
синтезирует события `Added`/`Removed`/`Changed` из последовательных
опросов таблицы соседей, с более слабыми гарантиями
латентности/упорядоченности/коалесценции/затрат ресурсов, чем у native
доставки событий (полное описание гарантии и обоснование конвенции — в
разделах [ARCHITECTURE.ru.md](ARCHITECTURE.ru.md) «Platform Support
Matrix and Gaps» и «Гарантии доставки событий»). Бит `additions`, не
заявленный `AdditionProvider::additions()` подключённого backend'а, молча
не активируется, а не приводит к ошибке — так же, как и `Capability`,
следуя принципу «запрашивай, а не предполагай»; поэтому вызывающий код
может безусловно запросить `NEIGHBOR_MONITORING_POLLING` и просто не
получить addition-событий на backend'е, который её не заявляет.

## 📦 Установка

```toml
[dependencies]
# Synchronous API
net-lattice = "1.0"

# Plus the runtime-independent async event stream (`Lattice::watch_async`)
net-lattice = { version = "1.0", features = ["async"] }
```

`async` — единственная feature. Она добавляет watcher в виде
`futures::Stream` и не выбирает async-runtime. На Linux для сборки также
нужны dev-пакеты `libmnl` и `libnftnl`; см. [настройку Linux](#linux).

## 🎓 Быстрый старт

### Просмотр системы

```rust,no_run
use net_lattice::{Lattice, Result};

fn main() -> Result<()> {
    let lattice = Lattice::connect()?;
    for interface in lattice.interfaces()? {
        println!("{interface:?}");
    }

    // Or read routes, interfaces, neighbors, addresses, DNS, and firewall
    // rules together in one call.
    let state = lattice.current_state()?;
    println!("{} routes, {} interfaces", state.routes.len(), state.interfaces.len());
    Ok(())
}
```

### Отслеживание изменений

```rust,no_run
use net_lattice::monitoring::EventFilter;
use net_lattice::{Capability, Lattice, Result};

fn main() -> Result<()> {
    let lattice = Lattice::connect()?;
    if lattice.supports(Capability::ROUTE_MONITORING) {
        let events = lattice.watch_filtered(EventFilter::none().routes())?;
        loop {
            println!("{:?}", events.recv()?); // blocks until the next event
        }
    }
    Ok(())
}
```

С feature `async` метод `Lattice::watch_async(filter)` возвращает те же
события в виде `futures::Stream`.

## 🧠 Основные понятия

### Снапшоты всей системы

Net Lattice собирает снапшоты `CurrentState` для всей системы:
`CurrentState` в `net-lattice-model` объединяет маршруты, интерфейсы,
соседей, адреса интерфейсов и конфигурацию DNS;
`net-lattice-platform::SnapshotProvider` описывает контракт сборки;
`Lattice::current_state()` реализует его, завершаясь с первой же ошибкой
чтения без частичного результата. Ни одному backend-крейту не требуется
изменение — реализация написана один раз для `Lattice<B>`. Полный,
датированный по версиям список изменений, включая доменные
reexport-модули `net_lattice::model`/`mutation`/`monitoring` (корень
крейта больше не реэкспортирует доменные типы напрямую), см. в
[CHANGELOG.md](CHANGELOG.md).

### Декларативное желаемое состояние

Net Lattice также предоставляет декларативную модель, inspectable diff и
скомпилированный, исполняемый apply-план:

- `DesiredState` (`net-lattice-model`, также доступен как
  `net_lattice::mutation::DesiredState`) — whole-system-агрегат,
  формируемый вызывающей стороной и параллельный `CurrentState`: по одному
  полю-`Option` на домен, собирается через `DesiredState::empty()` и
  подомённые builder-методы `with_*`, без собственной зависимости от
  backend'а.
- `Diff::compute(&CurrentState, &DesiredState) -> Diff`
  (`net_lattice::mutation::Diff`) вычисляет чистую, side-effect-free
  разницу между ними: маршруты, соседи и адреса — как naturally-keyed
  множества add/remove(/change), интерфейс — как patch-diff по полям, DNS и
  firewall policy — как сравнение целого значения. `Diff::compute` не
  выполняет I/O и не вызывает ни один provider/backend метод.
- `ApplyPlan::compile(&Diff) -> ApplyPlan`
  (`net_lattice::mutation::ApplyPlan`) — точно так же чистая и
  side-effect-free функция, компилирующая diff в упорядоченный список
  `ApplyStep` (см. раздел State Model в [архитектуре](ARCHITECTURE.ru.md)
  о том, как add/remove-пара маршрутов с одним destination компилируется в
  один шаг `ReplaceRoute` вместо двух независимых).
- `Lattice::execute_apply_plan()` исполняет этот план на подключённом
  backend'е с capability-aware отклонением, порядком замены маршрута по
  backend'у и обязательной read-after-write верификацией.
- Тонкое удобство `Lattice::apply(&DesiredState, &mut ExecutionOptions)`
  объединяет все четыре шага (`current_state` → `Diff::compute` →
  `ApplyPlan::compile` → `execute_apply_plan`) для вызывающих, которым не
  нужно инспектировать скомпилированный план заранее.

Рабочий пример только для чтения — `declarative_diff`; полный пример
применения — `declarative_apply`.

### Контракты изменений

- **Намерение отделено от наблюдения.** `InterfaceConfig` не
  переиспользует observed `Interface`: он выбирает один интерфейс и
  запрашивает одно или оба поддерживаемых свойства. Создание адреса
  принимает `NewInterfaceAddress` и возвращает результирующий наблюдаемый
  `InterfaceAddress`; замена конфигурации резолвера принимает
  `NewDnsConfig` и возвращает результирующий наблюдаемый `DnsConfig`.
- **Патч интерфейса может примениться частично.** Для каждого свойства
  проверяйте `Capability::INTERFACE_ADMIN_STATE` и
  `Capability::INTERFACE_MTU`. Native backend может применять свойства
  разными вызовами, поэтому ошибка combined patch может означать partial
  application; перечитайте состояние и при необходимости используйте явный
  compensator executor'а.
- **Статические соседи защищены.** Создание статической записи соседа
  принимает `StaticNeighbor` (отдельный от `NeighborEntry` тип: без
  синтезированного ID или наблюдаемого состояния, MAC-адрес обязателен) и
  возвращает результирующий наблюдаемый `NeighborEntry`; сначала проверяйте
  `Capability::NEIGHBOR_MUTATION`. Удаление присутствующей, но не
  `Permanent` (динамически изученной) записи отклоняется с
  `Error::InvalidState`, а не молча её вытесняет.
- **Изменение статических соседей — не мониторинг.** Это native-вызов
  запрос/ответ (`RTM_NEWNEIGH`/`RTM_DELNEIGH`,
  `CreateIpNetEntry2`/`DeleteIpNetEntry2`, `RTM_ADD` через `PF_ROUTE`), а
  не подписка на события. `Capability::NEIGHBOR_MUTATION` и
  `Capability::NEIGHBOR_MONITORING` — независимые capabilities: поддержка
  изменения не означает native-уведомления об изменениях таблицы соседей.
  Перед подпиской на изменения таблицы соседей проверяйте
  `Capability::NEIGHBOR_MONITORING` (строка «Мониторинг изменений соседей»
  выше); сейчас она объявлена на Linux и macOS, но не на Windows — см.
  [уровень Addition](#уровень-addition) про опциональную замену через опрос
  для Windows.
- **Планы — это данные.** `MutationPlan` описывает семантику операций, а
  `Lattice::execute_plan` исполняет план через единый `ExecutionOptions` с
  runtime-проверками, cancellation на границах операций, типизированными
  snapshots, явной compensation и фазовыми отчётами.
- **Файлы резолвера могут перегенерироваться.** Менеджеры резолвера в Unix
  могут позже перегенерировать `/etc/resolv.conf`; если нужна
  персистентность, используйте интерфейс конфигурации менеджера-владельца.

### Доставка событий

`EventFilter` сочетает селекторы доменов (`routes()`) и объектов
(`route(route_id)`); каждый backend применяет filter до помещения обычного
события в очередь. Перед watching проверяйте capability каждого выбранного
filter-домена; `Capability::MONITORING` означает, что доступны все текущие
домены.

Потоки событий bounded. Если consumer не успевает обрабатывать события,
watcher запоминает и выдаёт `Event::ResyncRequired { .. }` перед
последующим обычным событием, а не сохраняет неограниченный backlog.
Прежде чем полагаться на последующие события, перечитайте состояние
затронутого provider.

Capabilities мониторинга описывают фактическую native-доставку. Netlink в
Linux и PF_ROUTE в macOS доставляют изменения маршрутов, интерфейсов,
адресов интерфейсов и соседей, поэтому публикуют aggregate
`Capability::MONITORING`. IP Helper в Windows доставляет только маршруты,
интерфейсы и unicast-адреса: используйте соответствующую capability
`ROUTE_MONITORING`, `INTERFACE_MONITORING` или `ADDRESS_MONITORING` вместе
с `watch_filtered`. Запрос neighbors или всех доменов в Windows
завершается `Error::Unsupported` до native-регистрации — выбранный домен
никогда не теряется молча.

```rust,no_run
use net_lattice::monitoring::EventFilter;
use net_lattice::{Capability, Lattice, Result};

fn main() -> Result<()> {
    let lattice = Lattice::connect()?;
    let Some(route) = lattice.routes()?.into_iter().next() else {
        return Ok(());
    };
    let route_events = EventFilter::none().route(route.id);
    if lattice.supports(Capability::ROUTE_MONITORING) {
        let watcher = lattice.watch_filtered(route_events)?;
        let _ = watcher;
    }
    Ok(())
}
```

Feature `async` в Net Lattice использует и реэкспортирует реализацию
`EventStream` из `net-lattice-async`; приложению достаточно включить эту
feature фасада.

## 📚 Примеры

Запускаемые исходники в
[`crates/net-lattice/examples`](crates/net-lattice/examples) покрывают
каждую доступную сейчас операцию фасада. Примеры только для чтения
безопасны для запуска; примеры изменений требуют явного opt-in через
переменную окружения и повышенных прав ОС.

| Сценарий | Запускаемый пример | Покрываемый фасад/API |
|---|---|---|
| Полное состояние только для чтения | [`snapshot`](crates/net-lattice/examples/snapshot.rs) | `capabilities`, `interfaces`, `routes`, `addresses`, `dns_config`, `neighbors` |
| Выбор возможностей во время работы | [`capabilities`](crates/net-lattice/examples/capabilities.rs) | `capabilities`, `supports`, все текущие флаги `Capability` |
| Точечное чтение маршрутов | [`list_routes`](crates/net-lattice/examples/list_routes.rs) | `routes` |
| Bounded синхронная доставка | [`sync_monitor`](crates/net-lattice/examples/sync_monitor.rs) | capability-gated `watch_filtered`, `recv_timeout`, `Event::ResyncRequired` |
| Фильтрация доменов и объектов | [`filtered_monitor`](crates/net-lattice/examples/filtered_monitor.rs) | `watch_filtered`, все domain/object selectors `EventFilter` |
| Нативная async-доставка | [`async_monitor`](crates/net-lattice/examples/async_monitor.rs) | capability-gated `watch_async`, `EventStream` |
| Жизненный цикл адреса | [`address_assignment`](crates/net-lattice/examples/address_assignment.rs) | `NewInterfaceAddress`, `add_address`, `remove_address` |
| Жизненный цикл маршрута | [`route_mutation`](crates/net-lattice/examples/route_mutation.rs) | `RouteConfig`, `add_route`, `remove_route` |
| Жизненный цикл статического соседа | [`static_neighbor_mutation`](crates/net-lattice/examples/static_neighbor_mutation.rs) | `StaticNeighbor`, `Capability::NEIGHBOR_MUTATION`, `add_static_neighbor`, `remove_static_neighbor` |
| Замена конфигурации резолвера | [`dns_mutation`](crates/net-lattice/examples/dns_mutation.rs) | `NewDnsConfig`, `set_dns_config`, read-after-write verification |
| Настройка интерфейса | [`interface_configuration`](crates/net-lattice/examples/interface_configuration.rs) | `InterfaceConfig`, `DesiredAdminState`, capability checks, `set_interface_config` |
| Политика firewall | [`firewall_policy`](crates/net-lattice/examples/firewall_policy.rs) | `FirewallPolicy`, `Capability::FIREWALL_MUTATION`, `set_firewall_policy`, `firewall_rules` |
| Просмотр mutation | [`mutation_plan`](crates/net-lattice/examples/mutation_plan.rs) | все варианты `Mutation`, `Mutation::semantics`, `MutationPlan` |
| Декларативный diff (только чтение) | [`declarative_diff`](crates/net-lattice/examples/declarative_diff.rs) | `DesiredState`, `Diff`, `Lattice::diff`, `RouteChange` |
| Декларативное применение | [`declarative_apply`](crates/net-lattice/examples/declarative_apply.rs) | `DesiredState`, `ApplyPlan`, `Lattice::apply`, `ApplyPlanReport` |

Запуск: `cargo run -p net-lattice --example <name>`. Для `async_monitor`
добавьте `--features async`. Linux-backend также содержит пример
[`kill_switch`](crates/net-lattice-backend-linux/examples/kill_switch.rs):
fail-closed политику default-deny на основе общего API firewall.

Краткое руководство для приложений находится в
[`README` крейта `net-lattice`](crates/net-lattice/README.md). Остальные
руководства из [таблицы крейтов](#крейты-воркспейса) описывают прямое
использование библиотечных и backend-крейтов без дублирования этих
контрактов здесь.

## 🔧 Настройка под платформу

API только для чтения обычно не требуют привилегий. Изменениям нужны
права, перечисленные ниже. Capabilities во время работы описывают
реализованные возможности, а не гарантию того, что текущему процессу это
разрешено.

### Linux

```bash
sudo apt-get install libmnl-dev libnftnl-dev   # build dependency (Debian/Ubuntu)
sudo setcap cap_net_admin+ep ./your-app        # or run with sudo
```

- Управление firewall линкуется с `libmnl` и `libnftnl` через крейт
  `nftnl`; подпроцесс `nft` никогда не запускается. Разделяемые
  runtime-библиотеки должны быть там, где запускается бинарник.
- Изменения интерфейсов, адресов, маршрутов, статических соседей и
  firewall требуют `CAP_NET_ADMIN`. Замена конфигурации резолвера также
  зависит от прав файловой системы и менеджера резолвера на хосте.

### Windows

- Изменение интерфейсов, маршрутов, адресов, статических соседей или DNS
  может требовать прав администратора и зависит от политик адаптера и
  системы; замена политики firewall требует прав администратора.
- Кроме обычного тулчейна с Windows SDK, для сборки ничего не нужно.
- У IP Helper нет native-обратного вызова для изменений таблицы соседей;
  см. [уровень Addition](#уровень-addition) про замену через опрос.

### macOS

- Изменения могут требовать root или особых системных entitlements и
  могут взаимодействовать с сетевыми сервисами конфигурации macOS; замена
  политики firewall требует root.
- Управление firewall использует прямые вызовы `ioctl` на `/dev/pf` и
  ограничено anchor'ом `pf` с именем `net_lattice`; пакеты для сборки не
  нужны.

<a id="api-overview"></a>

## 🛠️ Обзор API

| Элемент | Назначение |
|------|---------|
| `Lattice::connect()` | Подключение к нативному backend'у текущей ОС |
| `interfaces` / `routes` / `addresses` / `neighbors` / `dns_config` | Чтение наблюдаемого состояния |
| `current_state()` | Снапшот `CurrentState` всей системы |
| `add_route` / `remove_route` | Изменение маршрутов (`RouteConfig`) |
| `add_address` / `remove_address` | Изменение адресов интерфейсов |
| `set_dns_config` | Замена конфигурации резолвера (`NewDnsConfig`) |
| `set_interface_config` | Administrative state и MTU (`InterfaceConfig`) |
| `add_static_neighbor` / `remove_static_neighbor` | Статические записи ARP/NDP (`StaticNeighbor`) |
| `firewall_rules` / `set_firewall_policy` / `clear_firewall_policy` | Политика native-firewall |
| `validate_plan` / `execute_plan` | Упорядоченное исполнение `MutationPlan` |
| `diff` / `apply` / `validate_apply_plan` / `execute_apply_plan` | Декларативное желаемое состояние |
| `capabilities` / `supports` | Флаги `Capability` во время работы |
| `watch` / `watch_filtered` / `watch_with_additions` | Синхронные bounded-получатели событий |
| `watch_async` | Async `EventStream` (feature `async`) |

Доменные типы доступны через модули `net_lattice::model`, `mutation` и
`monitoring`; модуль `backend` собирает трейты, которые реализует
сторонний backend.

### Замороженная поверхность 1.0

Следующая поверхность — замороженный публичный API версии 1.0, описанный в
[архитектуре](ARCHITECTURE.ru.md) — проверена privileged CI-задачами на
Linux, Windows и macOS:

- `net-lattice-core`, `net-lattice-ip`
- модули `route`, `mac`, `interface`, `dns`, `neighbor`, `ifaddr`, `event` и `mutation` в `net-lattice-model`; `NewInterfaceAddress`, `NewDnsConfig` и `StaticNeighbor` выражают намерение изменения отдельно от наблюдаемого состояния
- `RouteProvider`, `RouteMutator`, `InterfaceProvider`, `InterfaceMutator`, `DnsProvider`, `DnsMutator`, `NeighborProvider`, `NeighborMutator`, `AddressProvider`, `AddressMutator`, `CapabilityProvider`, синхронные `EventProvider`/bounded `EventReceiver` и опциональная async-поддержка мониторинга в `net-lattice-platform`
- `net-lattice-async`, предоставляющий единый runtime-agnostic тип `EventStream`
- фасад `net-lattice`, включая `Lattice::add_address()`, `Lattice::remove_address()`, `Lattice::set_dns_config()`, `Lattice::set_interface_config()`, `Lattice::add_static_neighbor()`, `Lattice::remove_static_neighbor()`, `Lattice::capabilities()`, `Lattice::supports()`, `Lattice::watch()`, `Lattice::watch_filtered()`, `Lattice::execute_plan()`, `Lattice::execute_apply_plan()`, `Lattice::apply()` и feature-gated `Lattice::watch_async()`

Это даёт реальное управление маршрутами, IP-адресами интерфейсов и
статическими записями ARP/NDP, desired-патчи `InterfaceConfig` для
administrative state и MTU, просмотр интерфейсов, просмотр и изменение
DNS-конфигурации резолвера, чтение таблиц соседей (ARP/NDP), inspectable
планы mutation-операций, упорядоченное исполнение транзакций и
bounded-мониторинг сетевых изменений на Linux, Windows и macOS.

### Крейты воркспейса

Workspace разделён на отдельные крейты. У каждого крейта есть собственный
README с назначением и примером использования:

| Крейт | Назначение |
|---|---|
| [`net-lattice`](crates/net-lattice/README.md) | Публичный фасад и transaction executor |
| [`net-lattice-model`](crates/net-lattice-model/README.md) | Observed state, intent, события и mutation plans |
| [`net-lattice-platform`](crates/net-lattice-platform/README.md) | Provider- и capability-контракты |
| [`net-lattice-core`](crates/net-lattice-core/README.md) | Общие ошибки, результаты и ID |
| [`net-lattice-ip`](crates/net-lattice-ip/README.md) | IPv4/IPv6 адреса и сети |
| [`net-lattice-async`](crates/net-lattice-async/README.md) | Runtime-independent адаптер event stream |
| [`net-lattice-backend-linux`](crates/net-lattice-backend-linux/README.md) | Linux Netlink backend |
| [`net-lattice-backend-windows`](crates/net-lattice-backend-windows/README.md) | Windows IP Helper backend |
| [`net-lattice-backend-darwin`](crates/net-lattice-backend-darwin/README.md) | macOS BSD/PF_ROUTE backend |

## 🗺️ Дорожная карта

`1.0` — текущая стабильная линия: полная кроссплатформенная поддержка
inspection, monitoring, imperative mutation, упорядоченных транзакций,
декларативного apply и управления native-firewall policy (imperative и
транзакционное), каждая с privileged regression coverage на Linux,
Windows и macOS. Датированную историю того, как это появилось, см. в
[CHANGELOG.md](CHANGELOG.md), а замороженную публичную поверхность API — в
[ARCHITECTURE.ru.md](ARCHITECTURE.ru.md).

Запланировано на 2.0+ — каждый пункт достаточно велик, чтобы требовать
отдельного архитектурного прохода, ни один не является prerequisite для
1.0:

| Домен | Содержание |
|---|---|
| VLAN | модель read/intent/mutation для tagged-интерфейсов, единая для всех трёх backend'ов |
| VRF | модель изоляции таблиц маршрутизации и привязка по backend'ам |
| Namespaces | изоляция process/network namespace — асимметрична между Linux/Windows/macOS, требует отдельного архитектурного прохода до начала реализации |

Управление tunnel-интерфейсами полностью вне зоны ответственности этого
репозитория; см. [tunnel-lattice](https://github.com/F000NKKK/tunnel-lattice)
в [таблице экосистемы](#-экосистема-lattice) ниже.

### Не входит в задачи проекта

- Net Lattice не является заменой полноценным демонам управления сетью
  (например, NetworkManager, systemd-networkd).
- Net Lattice не ставит целью предоставление интерфейса командной строки
  или графического интерфейса в составе основной библиотеки.
- Net Lattice не ставит целью парсинг или оборачивание вывода внешних
  CLI-инструментов в качестве долгосрочной стратегии.
- Net Lattice не ставит целью поддержку всех мыслимых сетевых протоколов
  или вендорских расширений с первого дня.

## 📖 Документация

- **Справочник API**: [docs.rs/net-lattice](https://docs.rs/net-lattice)
- **Архитектура**: [ARCHITECTURE.ru.md](ARCHITECTURE.ru.md)
- **Журнал изменений**: [CHANGELOG.md](CHANGELOG.md)
- **Поддержка и безопасность**: [SUPPORT.md](SUPPORT.md), [SECURITY.md](SECURITY.md)

## 🐛 Решение проблем

<details>
<summary><b><code>PermissionDenied</code> при изменении сети</b></summary>

Изменениям нужен `CAP_NET_ADMIN` на Linux (`sudo` или
`sudo setcap cap_net_admin+ep ./your-app`), права администратора на
Windows или root на macOS. Вызовы только для чтения обычно не требуют
привилегий. См. [настройку под платформу](#-настройка-под-платформу).
</details>

<details>
<summary><b>Сборка на Linux не находит <code>libmnl</code> или <code>libnftnl</code></b></summary>

Linux-backend линкуется с `libmnl` и `libnftnl` для управления firewall
через nftables. Установите dev-пакеты, например
`sudo apt-get install libmnl-dev libnftnl-dev` на Debian/Ubuntu.
</details>

<details>
<summary><b><code>Unsupported</code> при подписке на соседей в Windows</b></summary>

У Windows IP Helper нет native-обратного вызова для изменений таблицы
соседей, поэтому `watch()` и запросы `watch_filtered` с доменом соседей
возвращают `Error::Unsupported`. Подписывайтесь на маршруты, интерфейсы
или адреса по отдельности либо запросите
`Addition::NEIGHBOR_MONITORING_POLLING` через
`Lattice::watch_with_additions`.
</details>

<details>
<summary><b>Watcher выдаёт <code>ResyncRequired</code></b></summary>

Consumer отстал, и bounded-очередь потеряла события. Перечитайте
состояние затронутого provider (например, `lattice.routes()`), прежде чем
полагаться на последующие события.
</details>

<details>
<summary><b><code>InvalidState</code> при удалении статического соседа</b></summary>

Запись существует, но не `Permanent`: она изучена динамически. Net Lattice
отказывается вытеснять её в качестве побочного эффекта запроса на
удаление статической записи.
</details>

<details>
<summary><b>Патч интерфейса завершился ошибкой, но что-то изменилось</b></summary>

Патч, запрашивающий и MTU, и administrative state, может отправляться
отдельными native-вызовами, поэтому после ошибки одно из свойств может
остаться применённым. Перечитайте интерфейс и, если важно восстановление,
выполняйте изменение через `execute_plan` с явным compensator.
</details>

<details>
<summary><b>Изменения DNS на Linux или macOS позже откатываются</b></summary>

Менеджер резолвера может перегенерировать `/etc/resolv.conf`. Для
персистентных изменений используйте интерфейс конфигурации
менеджера-владельца.
</details>

## 🌐 Экосистема Lattice

Net Lattice — первый крейт в более широком семействе Lattice:
композируемых кроссплатформенных Rust-библиотек для сети. Остальные
крейты проектируются так, чтобы дополнять Net Lattice, а не дублировать
его; текущий статус смотрите в каждом репозитории.

| Крейт | Назначение |
|---|---|
| [net-lattice](https://github.com/F000NKKK/net-lattice) | Инспекция и настройка сетевого стека ОС (маршруты, DNS, интерфейсы) |
| [tunnel-lattice](https://github.com/F000NKKK/tunnel-lattice) | TUN/TAP туннельные интерфейсы |
| [dns-lattice](https://github.com/F000NKKK/dns-lattice) | Программируемый DNS control plane |
| [flow-lattice](https://github.com/F000NKKK/flow-lattice) | Компилятор политик: правила в платформенно-нейтральные сетевые планы |
| [sdk-lattice](https://github.com/F000NKKK/sdk-lattice) | Прикладной SDK, объединяющий крейты выше |

Направление зависимостей между репозиториями и границы API фиксируются в
архитектурных документах каждого репозитория по мере проработки.

## 🙏 Участие в разработке

Вклад в проект приветствуется. См. [CONTRIBUTING.md](CONTRIBUTING.md) для
рекомендаций, [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) для правил
поведения в сообществе и [SECURITY.md](SECURITY.md) для сообщения о
проблемах безопасности.

```bash
git clone https://github.com/F000NKKK/net-lattice.git
cd net-lattice
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features                        # unprivileged tests
sudo -E cargo test -p net-lattice-backend-linux -- --ignored   # privileged, Linux
```

Privileged-тесты помечены `#[ignore]` в обычных запусках и восстанавливают
изменённое состояние на каждом пути выхода.

## 📄 Лицензия

Net Lattice распространяется под лицензией
[Mozilla Public License 2.0](LICENSE) (`MPL-2.0`).

## 🌟 Благодарности

- [`rtnetlink`](https://github.com/rust-netlink/rtnetlink) для Linux
  Netlink, а также [`nftnl`](https://github.com/mullvad/nftnl-rs) и
  [`mnl`](https://github.com/mullvad/mnl-rs) от Mullvad для nftables
- Крейт [`windows`](https://github.com/microsoft/windows-rs) для привязок
  к IP Helper и WFP
- [`libc`](https://github.com/rust-lang/libc), `bitflags` и экосистема
  async в Rust (`futures`, Tokio)

---

<div align="center">

**[⬆ Наверх](#top)**

Часть сетевого стека Lattice

</div>
