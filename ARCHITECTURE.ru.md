# Архитектура

**Языки**

🇺🇸 [English](ARCHITECTURE.md) | 🇷🇺 **Русский**

Этот документ описывает структуру workspace Net Lattice и принципы дизайна,
лежащие в её основе. План поэтапной поставки ниже реализован вплоть до
строки 0.22 (firewall) и строки 1.0 включительно (аудит заморозки публичного
API стадии 0.21, закрывающий 1.0, завершён); только строки доменов Capability
после 1.0 (VLAN, VRF, namespaces) описывают ещё не реализованную,
планируемую работу. См. [CHANGELOG.md](CHANGELOG.md) и
[README.ru.md](README.ru.md) для датированной записи о том, что уже вышло.

Net Lattice предоставляет, и privileged CI на Linux/Windows/macOS проверяет:
`net-lattice-core` и `net-lattice-ip`; модули `route`, `interface`, `dns`,
`neighbor`, `ifaddr` и `mutation` в `net-lattice-model`;
`RouteProvider`/`RouteMutator`, `InterfaceProvider`, `InterfaceMutator`,
`DnsProvider`, `DnsMutator`, `NeighborProvider`, `NeighborMutator`,
`AddressProvider`, `AddressMutator`, `CapabilityProvider`, синхронный
`EventProvider`, feature-gated `TokioEventProvider` и object/domain selectors
`EventFilter` в `net-lattice-platform`; просмотр и нативное изменение
маршрутов, адресов интерфейсов, DNS и соседей (ARP/NDP); inspectable mutation
plans; упорядоченный executor транзакций с runtime-preflight, cancellation на
границах операций, типизированными snapshots, явной compensation и фазовыми
отчётами; а также снапшоты `CurrentState` для всей системы через
`net-lattice-platform::SnapshotProvider`. `InterfaceConfig` и
`DesiredAdminState` описывают intent интерфейса отдельно от наблюдаемого
`Interface`; `InterfaceMutator` применяет capability-gated патчи
administrative state и MTU с read-after-write наблюдением во всех встроенных
backend'ах. Нативный мониторинг событий реализован в
`net-lattice-backend-linux`, `net-lattice-backend-windows`,
`net-lattice-backend-darwin`, crate потока событий `net-lattice-async` и
feature-gated async-фасад. Capabilities мониторинга зависят от домена:
aggregate-бит `MONITORING` означает native-путь доставки для каждого текущего
домена, а filtered watch требует выбранный бит route/interface/neighbor/address.
В Windows нет native callback изменений соседей, поэтому neighbor и
all-domain subscriptions отклоняются. Полный список этапов см. в таблице
плана поэтапной поставки ниже, а подробности по каждому релизу — в
[CHANGELOG.md](CHANGELOG.md)/[README.ru.md](README.ru.md).

## Руководящий принцип

Net Lattice разделяет два аспекта, которые легко перепутать в кроссплатформенном
сетевом коде:

1. **Model (модель)** — строго типизированные представления сетевых понятий
   (IP-адреса, маршруты, интерфейсы, конфигурация DNS, ...), не имеющие
   никакой зависимости от операционной системы.
2. **Backend (бэкенд)** — платформо-специфичный код, читающий и записывающий
   реальное состояние ОС (Linux Netlink, Windows IP Helper API, macOS BSD
   route sockets), производя и потребляя типы модели.

Зависимости всегда направлены от backend к model, никогда наоборот. Модель
никогда не должна знать о существовании Linux, Windows или macOS.

## Граница крейта vs. граница модуля

Понятие получает **собственный крейт** только тогда, когда есть конкретная
причина выделить его отдельно: потенциал независимого переиспользования вне
Net Lattice, отдельный темп релизов или реальный случай самостоятельной публикации
на crates.io. Всё остальное — **модуль** внутри общего крейта.

Применяя этот критерий:

- **IP-адреса и сети** (`IPv4Address`, `IPv6Address`, `Network`, `Prefix`) —
  реальный кандидат на самостоятельное использование: потребителю может
  понадобиться типизированный парсинг IP без остальной части Net Lattice. Это
  оправдывает отдельный крейт.
- **MAC-адреса**, **маршруты**, **интерфейсы**, **записи соседей (ARP/NDP)**
  и **конфигурация DNS** не имеют случая независимого переиспользования: они
  всегда используются вместе, меняются вместе и бессмысленны без остальной
  части сетевой модели. Они живут как модули внутри одного крейта модели,
  а не как отдельные крейты.

Если модуль позже наберёт достаточно внутренней сложности, чтобы оправдать
независимое версионирование (например, если конфигурация DNS обрастёт полной
реализацией резолвера), его можно будет выделить в отдельный крейт в этот
момент. Это некритичный рефакторинг workspace, а не ранняя обязанность.

## Структура Workspace

```text
net-lattice-core          Error, Result, ID types
net-lattice-ip            IPv4/IPv6 addresses, networks, prefixes
net-lattice-model         mac, route, interface, neighbor, dns, event, mutation
    зависит от: net-lattice-core, net-lattice-ip
net-lattice-platform      Generic provider traits, Capability
    зависит от: net-lattice-core; никогда от net-lattice-model
net-lattice-async         Runtime-independent event stream adapter
    зависит от: net-lattice-core, net-lattice-platform
net-lattice-backend-*     Native Linux, Windows и macOS implementations
    зависят от: core, ip, model, platform
net-lattice               Public facade и выбор backend по умолчанию
    зависит от: core, ip, model, platform, target backend, optional async
```

`net-lattice-core` и `net-lattice-ip` — независимые foundational-крейты.
`net-lattice-model` и `net-lattice-platform` — sibling-слои, а не цепочка
зависимостей. `net-lattice-platform` не зависит ни от чего, что описывает, что такое
маршрут или интерфейс на самом деле — он знает только, что backend производит
*что-то*, и оставляет решение о том, что это "что-то" есть, тому, кто
реализует или потребляет trait. `net-lattice-model`, в свою очередь, понятия не
имеет о существовании `net-lattice-platform`. Ни один из них не может превратиться
в ситуацию `if linux { ... } else if windows { ... }`, потому что ни у одного
нет достаточно информации о домене другого, чтобы это сделать. См. раздел
`net-lattice-platform` ниже о том, как это выражено конкретно.

### `net-lattice-core`

Базовые типы без собственной сетевой семантики: `Error`, `Result<T>`, типы ID
и общие traits, используемые во всём workspace. Никакой зависимости от ОС,
никаких сетевых типов.

**Типы ID — это один generic-тип, а не отдельная структура на каждый доменный
объект.** Вместо определения `RouteId`, `InterfaceId`, `NeighborId`, ... как
независимых структур, `net-lattice-core` определяет один phantom-типизированный
`Id<T>`, и каждый домен получает алиас типа (`type InterfaceId = Id<Interface>;`).
Это ничего не стоит дополнительно определить и превращает целый класс ошибок
в ошибку компиляции вместо runtime-бага: передача `RouteId` там, где ожидается
`InterfaceId`, не компилируется, вместо того чтобы молча искать не тот объект.
Точная форма `Id<T>` — деталь API-дизайна для черновика Stage 0.1; этот
документ фиксирует лишь то, что ID — это один общий механизм, а не N
рукописных похожих друг на друга структур.

`Id<T>` обязан иметь стабильное, не зависящее от `T` сериализованное
представление (например, сериализуется как своё внутреннее значение, а не
как структура с phantom-маркером) с того момента, как появится сериализация.
ID — это именно тот тип, который в итоге окажется встроен в
`RouteConfig`/`DesiredState`, сохранённые на диск или переданные по сети (см.
State Model ниже); изменение их wire-формата задним числом стало бы breaking
change для каждого сохранённого или переданного конфига.

Этот крейт намеренно держится минимальным и остаётся таким по построению:
всё, что представляет сетевое понятие (адрес, маршрут, настройка резолвера),
относится к `net-lattice-ip` или `net-lattice-model`, никогда не сюда. `net-lattice-core`
никогда не должен требовать нового модуля просто потому, что где-то в
workspace появился новый домен (DNS, firewall, VLAN, ...) — если это
происходит, значит что-то было размещено не туда.

### `net-lattice-ip`

Примитивы IP-адресов и сетей: `IPv4Address`, `IPv6Address`, `IPv4Network`,
`IPv6Network`, `PrefixLength`. Чистые данные и арифметика, никакой зависимости
от ОС. Этот крейт должен собираться под любую цель, включая `wasm32`.

### `net-lattice-model`

Доменная модель сетевого состояния операционной системы, организованная как
модули:

- `mac` — `MacAddress`
- `route` — `Route`, gateway, metric
- `interface` — `Interface` и тип интерфейса (зависит от `mac`)
- `neighbor` — записи ARP/NDP (зависит от `net-lattice-ip` и `mac`)
- `dns` — конфигурация DNS-резолвера (зависит от `net-lattice-ip`)
- `ifaddr` — IP-адреса, назначенные интерфейсам, включая наблюдаемые записи
  `InterfaceAddress` и намерение назначения `NewInterfaceAddress`
  (зависит от `net-lattice-ip`;
  назван `ifaddr`, а не `address`, чтобы не конфликтовать с собственными
  примитивами `IpAddress`/`Network` из `net-lattice-ip`/`net-lattice-model` —
  это отдельное понятие адреса, *привязанного к интерфейсу*, а не ещё одно
  представление адреса)
- `event` — `Event`, enum уведомлений об изменениях. Он живёт здесь, а не в
  `net-lattice-platform`, потому что событие ссылается на доменные данные — оно
  бессмысленно без знания того, что такое маршрут или интерфейс, а это ровно
  то знание, которого `net-lattice-platform` иметь не должен.

  **События — это сигналы, а не снапшоты.** Событие должно нести ID и вид
  изменения (`Added` / `Removed` / `Changed`), а не клон полного доменного
  объекта:

  ```rust
  pub enum Event {
      Route { id: RouteId, kind: ChangeKind },
      Interface { id: InterfaceId, kind: ChangeKind },
  }
  ```

  а не `Event::RouteAdded(Route)`. Две причины: нативные уведомления об
  изменениях часто вообще не передают полный объект (сообщение `RTM_NEWROUTE`
  или callback об изменении маршрута в Windows может нести только то, что
  изменилось, а не полную запись), так что `Event`, требующий полный `Route`,
  вынуждал бы backend реконструировать то, что на самом деле не было
  доставлено; и клонирование полного доменного объекта при каждом изменении —
  напрасная работа, когда большинству потребителей нужно лишь знать *сам факт*
  изменения, прежде чем решить, стоит ли перезапрашивать данные. Потребитель,
  которому нужно текущее значение, перечитывает его через соответствующий
  provider (`backend.routes()`, по ID из события).

  `ChangeKind::Changed` должен со временем нести информацию о том, какие поля
  изменились (например, `Changed { fields: RouteFieldMask }`), а не быть
  голым маркером. Без этого потребителю, которому важны только изменения
  gateway, всё равно придётся перезапрашивать и сравнивать весь объект при
  каждом несвязанном изменении metric, что сводит на нет большую часть смысла
  сигнального события. Точное представление field-mask — деталь API Stage 0.1
  (или того этапа, на котором появится `EventProvider`); этот документ
  фиксирует лишь то, что `Changed` со временем должен нести эту информацию,
  так что форма enum не должна этому препятствовать.

Модули внутри `net-lattice-model` могут зависеть друг от друга и от `net-lattice-ip`,
но крейт в целом не имеет зависимости от ОС. `dns` намеренно не зависит от
`interface`; связь DNS с конкретным интерфейсом выражается через `InterfaceId`
из `net-lattice-core`, а не через прямую зависимость модулей, чтобы избежать
связывания модулей, которые должны свободно эволюционировать независимо.

**Типы модели должны проектироваться с расчётом на расширение, а не под
наименьший общий знаменатель.** Одно и то же доменное понятие несёт разный
набор полей на каждой платформе — маршрут в Linux несёт таблицу маршрутизации,
protocol, scope и type в дополнение к destination/gateway/metric; Windows и
BSD предоставляют более узкий набор. Сжатие типа модели только до тех полей,
которые сейчас есть у всех платформ, сделало бы невозможным добавление
платформо-специфичных полей позже без breaking change. Конкретные списки
полей — решение API-дизайна для черновика Stage 0.1, не этого документа, но
какую бы форму они ни приняли, они обязаны с самого начала оставлять место
для платформо-специфичного расширения (например, через открытый
properties/extension-контейнер).

### `net-lattice-platform`

Это крейт, который делает разделение model/backend реальным, а не
декларативным: **`net-lattice-platform` не зависит от `net-lattice-model`.**

Его provider-traits описывают *форму* контракта, а не *содержимое* модели —
они generic относительно доменного типа, с которым работают, через
associated types, а не называют `Route`/`Interface` из `net-lattice-model`
напрямую:

```rust
trait RouteProvider {
    type Route;

    fn routes(&self) -> Result<Vec<Self::Route>, Error>;
}

trait RouteMutator {
    type RouteConfig;

    fn add_route(&self, route: Self::RouteConfig) -> Result<(), Error>;
    fn remove_route(&self, route: Self::RouteConfig) -> Result<(), Error>;
}

trait InterfaceProvider {
    type Interface;

    fn interfaces(&self) -> Result<Vec<Self::Interface>, Error>;
}

trait InterfaceMutator: InterfaceProvider {
    type InterfaceConfig;

    fn set_interface_config(
        &self,
        config: Self::InterfaceConfig,
    ) -> Result<Self::Interface, Error>;
}
```

`net-lattice-platform` удовлетворён чем угодно, что имеет форму маршрута; у него
нет способа знать или заботиться о том, что конкретный тип на самом деле
происходит из `net-lattice-model`. Именно это означают на языке Rust слова
"platform говорит: *мне нужно что-то Route-образное*; model говорит: *я
существую независимо от platform*" — это не достигается желанием убрать
стрелку зависимости, для этого trait должен перестать называть конкретный
тип.

Provider-traits, по одному на возможность, а не один большой trait, по той
же причине, что и раньше — монолитный trait, покрывающий каждый домен,
заставлял бы каждый backend заглушать методы для возможностей, которых у
него нет:

- `RouteProvider` — список маршрутов.
- `RouteMutator` — добавление и удаление маршрутов (ADR-0002; тип входа
  отделён от `RouteProvider::Route` в ADR-0008). Его вход, `RouteConfig`,
  отличен от наблюдаемого `Route`: как и `StaticNeighbor`, он не несёт
  синтезированного backend'ом идентификатора (`Route::id` ни один backend не
  принимает обратно как вход мутации). Идентичность для сопоставления на
  уровне facade — `destination + gateway + metric + interface_index`,
  намеренное надмножество реального ключа сопоставления каждого backend'а.
  Metric маршрута учитывается только на Linux/Windows и молча
  игнорируется как no-op на Darwin, отражая уже существующий пробел на
  стороне наблюдаемого состояния.
- `InterfaceProvider` — список наблюдаемых интерфейсов.
- `InterfaceMutator` — применение частичной desired-конфигурации интерфейса
  с возвратом наблюдаемого интерфейса после read-after-write. Он отделён от
  чтения, поскольку требует повышенных нативных сетевых привилегий.
- `NeighborProvider` — список записей ARP/NDP.
- `NeighborMutator` — добавление и удаление статических записей ARP/NDP. Его
  входной тип, `StaticNeighbor`, отделён от `NeighborEntry`: он не содержит ни
  синтезированного `NeighborId`, ни наблюдаемого `NeighborState`, и требует
  MAC-адрес, поскольку на этом этапе создаются только статические L2-записи.
  `net-lattice-backend-linux` реализует этот трейт (`RTM_NEWNEIGH`/
  `RTM_DELNEIGH` через `rtnetlink`, `NUD_PERMANENT`, защита от удаления
  не-`Permanent` записи); `net-lattice-backend-windows` реализует его через
  `CreateIpNetEntry2`/`DeleteIpNetEntry2` над `MIB_IPNET_ROW2`
  (`NlnsPermanent`, та же защита, подтверждено на реальном elevated Windows
  CI); `net-lattice-backend-darwin` реализует его через `RTM_ADD`,
  кодирующий полный `sockaddr_dl`-шлюз с реальным link-типом интерфейса, и
  последовательность из двух сообщений `RTM_GET`-затем-`RTM_DELETE` поверх
  `PF_ROUTE`, повторяя собственный подход Apple из `arp.c`/`ndp.c` (та же
  защита), подтверждено на реальном elevated macOS CI round-trip. Все три
  backend'а заявляют `Capability::NEIGHBOR_MUTATION`. facade `net-lattice`
  выполняет прямую передачу вызовов `NeighborMutator` на каждом backend'е
  через `Lattice::add_static_neighbor`/`remove_static_neighbor` и
  диспетчеризацию executor'а `Mutation::{AddStaticNeighbor,
  RemoveStaticNeighbor}` (ADR-0001).
- `DnsProvider` — чтение/запись конфигурации DNS-резолвера.
- `AddressProvider` — список IP-адресов, назначенных интерфейсам.
- `AddressMutator` — назначение и удаление IP-адресов. Его входной тип
  отделён от наблюдаемого результата: `NewInterfaceAddress` содержит ID
  интерфейса, адрес/префикс и необязательный IPv4 broadcast, а
  `InterfaceAddress` содержит созданный backend'ом ID и атрибуты, сообщённые ОС.
- `EventProvider` — подписка на уведомления об изменениях, generic
  относительно associated-типа `Event` по той же причине, что и остальные.
- `AdditionProvider: EventProvider` — обособленный, явно опциональный
  уровень неродных (non-native) возможностей, о которых сообщает отдельный
  тип флагов `Addition` (`#[non_exhaustive]` набор в стиле bitflags,
  структурно параллельный `Capability`, но никогда не сливаемый с ним).
  Каждый флаг `Capability` описывает полноценный родной механизм, единый
  для всех backend'ов; `Addition` описывает документированный обходной путь
  более низкого качества (например, поллинг вместо родной push-подписки),
  который вызывающий должен запросить явно и который никогда не
  анонсируется и не активируется по умолчанию. Оба метода
  `AdditionProvider` — `additions` (по умолчанию: `Addition::empty()`) и
  `watch_addition` (по умолчанию: `Err(Error::Unsupported)`) — предоставлены
  по умолчанию, так что backend, которому нечего добавить, реализует этот
  trait бесплатно. Backend, у которого нет родного механизма для чего-либо,
  по-прежнему просто не выставляет соответствующий бит `Capability` —
  `Addition` никогда не расширяет то, что означает `Capability`.

- `Capability` — отличается от provider-traits, и намеренно не является той
  же осью. Provider-traits (`RouteProvider`, ...) описывают поверхности API,
  фиксированные во время компиляции: backend либо реализует `DnsProvider`,
  либо нет, и это известно на момент сборки крейта backend'а. `Capability`
  описывает *runtime*-зависимые возможности операционной системы, которые
  невозможно выразить только через реализацию Rust trait'а — например, Linux
  backend всегда реализует `RouteProvider`, но включена ли в запущенном ядре
  поддержка IPv6 или VRF — это факт о текущей машине, а не о крейте.
  Потребители запрашивают `backend.capabilities().contains(Capability::VRF)`
  во время выполнения, вместо того чтобы полагаться на метод, молча
  проваливающийся или паникующий, когда возможность на самом деле
  недоступна. `Capability` — простой enum без доменных типов внутри, так что
  держать его здесь ничего не стоит `net-lattice-platform`. Поскольку
  потребителям регулярно нужно проверять комбинации возможностей
  (`caps.contains(Capability::IPV6 | Capability::VRF)`), он должен быть
  представлен как значение в стиле bitflags, а не как `Vec<Capability>` или
  `HashSet<Capability>` — тогда проверки на комбинацию и вхождение становятся
  дешёвыми битовыми операциями вместо сканирования коллекции. Точное
  представление (тип, сгенерированный `bitflags!`, или рукописный) — деталь
  Stage 0.1; этот документ фиксирует лишь то, что `Capability` — это набор
  флагов, а не список.

Этот крейт зависит только от `net-lattice-core` (ради `Error` и типов ID). У него
нет OS-специфичного кода и, в отличие от предыдущей редакции этого документа,
никакой зависимости от `net-lattice-model`.

**Где generic-контракт встречается с конкретной моделью.** Что-то в итоге
должно связать `Self::Route = net_lattice_model::route::Route`, иначе associated
types никогда не разрешатся во что-то реальное. Это связывание происходит в
крейтах backend'ов, которые уже зависят и от `net-lattice-platform` (ради
traits), и от `net-lattice-model` (ради конкретных типов) — см. ниже.
`net-lattice-platform` сам это связывание никогда не выполняет и никогда не
должен.

### Backend-крейты платформ: `net-lattice-backend-linux`, `net-lattice-backend-windows`, `net-lattice-backend-darwin`

Каждый backend реализует то подмножество provider-traits из
`net-lattice-platform`, которое реально может поддержать, используя нативные
средства ОС:

- `net-lattice-backend-linux` — Netlink (через существующий Netlink-крейт как
  зависимость, а не собственную обёртку Net Lattice).
- `net-lattice-backend-windows` — IP Helper API через Windows-биндинги.
- `net-lattice-backend-darwin` — macOS BSD route sockets и связанные системные
  API.

Нейминг `net-lattice-backend-*` (вместо голых `net-lattice-linux` и т.п.) делает роль
каждого крейта понятной из одного лишь имени при просмотре workspace или
результатов `cargo search`, и оставляет место для имён вроде
`net-lattice-backend-linux-networkmanager` рядом с `net-lattice-backend-linux-netlink`,
если какой-то ОС когда-нибудь понадобится больше одного конкурирующего
backend-крейта.

`net-lattice` по умолчанию выбирает backend-крейт для текущей цели через
`cfg(target_os = "...")`, но каждый backend дополнительно закрыт одноимённым
Cargo-feature (`linux`, `windows`, `darwin`). Речь не о переключении backend'а
во время выполнения (см. замечание об object safety выше — это остаётся
выбором на этапе компиляции), а о возможности зависеть конкретно от
`net-lattice-backend-linux` — например, чтобы запустить его unit-тесты или
перепроверить его поведение — без необходимости полной сборки под каждую
другую платформу на машине, которая не может собирать под них.

Каждый backend связывает associated type каждого trait'а с конкретным типом
`net-lattice-model`, который он производит:

```rust
impl RouteProvider for LinuxBackend {
    type Route = net_lattice_model::route::Route;

    fn routes(&self) -> Result<Vec<Self::Route>, Error> { /* netlink */ }
}

impl RouteMutator for LinuxBackend {
    type Route = net_lattice_model::route::Route;

    fn add_route(&self, route: Self::Route) -> Result<(), Error> { /* netlink */ }
    fn remove_route(&self, route: Self::Route) -> Result<(), Error> { /* netlink */ }
}
```

Backend'ы — единственное место в workspace, где `net-lattice-platform` и
`net-lattice-model` одновременно находятся в области видимости.

Платформо-специфичные нюансы, не сводящиеся к одному нативному API (например,
DNS в Linux, обслуживаемый systemd-resolved, NetworkManager или простым
`resolv.conf`, в зависимости от системы), решаются внутри самого
backend-крейта — через определение возможностей — а не путём создания
отдельных крейтов под каждый механизм. Если однажды один backend-крейт
наберёт достаточно конкурирующих реализаций provider'ов для одного домена,
чтобы стать неудобным (например, Netlink-реализация `RouteProvider` и
NetworkManager-реализация `DnsProvider`, реально заслуживающие независимых
циклов релизов), этот домен можно будет выделить в собственный
provider-крейт в этот момент — не раньше.

Backend'ы зависят от `net-lattice-platform` и `net-lattice-model`. Они ничего не
экспортируют выше; ничто вне backend-крейта не зависит от него напрямую,
кроме самого `net-lattice`.

**Ничто не мешает backend'у связать associated type provider'а с чем-то, что
не совпадает с соответствующим типом `net-lattice-model`** — это неизбежное
следствие того, что `net-lattice-platform` остаётся generic. Крейт backend'а
волен написать `type Route = LinuxRoute;` для какого-то backend-специфичного
типа вместо `net_lattice_model::route::Route`. Это не пробел, который закрывается
через зависимость `net-lattice-platform` от `net-lattice-model` (см. предыдущий
раздел); он закрывается на слой выше, в `net-lattice`. См. ниже.

### `net-lattice`

Публичный фасад. Реэкспортирует типы, нужные потребителям, из `net-lattice-model`
и `net-lattice-ip`, выбирает backend по умолчанию на основе
`cfg(target_os = "...")` и предоставляет верхнеуровневый API (например,
`Lattice::connect()`). Это единственный крейт, от которого напрямую зависит
большинство потребителей.

**Именно здесь обеспечивается схождение модели.** Generic-контракт
`net-lattice-platform` означает, что associated types backend'а в принципе могут
разойтись с `net-lattice-model` (см. предыдущий раздел). `net-lattice` закрывает этот
пробел не добавлением зависимости `net-lattice-platform → net-lattice-model`, а
ограничением associated types равенством конкретным типам `net-lattice-model`
везде, где он принимает backend:

```rust
pub trait LatticeBackend:
    RouteProvider<Route = net_lattice_model::route::Route>
    + RouteMutator<RouteConfig = net_lattice_model::route::RouteConfig>
    + InterfaceProvider<Interface = net_lattice_model::interface::Interface>
{
}

pub struct Lattice<B: LatticeBackend> {
    backend: B,
}
```

Backend, чей associated type `Route` не является буквально
`net_lattice_model::route::Route`, просто не удовлетворяет `LatticeBackend` и не
может быть использован с публичным типом `Lattice` — ошибка компиляции в
момент подключения backend'а, а не сюрприз во время выполнения. Сбор
ограничений по каждому provider'у в один именованный trait `LatticeBackend`
(вместо повторения растущего `where`-условия на самом `Lattice`) — чисто
эргономическое решение, оно не меняет, где именно живёт ограничение. Это
даёт ту же силу гарантии, что и прямая зависимость, не требуя от
`net-lattice-platform` знать о существовании `net-lattice-model`: ограничение живёт
у потребителя контракта (фасада, который собирает конкретную систему), а не
у определения контракта. Это та же форма, что используется в таких крейтах,
как `sqlx` и `diesel`, где generic-trait backend'а сочетается со связыванием
конкретного типа, обеспечиваемым в точке использования.

**Этот generic-дизайн намеренно жертвует object safety, пока что.**
Associated types (`RouteProvider::Route`, ...) делают эти traits
нереализуемыми как `Box<dyn RouteProvider>` — Rust не может построить vtable
для trait'а, чьи сигнатуры методов зависят от типа, который варьируется от
реализации к реализации. Конкретно это означает, что backend'ы должны
выбираться во время компиляции (`Lattice<LinuxBackend>`), а не динамически во
время выполнения из списка загруженных реализаций. Для реального плана
поставки Net Lattice — фиксированный, статически слинкованный backend на целевую
ОС, выбираемый через `cfg(target_os = "...")` — это ничего не стоит. Это
имело бы значение, если бы Net Lattice впоследствии понадобилось выбирать между
несколькими конкурирующими backend'ами для одной и той же платформы во время
выполнения (например, Netlink против backend'а на основе NetworkManager на
одной машине); если такая потребность материализуется, object-safe erased
слой (не-generic `dyn`-совместимые traits, внутренне делегирующие к generic
версиям, условно называемые `DynRouteProvider` и подобными) можно будет
добавить в `net-lattice-platform`, не меняя generic-traits, от которых уже
зависят потребители. Это зарезервированная точка расширения, а не
обязательство — она не строится, пока не появится конкретный случай
использования.

## Модель ошибок

Net Lattice не должна допускать утечку `std::io::Error` или сырых кодов ошибок ОС
(`EPERM`/`ENODEV` в Linux, `ERROR_ACCESS_DENIED` в Windows) в качестве своего
публичного типа ошибки. Разные backend'ы проваливаются по одной и той же
логической причине через совершенно разные коды, а потребителю,
пишущему кроссплатформенный код, нужно матчиться на *причину* сбоя, а не на
платформо-специфичное целое число.

`net-lattice-core::Error` — единственный тип ошибки, предъявляемый во всём
workspace, выраженный через платформо-независимые варианты, такие как:

- `PermissionDenied`
- `NotFound`
- `AlreadyExists`
- `Unsupported` — операция вообще не имеет смысла на этом backend'е (в
  отличие от отсутствия `Capability` во время выполнения; см. ниже).
- `InvalidState`
- `Platform` — лазейка, сохраняющая сырую backend-специфичную ошибку
  для диагностики, не будучи основным способом, которым потребителям
  предлагается матчиться на сбои.

Точный список вариантов был решением API-дизайна, закреплённым в черновике
Stage 0.1 (см. `net-lattice-core::Error`); этот документ фиксирует лишь то,
что такая таксономия существует и живёт в `net-lattice-core`, и что методы
provider-traits возвращают `Result<T, Error>` с её использованием — никогда
сырой тип ошибки ОС.

**Код `Platform` не может быть одним нетипизированным целым числом.**
Linux errno — это знаковый `i32`, коды ошибок Windows — беззнаковый `DWORD`
(`u32`), и сворачивание обоих в одно голое поле `i32`/`u32` либо молча
обрезает один из них, либо создаёт ложное впечатление, что коды сравнимы
между платформами, хотя это не так — Linux `13` и Windows `13` не имеют
ничего общего. Код должен быть помечен платформой, например через enum
(`PlatformErrorCode::Linux(i32)` / `Windows(u32)` / `Darwin(i32)`) или через
boxed `dyn Error`. Любой из вариантов снимает неоднозначность; выбор между
ними — решение Stage 0.1, но оставление кода одним обычным целочисленным
типом здесь исключается.

## Модель привилегий

Настройка сети привилегирована на каждой целевой платформе, и граница
привилегий не совпадает одинаково между ними:

- **Linux** — чтение маршрутов/интерфейсов, как правило, непривилегировано;
  добавление или удаление требует `CAP_NET_ADMIN`.
- **Windows** — чтение доступно обычным пользователям; изменение обычно
  требует прав администратора.
- **macOS** — похожая асимметрия чтения/записи через BSD route sockets.

Это не гипотетическая проблема: это конкретный сценарий, стоящий за
вариантом `Error::PermissionDenied` выше, и это означает, что операции
чтения и записи следует ожидать проваливающимися независимо друг от друга и
по разным причинам как в коде потребителя, так и в тестах. Этот документ не
предписывает конкретный API проверки привилегий (например, предварительный
`backend.can_modify()`) — это снова решение API-дизайна — но разделение
provider-traits (методы, ориентированные на чтение-список, и методы,
ориентированные на запись-добавление/удаление, уже отдельные методы одного
trait'а) не должно скрывать тот факт, что у вызывающего может правдоподобно
быть одно без другого.

## Асинхронная модель

`EventProvider` по своей природе push-based на каждой платформе (multicast-
сокеты Netlink в Linux, callback'и в стиле `NotifyRouteChange2` в Windows,
routing sockets BSD в macOS). В Stage 0.8 его API синхронный и
runtime-агностичный: `watch() -> Result<EventReceiver<Event>>`.
`EventReceiver` повторяет модель `std::sync::mpsc::Receiver`: предоставляет
`recv`, `try_recv`, `recv_timeout` и реализует `Iterator`. Это сохраняет
возможность использования без async runtime.

Синхронный контракт остаётся доступен без async-зависимости. Этап 0.11
добавляет опциональную feature `async` в `net-lattice`: она реэкспортирует единый
runtime-agnostic `net-lattice-async::EventStream` и добавляет
`Lattice::watch_async(filter)`. `EventStream` реализует `futures::Stream`,
поэтому приложения сохраняют свободу выбора executor. Это не zero-cost wrapper
вокруг `EventReceiver`: `std::sync::mpsc::Receiver` не может регистрировать
waker. Отдельный async crate сохраняет явный worker-thread bridge для
произвольного синхронного receiver, но фасад использует нативный Tokio-aware
путь каждого backend: Netlink опрашивается существующим Tokio runtime Linux,
callbacks IP Helper Windows пишут в bounded Tokio channel, а reader PF_ROUTE
macOS пишет прямо в этот channel. Все нативные async transports имеют ту же
семантику bounded delivery и resynchronization, что и `EventReceiver`.

## Модель состояния: императивная и декларативная

Изначальная поверхность API Net Lattice была императивной: `route.add()`,
`route.delete()`, отражая то, что естественно предоставляют
`RouteProvider`/`InterfaceProvider`. Это было осознанным решением — это
наименьшая полезная поверхность, и она напрямую отображается на то, что
предоставляют нативные API платформ.

Декларативная конфигурация была заявленной долгосрочной целью и с тех пор
реализована (стадии 0.19–0.20): это другой способ использования тех же
provider-traits, а не другой контракт backend'а, поэтому она не потребовала
доработки каждого provider'а. Архитектура назвала это понятие заранее, до
реализации, как:

- `SnapshotProvider` — provider-trait в `net-lattice-platform` (generic
  относительно associated-типа `State`, как и остальные), собирающий
  `CurrentState`, читая другие provider'ы, которые реализует backend. Это
  конкретный механизм, стоящий за `CurrentState` ниже, вместо того чтобы
  каждому backend'у или фасаду приходилось собирать снапшот вручную и
  ситуативно.
- `CurrentState` — снапшот, который производит `SnapshotProvider`, читая
  provider'ы (маршруты, интерфейсы, ...) для данного backend'а, построенный
  из уже существующих типов состояния `net-lattice-model` (`Route`, `Interface`,
  ...).
- `DesiredState` — **не тот же тип, что `CurrentState`.** Желаемый маршрут
  или интерфейс выражается отдельным типом конфигурации (`RouteConfig`,
  `InterfaceConfig`, ...) рядом с соответствующим типом состояния, а не
  переиспользованным `Route`/`Interface`. Объекты состояния несут поля,
  являющиеся доступными только для чтения фактами о текущей системе (живой
  MTU интерфейса, его операционное состояние, счётчики трафика), которые
  невозможно осмысленно "пожелать" — потребитель, выражающий намерение, не
  должен иметь возможности сконструировать `Route` с бессмысленным набором
  read-only полей, и компилятор не должен позволять ему даже попытаться.
  Реализовано начиная с этапа 0.19: `DesiredState` (`net-lattice-model`) —
  цельносистемный, авторски задаваемый вызывающим кодом агрегат с одним
  полем на домен, обёрнутым в `Option` — `None` означает, что домен не
  управляется, `Some` (включая пустую коллекцию) означает, что домен
  управляется именно с этим желаемым содержимым — строится через
  `DesiredState::empty()` и подомённые builder-методы `with_*`, без
  зависимости от backend/provider (в отличие от `CurrentState`, он никогда
  не собирается из чтения backend'а).
- `Diff` — вычисленная разница между `CurrentState` и `DesiredState`,
  сравнивающая типы состояния и конфигурации по полям там, где они
  пересекаются. Реализовано начиная с этапа 0.19: `Diff` (`net-lattice-model`)
  — чистая, лишённая побочных эффектов структура с одним полем на домен,
  вычисляемая функцией `Diff::compute(&CurrentState, &DesiredState) -> Diff`.
  Маршруты, соседи и адреса используют общую форму set-diff по natural key
  (`Added`/`Removed`, плюс `Changed` для соседей/адресов); интерфейс
  использует отдельную форму patch-diff по полям (`InterfaceDiff`),
  зеркалирующую семантику "не трогать" у `InterfaceConfig`; DNS —
  сравнение целого значения (`DnsChange`). `Diff::compute` не выполняет
  ввод-вывод и не вызывает методы provider/backend — это чисто
  inspectable-результат, без `ApplyPlan` и без исполнения.
- `ApplyPlan` — упорядоченная последовательность вызовов provider'ов
  (add/remove/modify), которая разрешила бы `Diff`, которую можно
  просмотреть до выполнения и откатить, если шаг провалится. Реализовано
  начиная с этапа 0.20: `ApplyPlan` (`net-lattice-model`) — чистая,
  лишённая побочных эффектов структура `#[non_exhaustive]` из `ApplyStep`,
  вычисляемая функцией `ApplyPlan::compile(&Diff) -> ApplyPlan` —
  безотказная, без ввода-вывода, без зависимости от provider/backend,
  зеркалирующая ту же дисциплину области действия, что и `Diff::compute`.
  `ApplyStep` (`#[non_exhaustive]`) напрямую оборачивает `Mutation` для
  изменений интерфейса, соседа, адреса и DNS, а также для любой
  непарной записи маршрута `Added`/`Removed` (`Single`); пара маршрутов
  `Added`/`Removed` с одинаковым destination компилируется вместо этого в
  один шаг `ReplaceRoute { old, new }` — конкретное воплощение политики
  порядка замены маршрута, покрывающее неоднозначность native-ключа
  удаления, которая варьируется по backend'у. Теперь существует и
  исполнение: `Lattice::<B>::execute_apply_plan(&ApplyPlan, &mut
  ExecutionOptions) -> ApplyPlanReport` отправляет нижележащие
  native-операции подключённому backend'у, повторно используя
  собственные примитивы `execute_plan`
  (cancellation/snapshot/dispatch/compensation) для шагов `Single` и
  выполняя отдельный конечный автомат для шагов `ReplaceRoute`:
  общеплановое отклонение по возможностям (capability-aware) до любого
  native-вызова (для изменения route-метрики, которое подключённый
  backend не может поддержать, через два новых additive-метода
  `RouteMutator`, `supports_route_metric`/`route_replace_order`),
  повторная проверка precondition, порядок двух native-вызовов по
  backend'у и обязательная верификация read-after-write.
  `ApplyPlanReport` различает `Applied`/`Failed`/`NotAttempted` и два
  дополнительных исхода, которые не может выразить ни один вариант
  `MutationOutcome`: `Rejected` (capability-aware, ни один native-вызов
  не был предпринят) и `NonConvergent` (native-вызов был предпринят, но
  итоговое состояние не удалось подтвердить).

`CurrentState` (форма данных, в `net-lattice-model`)
и `SnapshotProvider` (контракт сборки, в `net-lattice-platform`) уже
существуют, и `Lattice<B>::current_state()` производит `CurrentState` для
любого подключённого backend'а без единой строчки кода в крейте backend'а.
Связка между associated-типом `State` у `SnapshotProvider` и конкретным типом
`CurrentState` реализована как `impl SnapshotProvider for Lattice<B>` в
фасаде, а не как blanket-реализация для произвольного типа backend'а `B`:
orphan rules Rust запрещают blanket-реализацию foreign trait'а
(`SnapshotProvider`, объявленного в `net-lattice-platform`) для голого
generic-параметра типа без локального типа в самой реализации. `Lattice<B>`
— это собственный локальный тип фасада, поэтому реализация trait'а на нём
одновременно легальна и достаточна — backend'ам по-прежнему не нужно писать
никакого кода, чтобы получить снапшот всей системы.
`DesiredState` и `Diff` (формы данных, в `net-lattice-model`, см. выше)
теперь существуют начиная с этапа 0.19, а `ApplyPlan`/`ApplyStep` (тоже
`net-lattice-model`, см. выше) теперь существуют начиная с этапа 0.20,
вместе с `Lattice::<B>::execute_apply_plan` (`net-lattice`), который
исполняет `ApplyPlan` для конкретного подключённого backend'а и сообщает
о результатах convergence, non-convergence и compensation. Тонкое
удобство фасада, `Lattice::<B>::apply(&self, desired: &DesiredState,
options: &mut ExecutionOptions<'_>) -> Result<ApplyPlanReport>`,
объединяет `current_state()` → `Diff::compute` → `ApplyPlan::compile` →
`execute_apply_plan` для обычного случая, когда вызывающей стороне не
нужно инспектировать скомпилированный план перед его исполнением;
вызывающие, которым нужен preflight или инспекция плана, по-прежнему
вызывают `current_state()`/`Diff::compute`/`ApplyPlan::compile` напрямую
(или ставший публичным `Lattice::<B>::validate_apply_plan`) вместо
`apply()`. Разделение state/config названо здесь — как параллельный тип `*Config` на
каждый доменный объект, живущий рядом с его типом состояния в
`net-lattice-model` — чтобы оно было заложено с первого типа `*Config`, а не
доделано после того, как `CurrentState`/`DesiredState` уже были бы слиты в
один тип.

## Контракт mutation и событий

Stage 0.14 превратил следующее наблюдаемое по доменам поведение mutation в
явные метаданные операций (`Mutation`, `MutationPrecondition`,
`MutationOutcome`, ...), на которых построен transaction executor (стадии
0.15–0.20: `Lattice::execute_plan`, `ApplyPlan`, `Lattice::apply`), вместо
того чтобы задним числом заявлять atomicity или более сильные обещания, чем
поддерживают нативные источники.

| Домен | Контракт mutation | Применённая нормализация для declarative apply |
|---|---|---|
| Routes | `RouteMutator` добавляет и удаляет через native acknowledgements, под контролем `Capability::ROUTE_MUTATION` (ADR-0002); входом мутации служит отдельный intent-тип `RouteConfig` (ADR-0008), matching при удалении по-прежнему зависит от платформы. | Результаты duplicate, absent и ambiguous match определены через `MutationPrecondition` поверх отделённого route intent и правила match для операции. |
| Адреса интерфейсов | `AddressMutator::add_address` возвращает повторно прочитанный `InterfaceAddress`; удаление принимает этот observed record. ID синтезируются из интерфейса и сети, а не выдаются ядром как стабильные identities. | Scope identity, assumptions о collision и preconditions удаления зафиксированы в модели операций. |
| DNS | `DnsMutator` заменяет portable resolver view и повторно читает `DnsConfig`. Unix переписывает active resolver file и отбрасывает directives вне portable model; Windows меняет global search settings и каждый перечисленный adapter отдельными вызовами. | Scope, manager ownership, persistence и partial-application results отражены в operation report. Atomic DNS replacement и automatic rollback никогда не обещаются. |
| Конфигурация интерфейсов | `InterfaceConfig` — partial desired patch; `InterfaceMutator` изменяет administrative state и/или MTU и возвращает observed readback. Combined native writes могут partially apply. | Явная compensation и eventual native event delivery сохранены; более широкое declarative состояние интерфейса теперь существует как per-field patch-diff `InterfaceDiff` (стадия 0.19). |
| Соседи | `NeighborMutator` добавляет и удаляет статические записи ARP/NDP через intent `StaticNeighbor`, под контролем `Capability::NEIGHBOR_MUTATION` (ADR-0001); удаление отказывает для присутствующей, но не `Permanent` записи. | Тот же паттерн intent/mutation расширяется на будущие поля домена соседей; дополнительная нормализация для статических записей не требуется. |

Каждая будущая mutation-операция должна задавать: target identity и match rule;
preconditions; idempotent result; нужные privileges; подтверждает ли ОС
завершение; перечитывает ли Net Lattice observed state; возможна ли partial
application; и безопасна ли compensating operation. `ApplyPlan` может
использовать эти метаданные, но не должен выводить безопасность rollback лишь
из успешного вызова.

Доставка событий — намеренно отдельный eventually consistent signal path; см.
раздел "Гарантии доставки событий" ниже — там дано каноническое описание
того, что watcher обещает и не обещает (порядок, переполнение, snapshot,
`ChangeKind::Changed`, DNS). Нативный механизм мониторинга по платформам:

- Linux отслеживает routes, links, neighbors и interface addresses через
  Netlink. Windows отслеживает routes, interfaces и unicast addresses через
  IP Helper; watcher соседей отсутствует. macOS отслеживает routes,
  interfaces, neighbors и addresses через PF_ROUTE.

Stages 0.15–0.20 построили transactions и declarative apply поверх этих
ограничений, а не задним числом обещали atomicity или event guarantees,
которых не предоставляют native sources.

## Правила стабильности API

После публикации разные крейты в этом workspace будут меняться с разной
скоростью, и потребителям нужно знать, какие обещания действуют на каком
уровне:

- **`net-lattice-core`** — самый стабильный крейт в workspace. От `Error`,
  `Id<T>` и общих traits зависит всё остальное; breaking change здесь
  вынуждает breaking change везде. Изменения требуют самого веского
  обоснования и самого широкого рецензирования.
- **`net-lattice-ip`** — стабилен, как только реализованы типы IPv4/IPv6; домен
  (адресация IP) хорошо изучен и медленно меняется.
- **`net-lattice-model`** — умеренная стабильность. Новые модули (`dns`,
  `neighbor`, ...) со временем добавляются согласно плану поставки, но
  существующие типы должны меняться консервативно после того, как домен
  вышел, поскольку и backend'ы, и потребители зависят от их точной формы.
- **`net-lattice-platform`** — ожидается, что будет эволюционировать быстрее,
  чем `net-lattice-model`, поскольку новые provider-traits добавляются по мере
  того, как новые домены получают поддержку backend'ов. Добавление trait'а
  не является breaking; изменение сигнатуры существующего trait'а —
  является, и затрагивает каждый backend, который его реализует.
- **Крейты `net-lattice-backend-*`** — наименее стабильны. Внутренние детали
  реализации могут меняться свободно; лишь реализации provider-traits,
  которые они предоставляют, являются поверхностью совместимости, и эта
  поверхность принадлежит `net-lattice-platform`, а не самому backend-крейту.

Это ранжирование существует, чтобы можно было оценить радиус поражения от
изменения до того, как оно сделано, а не для того, чтобы освободить какой-
либо крейт от обычной semver-дисциплины после достижения Net Lattice версии 1.0.

## Замороженная публичная поверхность API версии 1.0

Это сводный, по-крейтовый чек-лист публичных элементов, на которые
распространяется semver-дисциплина из раздела "Правила стабильности API"
выше после достижения Net Lattice версии 1.0. Он существует, чтобы
рецензент мог проверить "находится ли этот элемент в замороженном списке",
не выводя публичную поверхность workspace заново из исходного кода вручную.
Почти каждая доменная структура и enum ниже уже помечены
`#[non_exhaustive]` — новые поля/варианты остаются аддитивными после
1.0 — поэтому этот чек-лист отслеживает *существование*, *имя* и *форму*
элемента, а не только атрибут.

### `net-lattice-core`

Самый стабильный крейт; от каждого элемента ниже зависит каждый другой
крейт в workspace.

- `Error` (enum с `#[non_exhaustive]`, согласно ADR-0015) и его методы
  `is_permission_denied`, `is_not_found`, `is_already_exists`,
  `is_unsupported`, `is_invalid_state`, `is_disconnected`, `is_platform`.
- `PlatformErrorCode` (enum; намеренно **без** `#[non_exhaustive]` — см.
  примечание ниже), варианты `Linux(i32)`, `Windows(u32)`, `Darwin(i32)`.
- `Id<T>` (фантомно-типизированный идентификатор) и его методы `new`,
  `value`.
- `Result<T>` (псевдоним уровня крейта для `core::result::Result<T, Error>`).

Примечание: `Error` был помечен атрибутом `#[non_exhaustive]` перед
заморозкой 1.0 (ADR-0015), что привело его в соответствие с
почти каждым другим enum в `net-lattice-model`/`net-lattice-platform`.
`PlatformErrorCode` намеренно оставлен без этого атрибута: его три
варианта (`Linux`, `Windows`, `Darwin`) закрыты по построению — четвёртая
ОС не является реалистичным дополнением в текущей roadmap воркспейса, в
отличие от вариантов отказа у `Error`.

### `net-lattice-model`

- **Домен интерфейсов** (`interface`): `Interface`, `InterfaceConfig`,
  `InterfaceId` (`= Id<Interface>`), `InterfaceKind`, `AdminState`,
  `DesiredAdminState`, `OperationalState`.
- **Домен маршрутов** (`route`): `Route`, `RouteConfig`, `RouteId`
  (`= Id<Route>`).
- **Домен соседей** (`neighbor`): `NeighborEntry`, `NeighborId`
  (`= Id<NeighborEntry>`), `NeighborState`, `StaticNeighbor`.
- **Домен адресов интерфейса** (`ifaddr`): `InterfaceAddress`,
  `InterfaceAddressId` (`= Id<InterfaceAddress>`), `NewInterfaceAddress`.
- **Домен DNS** (`dns`): `DnsConfig`, `NewDnsConfig`.
- **Домен firewall** (`firewall`, добавлен в стадии 0.22, ADR-0017):
  `FirewallRule`, `FirewallPolicy`, `Direction`, `Protocol`, `PortRange`,
  `Verdict`. В отличие от разделения observed/desired, используемого всеми
  остальными изменяемыми доменами выше, `FirewallRule`/`FirewallPolicy`
  обслуживают обе стороны — чтение (`FirewallProvider::firewall_rules`) и
  запись (`FirewallMutator::set_firewall_policy`) — поскольку правило
  native-firewall не несёт синтезированного backend'ом идентификатора,
  который desired-intent пришлось бы опускать, в отличие от маршрута,
  адреса или записи соседа.
- **MAC-адрес** (`mac`): `MacAddress`.
- **Вспомогательные типы адресов** (`address`): `IpAddress`, `Network`.
- **Снимок состояния** (`snapshot`): `CurrentState`.
- **Декларативное желаемое состояние** (`desired_state`): `DesiredState`.
- **Diff** (`diff`): `Diff`, `Change`, `RouteChange`, `InterfaceDiff`,
  `NeighborChange`, `AddressChange`, `DnsChange`.
- **План применения** (`apply`): `ApplyPlan`, `ApplyPlanReport`,
  `ApplyStep`, `ApplyStepOutcome`, `NonConvergentReason`.
- **События** (`event`): `Event`, `EventDomain`, `EventFilter`,
  `ChangeKind`.
- **Намерение/план/отчёт мутации** (`mutation`): `Mutation`,
  `MutationKind`, `MutationPlan`, `MutationPlanReport`,
  `MutationOperationReport`, `MutationOutcome`, `MutationPreflight`,
  `MutationPrecondition`, `MutationConfirmation`, `MutationSnapshot`,
  `MutationPrivilege`, `MutationReversibility`, `MutationSemantics`,
  `MutationIdempotency`, `MutationExecutionPhase`, `MutationStopReason`,
  `RollbackStatus`.

Все перечисленные выше структуры/enum помечены `#[non_exhaustive]` на
уровне типа или варианта, за исключением небольших псевдонимов-маркеров
(`InterfaceId`/`RouteId`/`NeighborId`/`InterfaceAddressId` — это псевдонимы
типа `Id<T>` без собственного атрибута; дисциплина заморозки для них — это
дисциплина `Id<T>`, см. `net-lattice-core` выше) и `RouteReplaceOrder`,
который определён в `net-lattice-platform` (см. ниже), хотя и
ре-экспортируется через модуль `mutation` фасада.

### `net-lattice-platform`

- **Пары provider/mutator traits** (чтение без привилегий / запись с
  привилегиями, по одной паре на домен): `RouteProvider`/`RouteMutator`,
  `InterfaceProvider`/`InterfaceMutator`, `NeighborProvider`/
  `NeighborMutator`, `AddressProvider`/`AddressMutator`,
  `DnsProvider`/`DnsMutator`, `FirewallProvider`/`FirewallMutator`
  (`FirewallMutator::set_firewall_policy` атомарно заменяет всю managed
  policy целиком, в отличие от инкрементального add/remove у
  `RouteMutator` — см. ADR-0017).
- `RouteMutator::add_route`, `RouteMutator::remove_route` — два метода
  мутации, зависящих от `Capability`.
- **`RouteMutator::supports_route_metric`** и
  **`RouteMutator::route_replace_order`** — см. раздел "Факты,
  объявляемые backend'ом не через `Capability`" ниже; эти два
  предоставляемых по умолчанию метода trait'а являются такой же
  замороженной публичной поверхностью, как и список типов выше, но их
  легко упустить, поскольку это не флаги `Capability`.
- `RouteReplaceOrder` (enum `#[non_exhaustive]`), варианты
  `RemoveBeforeAdd`, `AddBeforeRemove`.
- `Capability` (тип на основе `bitflags`) и его флаги: `IPV6`, `VRF`,
  `NAMESPACES`, `ROUTE_MONITORING`, `DNS_MUTATION`,
  `INTERFACE_ADMIN_STATE`, `INTERFACE_MTU`, `INTERFACE_MONITORING`,
  `NEIGHBOR_MONITORING`, `ADDRESS_MONITORING`, `NEIGHBOR_MUTATION`,
  `ROUTE_MUTATION`, `FIREWALL_MUTATION` и составной `MONITORING`
  (побитовое объединение четырёх флагов `*_MONITORING`).
- Trait `CapabilityProvider` и его единственный метод `capabilities`.
- `EventProvider`, `EventReceiver`, `EventSender` (контракт доставки
  нативных событий изменения).
- `SnapshotProvider` (сборка состояния всей системы; реализуется blanket-
  реализацией, а не вручную на каждый backend).
- За флагом функции `async`: `TokioEventProvider` и его метод
  `watch_tokio`, `TokioEventReceiver`, `TokioEventSender`.

#### Факты, объявляемые backend'ом не через `Capability`

`RouteMutator::supports_route_metric() -> bool` (по умолчанию `true`) и
`RouteMutator::route_replace_order() -> RouteReplaceOrder` (по умолчанию
`RouteReplaceOrder::RemoveBeforeAdd`) **не являются** флагами `Capability`.
Это обычные методы trait'а со значениями по умолчанию, поскольку они
описывают фиксированный факт о целевом backend'е (например, "ключ
удаления маршрута этой операционной системы не может различить
находящуюся в процессе замену"), а не зависящую от времени выполнения
возможность, которая может отличаться между двумя процессами,
подключёнными к backend'у одного и того же вида. Заморозка версии 1.0
должна отслеживать их сигнатуры и значения по умолчанию с той же
дисциплиной, что и сам `Capability` — читатель, который проверяет только
doc-комментарий `Capability` в поисках "что backend объявляет о себе",
пропустит эти два метода.

### `net-lattice` (фасад)

- **Ре-экспорты корня крейта**: `Error`, `Id<T>`, `PlatformErrorCode`,
  `Result` (из `net-lattice-core`); типы адресов `net-lattice-ip`;
  `Capability`, `CapabilityProvider` (из `net-lattice-platform`);
  `Lattice<B>`; `LatticeBackend`.
- **Модуль `model`** (наблюдаемые доменные типы только для чтения и
  read-provider traits): `DnsConfig`, `Direction`, `FirewallRule`,
  `PortRange`, `Protocol`, `Verdict`, `InterfaceAddress`,
  `InterfaceAddressId`, `AdminState`, `Interface`, `InterfaceId`,
  `InterfaceKind`, `OperationalState`, `MacAddress`, `NeighborEntry`,
  `NeighborId`, `NeighborState`, `Route`, `RouteId`, `CurrentState`,
  `IpAddress`, `Network`, `AddressProvider`, `DnsProvider`,
  `FirewallProvider`, `InterfaceProvider`, `NeighborProvider`,
  `RouteProvider`, `SnapshotProvider`.
- **Модуль `mutation`** (намерение мутации, машинерия
  плана/выполнения/отчёта, mutator traits, декларативная пара
  `DesiredState`/`Diff`): `Cancellation`, `Compensation`,
  `ExecutionOptions`, `Snapshot`, `ApplyPlan`, `ApplyPlanReport`,
  `ApplyStep`, `ApplyStepOutcome`, `NonConvergentReason`, `DesiredState`,
  `AddressChange`, `Change`, `Diff`, `DnsChange`, `InterfaceDiff`,
  `NeighborChange`, `RouteChange`, `NewDnsConfig`, `FirewallPolicy`,
  `NewInterfaceAddress`, `DesiredAdminState`, `InterfaceConfig`,
  `Mutation`, `MutationConfirmation`, `MutationExecutionPhase`,
  `MutationIdempotency`, `MutationKind`, `MutationOperationReport`,
  `MutationOutcome`, `MutationPlan`, `MutationPlanReport`,
  `MutationPrecondition`, `MutationPreflight`, `MutationPrivilege`,
  `MutationReversibility`, `MutationSemantics`, `MutationSnapshot`,
  `MutationStopReason`, `RollbackStatus`, `StaticNeighbor`, `RouteConfig`,
  `AddressMutator`, `DnsMutator`, `FirewallMutator`, `InterfaceMutator`,
  `NeighborMutator`, `RouteMutator`, `RouteReplaceOrder`.
- **Модуль `monitoring`** (события изменений, фильтры, monitoring
  provider traits): `EventStream` (за флагом функции `async`),
  `ChangeKind`, `Event`, `EventDomain`, `EventFilter`, `TokioEventProvider`
  (за флагом функции `async`), `EventProvider`, `EventReceiver`,
  `Addition`, `AdditionProvider`.
- **Модуль `backend`** (единая точка входа для авторов сторонних
  backend'ов; ре-экспортирует элементы, также доступные через
  `model`/`mutation`/`monitoring` выше, плюс `LatticeBackend` и
  `CapabilityProvider`): `LatticeBackend`, `CurrentState`,
  `AddressMutator`, `AddressProvider`, `Addition`, `AdditionProvider`,
  `CapabilityProvider`, `DnsMutator`, `DnsProvider`, `EventProvider`,
  `EventReceiver`, `EventSender`, `FirewallMutator`, `FirewallProvider`,
  `InterfaceMutator`, `InterfaceProvider`, `NeighborMutator`,
  `NeighborProvider`, `RouteMutator`, `RouteProvider`, `RouteReplaceOrder`,
  `SnapshotProvider`, а также за флагом функции `async`:
  `TokioEventProvider`, `TokioEventReceiver`, `TokioEventSender`.
- **`LatticeBackend`** — ограничение времени компиляции, которому должен
  соответствовать сторонний backend; его точный набор supertraits
  (`RouteProvider`/`RouteMutator`/`InterfaceProvider`/`InterfaceMutator`/
  `DnsMutator`/`NeighborProvider`/`NeighborMutator`/`AddressProvider`/
  `AddressMutator`/`FirewallMutator`/`EventProvider`/`AdditionProvider`/
  `CapabilityProvider`, каждый привязан к конкретному типу
  `net-lattice-model`) сам является частью замороженного контракта:
  расширение или сужение этого набора — breaking change для каждой
  сторонней реализации backend'а. `AdditionProvider` был добавлен как
  обязательный supertrait на этапе 0.21 (ADR-0014); это additive-safe
  изменение для любого существующего и стороннего backend'а, поскольку
  оба его метода имеют реализацию по умолчанию — ни одной существующей
  реализации не потребовалось изменение кода, чтобы продолжить
  компилироваться. `FirewallMutator` (который требует `FirewallProvider`
  как собственный supertrait) был добавлен на этапе 0.22
  (ADR-0017) — в отличие от `AdditionProvider`, это **является**
  breaking-добавлением для любого стороннего backend'а, созданного до
  этапа 0.22, поскольку ни один из этих traits не имеет реализации по
  умолчанию; существующий сторонний backend должен реализовать оба, чтобы
  снова удовлетворять `LatticeBackend`.
- **Публичные методы `Lattice<B>`**: `routes`, `add_route`,
  `remove_route`, `interfaces`, `set_interface_config`, `dns_config`,
  `set_dns_config`, `firewall_rules`, `set_firewall_policy`,
  `clear_firewall_policy`, `neighbors`, `add_static_neighbor`,
  `remove_static_neighbor`, `addresses`, `add_address`, `remove_address`,
  `current_state`, `apply`, `diff`, `validate_plan`,
  `snapshot_for_mutation`, `execute_plan`, `execute_apply_plan`,
  `capabilities`, `supports`, `watch`, `watch_async` (за флагом функции
  `async`), `watch_filtered`, `watch_with_additions`, а также конструкторы
  `connect` для каждой платформы (по одной реализации, помеченной
  `#[cfg(target_os = "...")]`, на поддерживаемую ОС, с одной и той же
  публичной сигнатурой `fn connect() -> Result<Self>` на каждой
  платформе).

Этот чек-лист — это тот самый рецензируемый инвентарь, который требуется
аудитом заморозки публичного API; сам по себе он не меняет форму или
атрибут ни одного типа. Он выявил два вопроса, оба теперь решены: пометка
"Факты, объявляемые backend'ом не через `Capability`" выше (заморожены с
той же дисциплиной, что и `Capability` — изменение формы не требуется) и
вопрос о `#[non_exhaustive]`-статусе `Error`/`PlatformErrorCode`, решённый
в ADR-0015 (`Error` получил `#[non_exhaustive]`; `PlatformErrorCode`
— намеренно нет).

## Матрица поддержки платформ и пробелы

Реализация provider/mutator traits полная и одинаковая на всех трёх
нативных backend'ах (`net-lattice-backend-linux`, `net-lattice-backend-
windows`, `net-lattice-backend-darwin`) для каждого домена (маршрут,
интерфейс, сосед, адрес, DNS), а также `EventProvider` и
блочно-реализованный (blanket-implemented) `SnapshotProvider`.
`.github/workflows/ci.yml` собирает, прогоняет clippy и тесты на всех
трёх нативных ОС-раннерах при каждом коммите, поэтому этот паритет
непрерывно проверяется, а не документируется один раз с риском устареть.

На фоне этого в остальном единообразного базиса существуют три
подтверждённых, уже покрытых тестами пробела по платформам:

- **Windows: нет флага `NEIGHBOR_MONITORING`.** У Windows нет нативного
  механизма уведомления об изменениях таблицы соседей, поэтому
  `WindowsBackend::capabilities()` никогда не устанавливает
  `Capability::NEIGHBOR_MONITORING` и, соответственно, никогда не
  объявляет составной флаг `Capability::MONITORING` — все остальные
  под-флаги мониторинга (`ROUTE_MONITORING`, `INTERFACE_MONITORING`,
  `ADDRESS_MONITORING`) установлены. Это осознанное решение, а не
  недосмотр: см. `capabilities()` в
  `crates/net-lattice-backend-windows/src/lib.rs` и специальный
  регрессионный тест
  `windows_backend_does_not_advertise_neighbor_monitoring` в том же файле.
- **Darwin: `RouteConfig::metric`/`Route::metric` не поддерживаются.**
  Ни один нативный вызов не читает и не пишет метрику маршрута через
  route-socket API macOS/BSD (см. `crates/net-lattice-model/src/route.rs`).
  На Darwin значение молча игнорируется, а не отклоняется, и
  `Diff::compute` не даёт гарантии сходимости (convergence) для этого
  случая на данной платформе (зафиксированное архитектурное решение,
  ADR-0010 §3(a)).
- **Darwin: переопределения порядка замены маршрута и поддержки
  метрики.** Darwin переопределяет два описанных выше факта, объявляемых
  backend'ом не через `Capability`, отклоняясь от значений по умолчанию
  для Linux/Windows: `route_replace_order()` возвращает
  `RouteReplaceOrder::AddBeforeRemove` (вместо значения по умолчанию
  `RemoveBeforeAdd`), а `supports_route_metric()` возвращает `false`
  (вместо значения по умолчанию `true`), поскольку нативный ключ
  удаления маршрута на Darwin не может различить находящуюся в процессе
  замену так, как это могут Linux/Windows. См.
  `crates/net-lattice-platform/src/route_provider.rs` для определений и
  значений по умолчанию этих методов trait'а, и собственную реализацию
  `RouteMutator` Darwin-backend'а для переопределений.

Эти же два факта, объявляемых backend'ом не через `Capability`, —
`RouteMutator::supports_route_metric` и
`RouteMutator::route_replace_order` (см. "Факты, объявляемые backend'ом не
через `Capability`" выше) — названы здесь ещё раз, поскольку читатель,
просматривающий этот раздел матрицы платформ в поисках "чем отличаются
backend'ы", должен увидеть их рядом с пробелом на основе `Capability`, а
не только в чек-листе замороженного API выше.

Никаких других пробелов в возможностях или поведении между тремя
backend'ами, кроме перечисленных трёх, обнаружено не было; этот раздел —
единственное место, которое сводит их воедино для читателя, желающего
узнать "чем отличаются платформы" без сверки с doc-комментариями трёх
разных исходных файлов.

**Конвенция предупреждающего маркера для opt-in, ненативных "дополнений"
(additions).** Нативный флаг `Capability` отображается обычной галочкой (✓)
в любой матрице, перечисляющей поддержку по backend'ам; `Addition`
(`net_lattice_platform::Addition`), объявляемый backend'ом через
`AdditionProvider::additions()`, отображается отдельным предупреждающим
маркером (⚠) вместо неё — никогда той же галочкой, что и нативный
`Capability`, и никогда не сливается в одну ячейку с галочкой. Backend, у
которого нет ни `Capability`, ни покрывающего его `Addition`, сохраняет
существующий плоский маркер "не поддерживается"; оба пробела Darwin выше —
именно такой случай и отображаются без изменений. Единственная строка,
к которой это применимо сейчас: у Windows нет нативного
`Capability::NEIGHBOR_MONITORING` (пробел, описанный выше), но она
объявляет `Addition::NEIGHBOR_MONITORING_POLLING` через свою реализацию
`AdditionProvider` (`crates/net-lattice-backend-windows/src/lib.rs`) —
вызывающий, явно подключивший её через `Lattice::watch_with_additions`,
получает события изменения соседей, синтезированные через polling,
помеченные ⚠, а не ✓, чтобы обозначить: это opt-in-замена с более слабыми
гарантиями, а не эквивалент нативного механизма. Оговорка об уровне
качества за маркером ⚠ (различия в задержке, порядке, склеивании
(coalescing) и стоимости ресурсов относительно нативного мониторинга)
документируется один раз в собственном doc-комментарии
`Addition::NEIGHBOR_MONITORING_POLLING`
(`crates/net-lattice-platform/src/addition.rs`) и кратко изложена в разделе
"Гарантии доставки событий" ниже — этот раздел фиксирует только конвенцию
маркера и строку, к которой она сейчас применяется, не повторяя суть
оговорки. Эта конвенция доступна для любого будущего дополнения сверх
первого; добавление нового флага `Addition` расширяет этот же абзац, а не
вводит вторую конвенцию.

## Гарантии доставки событий

Этот раздел — единственное каноническое описание того, что на самом деле
обещают `Lattice::watch`/`watch_filtered` (на основе
`EventProvider`/`EventReceiver`). Он сводит воедино гарантии, ранее
разбросанные по собственному doc-комментарию `EventReceiver`
(`crates/net-lattice-platform/src/event_provider.rs`), doc-комментарию
`ChangeKind` (`crates/net-lattice-model/src/event.rs`) и разделу о контракте
mutation выше в этом документе — со ссылками на эти doc-комментарии, а не с
дублированием их текста.

**Обычная доставка — at-most-once, а не at-least-once и не exactly-once.**
Backend помещает каждое наблюдаемое изменение в очередь один раз; ничто не
повторяет и не дублирует событие. Когда consumer отстаёт и ограниченная
per-watcher очередь заполняется, backend отбрасывает переполняющие ordinary
события, а не блокирует нативный producer и не расширяет очередь
неограниченно — Net Lattice никогда не обещает, что каждое нативное
изменение в итоге будет замечено как отдельное событие.

**Переполнение получает гарантированный сигнал resync, а не тихую потерю.**
Всякий раз, когда одно или несколько ordinary событий отбрасываются
из-за заполненной очереди, backend сворачивает эту потерю в ровно одно
`Event::ResyncRequired` для затронутого домена, доставляемое перед
следующим ordinary событием этого домена. Consumer, получивший
`Event::ResyncRequired`, обязан перечитать указанный домен через свой read
provider, прежде чем доверять последующим ordinary событиям как
согласованному представлению — сам сигнал resync гарантированно появляется
(он не подвержен тому же отбрасыванию, что и ordinary события), но
конкретные отброшенные изменения, которые он замещает, из потока событий не
восстановить.

**Порядок сохраняется только per-producer, а не глобально.** Receiver
сохраняет порядок, в котором его backend-producer помещал события в
очередь, но **не** даёт гарантии cross-domain порядка или причинности —
событие в одном домене (маршруты) не несёт отношения порядка к событию в
другом домене (интерфейсы), даже если соответствующие нативные изменения
были причинно связаны.

**Нет initial snapshot и нет гарантии доставки событий о собственных
mutation вызывающего.** Запуск watch не выдаёт текущее состояние как
синтетические события; snapshot получают через собственный read provider
домена (`RouteProvider::routes()` и аналогичные), никогда — из потока
событий. Успешная mutation вызывающего не гарантированно порождает
соответствующее событие — доставка событий является отдельным, eventually
consistent signal path относительно контракта mutation/чтения, описанного
выше, а не заменой перечитывания состояния после mutation, результат
которой нужен вызывающему.

**`ChangeKind::Changed` — консервативный fallback, а не гарантия
жизненного цикла.** Native sources часто не могут отличить на уровне ОС
"объект создан" от "объект изменён". `ChangeKind::Changed` (см. собственный
doc-комментарий `ChangeKind`) — результат, который Net Lattice сообщает,
когда native source не предоставляет однозначный переход
create/modify/remove; сегодня он не несёт field-mask payload с описанием
того, что изменилось — consumer, которому нужно знать, что изменилось,
перечитывает объект через соответствующий provider.

**У DNS нет источника событий.** Ни один backend не выдаёт события
изменения DNS; вызывающий должен вызвать `dns_config()` после DNS mutation
(или на любом выбранном интервале polling), чтобы увидеть результирующий
view.

**Итог в явной терминологии гарантий доставки:** обычные события по
отдельным объектам — *at-most-once* (никогда не дублируются, могут
отбрасываться при устойчивом backpressure); переполнение *гарантированно*
сигнализируется ровно одним `Event::ResyncRequired` на затронутый домен
перед возобновлением ordinary событий этого домена, но гарантия покрывает
только *сигнал*, а не восстановление конкретных отброшенных изменений. Net
Lattice нигде в пути событий не даёт гарантии exactly-once или полностью
гарантированной доставки.

### События из источников уровня "дополнений": отдельный, более слабый уровень гарантий

`Lattice::watch_with_additions` объединяет нативные события с событиями,
синтезированными явно запрошенным `net_lattice_platform::Addition`
(например, `Addition::NEIGHBOR_MONITORING_POLLING` у Windows, которая
опрашивает `NeighborProvider::neighbors()` вместо нативной push-подписки,
отсутствующей у Windows — см. конвенцию маркера ⚠ в разделе "Матрица
поддержки платформ и пробелы" выше, под которой отображается это
дополнение). События из источников уровня "дополнений" используют ту же
форму `Event`/`EventReceiver` объединённого потока и тот же существующий
контракт at-most-once/склеенного resync/отсутствия cross-domain порядка,
описанный выше, но несут дополнительные, строго более слабые собственные
гарантии, авторитетно документированные в doc-комментарии каждого флага
`Addition` (`crates/net-lattice-platform/src/addition.rs`), а не
продублированные здесь. Кратко для читателя:

- **Задержка** ограничена интервалом polling дополнения (по умолчанию 2
  секунды для `NEIGHBOR_MONITORING_POLLING`), а не sub-second/push-based —
  в отличие от нативного producer'а, событие из источника уровня
  "дополнений" может проявиться с задержкой до одного интервала.
- **Порядок** не гарантируется относительно нативной части того же
  объединённого потока, в дополнение к (а не вместо) уже существующей
  гарантии отсутствия cross-domain порядка выше — чередование
  addition-vs-native не упорядочено так же, как уже неупорядочены
  cross-domain нативные события.
- **Склеивание (coalescing)** может сделать изменение полностью
  невидимым: два противоположных изменения, взаимно отменяющиеся в рамках
  одного интервала polling (например, сосед добавлен, а затем удалён до
  следующего опроса), никогда не появятся в потоке — это реальное отличие
  в поведении от нативного мониторинга, а не просто задержка.
- **Стоимость ресурсов** ненулевая и контролируется вызывающим:
  дополнение запускает один фоновый поток/таймер только тогда, когда
  вызывающий явно запросил его через `watch_with_additions`, и завершает
  его при уничтожении (drop) `EventReceiver` так же, как это происходит с
  нативной подпиской — никогда не запускается неявно.

Ни одна гарантия, описанная ранее в этом разделе, не ослабляется и не
переосмысливается этим подразделом; события из источников уровня
"дополнений" дополняют нативный путь событий и всегда отличимы от него по
уровню качества. Расширяйте этот подраздел на месте для любого будущего
`Addition`, а не создавайте второй, конкурирующий раздел "Гарантии доставки
событий" в другом месте этого документа.

## Явные не-цели этой архитектуры

- **Ни один крейт не является Linux-, Windows- или macOS-специфичным, кроме
  самих backend-крейтов.** `net-lattice-core`, `net-lattice-ip`, `net-lattice-model` и
  `net-lattice-platform` обязаны оставаться свободными от `cfg(target_os = "...")`
  и OS-биндингов.
- **`net-lattice-platform` никогда не зависит от `net-lattice-model`.** Его
  provider-traits обязаны оставаться generic относительно associated types,
  а не обрастать прямой зависимостью от конкретных типов модели, даже когда
  это было бы моментально удобно (например, добавление нового метода
  provider'а, чья наиболее очевидная сигнатура напрямую называет
  `net_lattice_model::route::Route`). Если provider-trait невозможно выразить
  без называния конкретного типа модели — это сигнал пересмотреть форму
  trait'а, а не добавлять зависимость.
- **Никакого интерфейса командной строки.** В соответствии с не-целями
  проекта в [README.md](README.md), крейт `net-lattice-cli` не планируется.
- **Никакого преждевременного создания крейтов.** Декларативная конфигурация
  и транзакционные apply/rollback с тех пор реализованы (стадии 0.19–0.20)
  как модули внутри существующих крейтов (`net-lattice-model`,
  `net-lattice`), согласно правилу «Границы крейта vs. границы модуля» выше,
  а не как новые крейты. Крейты для оставшихся будущих доменов (VLAN, VRF,
  namespaces) описаны в дорожной карте ниже, но не создаются, пока под них
  нет реального кода.
- **Никакого управления tunnel-интерфейсами.** TUN/TAP tunnel-интерфейсы —
  зона ответственности отдельного репозитория
  [tunnel-lattice](https://github.com/F000NKKK/tunnel-lattice) в более
  широкой экосистеме Lattice, а не дорожной карты этого крейта; см. раздел
  README.md «The Lattice ecosystem».

## Дорожная карта

`1.0` — текущая стабильная линия: полная кроссплатформенная поддержка
inspection, monitoring, imperative mutation, упорядоченных транзакций,
декларативного apply и управления native-firewall policy, каждая с
privileged regression coverage на Linux, Windows и macOS. Аудированную
поверхность см. в «Замороженная публичная поверхность API версии 1.0» выше,
датированную историю — в [CHANGELOG.md](CHANGELOG.md).

Запланировано на 2.0+ — каждый пункт достаточно велик для отдельного
архитектурного прохода, ни один не является prerequisite для 1.0:

| Домен | Содержание |
|---|---|
| VLAN | модель read/intent/mutation для tagged-интерфейсов, единая для всех трёх backend'ов |
| VRF | модель изоляции таблиц маршрутизации и привязка по backend'ам |
| Namespaces | изоляция process/network namespace — асимметрична между Linux/Windows/macOS, требует отдельного архитектурного прохода до начала реализации |

Управление tunnel-интерфейсами полностью вне зоны ответственности этого
репозитория (см. крейт экосистемы `tunnel-lattice`).
