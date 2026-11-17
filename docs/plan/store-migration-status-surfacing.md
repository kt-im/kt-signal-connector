# store 迁移状态：从 connector 暴露到桌面（A/B/C 三案 · 只读方案）

- 起草日期：2026-11-12
- 连接器基线：`kt-signal-connector` worktree `runtime-state-authority` @ `963cee6`（store 迁移编排已落地）
- 桌面基线：`/Users/tanye/test/kt/kt-desktop-wt-signal`
- 性质：**实施前设计文档，只读**。本文件不改任何代码、schema、测试；落盘后不 commit。
- 硬约束（用户给定）：**默认 off（`KT_ENGINE_STORE_MIGRATE` 未设/off）时，不得新增任何 wire 字段。**

引用缩写：

- `[C]` = 本连接器仓库根（/Users/tanye/test/kt/kt-signal-connector.worktrees/runtime-state-authority）
- `[D]` = 桌面仓库根（/Users/tanye/test/kt/kt-desktop-wt-signal）

---

## 0. 现状核实（先读后写，全部为仓库实况）

| 事实 | 出处 |
|---|---|
| 迁移开关三值 `off`/`dry-run`/`apply`，默认 off，未知值一律 off；**运行装配时读一次**，不按槽读 | `[C] src/pool.rs:149-231`；装配点 `src/registry.rs:3615-3626` |
| off 时闸的第一句就返回：不派生 key、不 spawn 迁移器、不读盘 | `[C] src/pool.rs:1264-1271` |
| 闸只有两个入口：常驻窗口 `start_resident` 与冷唤醒 `ensure_resident`（后者在 wake 锁内，闸先于 `supervisor.start`） | `[C] src/pool.rs:1179-1221`、`src/pool.rs:1460-1475` |
| 闸的裁决是四档：`Start` / `Retry` / `Blocked` / `Misconfigured` | `[C] src/pool.rs:239-253` |
| 终态（exit 11）写 `StoreMigrationBlock{code, exit, message}` 到槽位，**进程内永不清除** | `[C] src/pool.rs:255-275`、`src/pool.rs:719-723`、`src/pool.rs:1405`、`src/pool.rs:755-760` |
| 锁存存在时，闸不再 spawn 迁移器也不再 spawn 引擎，直接答 `Blocked` | `[C] src/pool.rs:1294-1296` |
| 可重试档（exit 10 耗尽 / 超时 / spawn 失败 / 其它退出码）**不写任何状态**，只写日志（outcome=`retry_pending`） | `[C] src/pool.rs:1332-1345`、`src/pool.rs:1385-1400` |
| exit 2（混版/无子模式）不锁存、本轮不重试，下次启动再来（日志按 60s 节流） | `[C] src/pool.rs:1428-1441`、`src/pool.rs:650-700` |
| 池化 `runtime.start` 对闸拒绝**只 `continue`**，不留任何痕迹 | `[C] src/registry.rs:995-1023`、`src/pool.rs:1197-1200` |
| 全部槽都没起来 → `RUNTIME_START_FAILED`，`retryable:true`（**对终态锁存是假话**） | `[C] src/registry.rs:1019-1022`、`src/host.rs:4551-4564` |
| 部分槽被锁存、别的槽起来了 → `runtime.start` **成功**，被锁存账号只表现为 `stopped` | `[C] src/registry.rs:1023` |
| 单账号请求命中锁存 → `CAPABILITY_UNAVAILABLE`，retryable 由档位给（锁存 false / 可重试 true） | `[C] src/pool.rs:347-364`、`src/pool.rs:1460-1475` |
| `runtime.status` 的 `engines[]` 只在池化形态出现（legacy 形态整键缺席，字节不变） | `[C] src/registry.rs:158-196`、`src/registry.rs:908-945`、测试 `src/registry.rs:4354` |
| `engines[]` 现有字段：`accountId/proxyGroup/state/pid/rssBytes/resourcePressure/resident/restarts`，**没有失败原因** | `[C] src/pool.rs:599-615`、`src/pool.rs:1574-1592` |
| 池化**没有**逐账号状态事件；引擎状态变化只扇出聚合 `runtime.stateChanged`（`AggregateEngineStatus`，不含槽位原因）；闸拒绝不产生任何引擎事件 | `[C] src/registry.rs:628-635`、`src/registry.rs:745-755`、`src/registry.rs:832-862` |
| `degraded` 只在"有槽在跑且另有槽没跑"时为 true；全槽被锁存时是 `stopped` + `degraded:false` | `[C] src/registry.rs:858-860` |
| `runtime.doctor` 只遍历 legacy group supervisor，池化下 `groups` 为空 → **看不到任何槽**；`store` 面讲的是 SQLite schema 迁移（`lastMigrationFailure`），不是 engine store 格式迁移 | `[C] src/doctor.rs:397-417`、`src/doctor.rs:424`、`src/store.rs:992-1001`、`src/store.rs:1015-1025` |
| 可观测只有日志行（`store_migration_outcome`），metrics 只有一个 `store_migration_failure`（SQLite 面） | `[C] src/pool.rs:1370-1440`、`src/metrics.rs:493` |
| 桌面只在 `runtime.start` 的结果里取 `proxyGroups`，**从不读 `engines[]`**，也**从不调 `runtime.status`** | `[D] electron/main/signal/connectorSupervisor.ts:1524`、`:1905-1917`、`:664-694` |
| 桌面池聚合按字段白名单拼装，未投影的字段会被**静默丢弃** | `[D] electron/main/signal/connectorPool.ts:205-249` |
| 桌面把 `CAPABILITY_UNAVAILABLE` 归因为"代理分组未在本次启动配置中" | `[D] src/view/signal/signalErrorCopy.ts:36` |
| 引擎证据码 `code` 只受整份 stdout 上限约束，**字符串本身没有长度上界** | `[C] src/engine.rs:311-327`、`src/engine.rs:447-478` |

### 0.1 三个结论（这就是本方案要解决的问题）

1. **状态面缺字段**：`runtime.status` 只能告诉你"这个账号的引擎停着"，说不出"为什么停"——锁存、可重试、从没试过，三者长得一模一样（`[C] src/pool.rs:599-615`）。
2. **事件面缺事件**：冷唤醒期间才发生的锁存没有任何推送路径，桌面只能靠下一次主动读（`[C] src/registry.rs:745-755`；`[D]` 侧更是连 `runtime.status` 都不调）。
3. **错误面在撒谎**：全槽锁死时 `RUNTIME_START_FAILED retryable:true` 让宿主一直重试一个永远不会自愈的终态（`[C] src/host.rs:4558-4563`）；单账号请求撞上锁存时，宿主文案把它归因成代理分组配置问题（`[D] src/view/signal/signalErrorCopy.ts:36`）。

---

## 1. 三案共用的地基（先定死，避免每案各写一套）

### 1.1 快照语义

`runtime.status` 是一次**快照**，不是订阅。三案都遵守：

- 快照反映"本进程到目前为止的闸裁决"，不承诺实时；
- 缺席（字段/key 不存在）= **没有可说的**，不等于"已加密"/"健康"/"没迁移过"；
- 进程重启即清空（锁存是内存态，`[C] src/pool.rs:719-723`），所以新进程第一次读可能"什么原因都没有"，直到某次 start 真正过了闸。

### 1.2 可重试档必须新增一份内存记录（A/B 都需要）

今天"可重试"只存在于日志里：`Retry` 决策返回后没有任何落点（`[C] src/pool.rs:1385-1400`）。要让桌面说"正在重试/下次启动再试"，必须新增一份**不参与决策**的记录：

- 字段：`{code, at}`（`at` 只进日志/诊断，不上 wire，见 1.3）；
- 写：闸返回 `Retry` 或 `Misconfigured` 时写入（`[C] src/pool.rs:1395-1440`）；
- 清：下一次闸返回 `Start`（任一 outcome：`disabled/already_running/already_migrated/migrated/noop/absent/completed/planned/planned_failed`）时清除；
- **绝不参与决策**：读它不得改变任何 spawn 行为，否则就把"重试"变成了"锁存"。

这条对 A 和 B 是同一份成本；C 不需要。

### 1.3 字段预算（三案共同的红线）

- **只带 code，不带 message**：connector 的英文句子已经有 320/365 字符的实例（`[C] src/pool.rs:281-336`），而 schema 给 `error.message` 的上界是 256（`[C] schemas/connector-api-v1.schema.json:9589-9591`）。桌面文案由桌面拥有（`[D] src/view/signal/signalErrorCopy.ts` 的既有纪律），状态面复述长句只会制造第二份会漂移的散文。
- **不带 exit**：`exit` 是引擎内部证据（`[C] src/pool.rs:259-265`），对桌面动作没有增量；留在日志和现有错误面。
- **不带路径 / 号码 / key / 明文**：账号标识沿用 `accountId`（`engines[]` 已有，`[C] src/pool.rs:600`）。
- **code 必须 clamp**：引擎证据码今天没有长度上界（`[C] src/engine.rs:462-476`），状态面要被反复渲染，必须截断到固定预算（建议 64 字符，超限即截断并保留可辨识前缀），A/B 在写入锁存/重试记录处做一次。

### 1.4 presence 规则（"off 零字段"的可证明写法）

三案都要满足：**默认 off 时，任何 wire 帧里都不得出现新字段。** 证明方式不能靠"反正 off 时不会锁存"的口头推理，必须两层：

1. 结构上不可能：off 时闸在第一句返回 `Start{outcome:"disabled"}`（`[C] src/pool.rs:1264-1271`），锁存与重试记录都不会被写入；
2. 投影上再挡一次：序列化前显式判 `config.store_migration.is_enabled()`（`[C] src/pool.rs:231`），为假则强制不产出该字段——这样将来即使有人在 off 路径上误写了记录，wire 也不会漏。
3. 测试必须钉"整帧不含该 key"，而不只是"值为 null"。

### 1.5 取数缺口（A/B 都要补的一步，不是 C 的责任）

`runtime.start` 失败时响应里**没有 result**（`[C] src/host.rs:1566-1575`），所以"全槽锁死"这个最需要解释的场景，恰恰拿不到状态体。两条出路：

- **推荐**：桌面在收到 `RUNTIME_START_FAILED` 后补一次 `runtime.status`（一次额外往返，wire 零新增）；
- 不推荐：把块列表塞进 `error.data`——那会在同一事实上有两个来源（status 与 error），必然漂移。

同样地，桌面在收到账号请求的 `CAPABILITY_UNAVAILABLE`（`[C] src/pool.rs:347-356`）后补一次 `runtime.status`，是"冷唤醒期锁存"唯一的及时可见点。

### 1.6 桌面显示口径（三案共用）

- **按 code 出中文，不显示 connector 的英文句子**；未知 code 走统一兜底，并把 code 放进诊断/详情，不进主文案。
- **不得由缺席推断健康**：不能因为没看到 `storeMigration` 就说"已加密/无需迁移"。
- 两类动作必须分开：`blocked` 给"要人动手"的补救（删除本地数据重链 / 恢复 store key / 换匹配组件），`retrying` 给"等下一次启动"的说明，且**不给重试按钮**。

---

## 2. 案 A：`engines[]` 增量字段 `storeMigration{state, code, retryable}`

### 2.1 wire 形状

`storeMigration` 是 `AccountEngineStatus` 的一个**可选成员**，只在该槽有话说时出现：

```json
{
  "state": "running",
  "proxyGroups": [],
  "engines": [
    {
      "accountId": "8f1c…",
      "proxyGroup": "default",
      "state": "stopped",
      "resourcePressure": false,
      "resident": true,
      "restarts": 0,
      "storeMigration": { "state": "blocked", "code": "StoreKeyRequired", "retryable": false }
    },
    {
      "accountId": "2b7d…",
      "proxyGroup": "default",
      "state": "stopped",
      "resourcePressure": false,
      "resident": true,
      "restarts": 0,
      "storeMigration": { "state": "retrying", "code": "store_busy", "retryable": true }
    },
    {
      "accountId": "c0a4…",
      "proxyGroup": "default",
      "state": "running",
      "resourcePressure": false,
      "resident": true,
      "restarts": 1
    }
  ]
}
```

字段定义：

| 字段 | 类型 | 值域 | 说明 |
|---|---|---|---|
| `state` | string | `blocked` \| `retrying` | `blocked` = 进程内终态锁存（exit 11）；`retrying` = 上一次过闸是可重试档（10 耗尽 / 超时 / spawn 失败 / 其它 / exit 2），下次启动会再试 |
| `code` | string | 引擎证据码（clamp 64） | 原样透传（`StoreKeyRequired`/`store_corrupt`/`store_busy`/…），未知码不臆造 |
| `retryable` | boolean | `blocked→false`，`retrying→true` | 派生常量，不是新事实（见 2.7 的"第二个会撒谎的地方"） |

presence：**只在该槽有 `blocked`/`retrying` 记录、且模式非 off 时出现**；其它情况整键缺席（不是 `null`，不是 `{}`）。

### 2.2 off 零字段

- 结构上：off 时无锁存无重试（见 1.4）；
- 投影上：`AccountPool::statuses`（`[C] src/pool.rs:1574`）里显式 `if !self.config.store_migration.is_enabled() { field = None }`；
- 测试：`off_mode_never_names_store_migration_on_the_wire`（off + apply 两次对照，序列化整帧后断言 `"storeMigration"` 子串不出现）。

### 2.3 旧端兼容

| 组合 | 行为 |
|---|---|
| 新 connector + 旧桌面 | 旧桌面从不读 `engines[]`（`[D] connectorSupervisor.ts:1905-1917` 只读 `proxyGroups`），整块被忽略；`engines` 本身的存在也不影响旧桌面（它是本轮 pool 引入的既有键，不是本案新增） |
| 新桌面 + 旧 connector | `engines` 整键缺席（legacy 形态，`[C] src/registry.rs:4354` 钉住）或条目无 `storeMigration`（pre-1.291 池化）→ 桌面按"没有可说"处理，绝不降级成"健康" |
| 新旧混合、多 connector | `engines[]` 天然挂在各自 connector 的 `connectors[]` 下（`[D] connectorPool.ts:231-249`），归属由外层给出，不需要额外字段 |

### 2.4 桌面能说什么话

按 `storeMigration.state` + `code` 出词，主文案示例（中文由桌面拥有，connector 不供英文句子）：

| 条件 | 桌面文案（建议） |
|---|---|
| `blocked` + `StoreKeyRequired`/`StoreKeyInvalid`/`store_key_mismatch`/`store_key_rejected` | 「该账号的本地数据无法用当前存储密钥打开（<code>）。明文数据与备份都还在：请恢复迁移时使用的存储密钥，或删除该账号本地数据后重新关联，然后重启客户端。」 |
| `blocked` + `store_corrupt`/`store_state_invalid`/`store_migration_verify_failed` | 「该账号本地数据损坏或校验未通过（<code>），无法转换为加密存储。请删除该账号本地数据后重新关联。」 |
| `blocked` + `StoreCipherUnavailable` | 「当前引擎组件不支持加密存储（<code>）。这是组件版本问题，**请不要删除账号数据**：安装与本客户端同版本的组件后重启。」 |
| `blocked` + 未知码 | 「该账号本地数据迁移失败（<code>），重试不会自愈。请重启客户端；仍失败请删除该账号本地数据后重新关联。」 |
| `retrying` + `store_busy` | 「该账号本地数据正忙，本次没有启动引擎；下次启动会自动重试，数据未改动。」 |
| `retrying` + 其它码 | 「该账号本地数据尚未就绪（<code>），下次启动会自动重试。」 |
| 缺席 | 不说话（并在实现注释里写死"缺席 ≠ 健康"） |

通道级：全槽 `blocked` 时给一句「N 个账号的本地数据需要处理，Signal 通道暂时无法启动」，并提供"逐个处理"入口（跳账号列表）。

### 2.5 改动文件与测试

连接器（`[C]`）：

1. `src/pool.rs:599`：`AccountEngineStatus` 增 `store_migration: Option<StoreMigrationFace>`（`#[serde(skip_serializing_if = "Option::is_none")]`）；新增 `StoreMigrationFace`（`state/code/retryable`，`rename_all="camelCase"`）与 `state` 的封闭词表常量。
2. `src/pool.rs:719-723`：`AccountSlot` 增 `migration_retry: StdMutex<Option<StoreMigrationRetry>>`（`code` + `at`，`at` 不上 wire）；配套 `migration_retry()` / `record_migration_retry()` / `clear_migration_retry()`，与 `latch_migration_block`（`:762`）同一风格。
3. `src/pool.rs:1264-1445` `gate_slot_start`：每个 `Start` 分支清 retry；`Retry`/`Misconfigured` 分支写 retry；`Blocked` 分支照旧锁存（`:1405`）。
4. `src/pool.rs:1574` `statuses()`：一次遍历内组装 `store_migration`（先判 off，再判 `blocked`，再判 `retrying`），**同一个槽只可能出一个 face**。
5. 文档 `docs/implementation-plan.md`：`## §4.277` + Status 增 `Contract revision: 1.291`。

测试：

- `tests/store_migrate_orchestration.rs`（现有 fake engine 装置可直接复用）：
  - `off_mode_never_names_store_migration_on_the_wire`
  - `a_terminal_latch_rides_the_engines_entry_as_blocked`（复用 `:522` 的 11 锁存场景，断言 `state/code/retryable` 与 `engines[].state != "running"`）
  - `an_exhausted_retryable_failure_rides_as_retrying_without_latching`（复用 `:492` 场景，断言下一次 start 仍会再试）
  - `a_successful_start_clears_the_retrying_face`（先 10 耗尽，再 0 成功，再读 status）
  - `a_cipherless_engine_reports_the_deployment_code_not_a_relink_code`（`:1017` 场景，wire 面只带 `StoreCipherUnavailable`）
  - `the_status_face_carries_no_key_path_number_or_hex`（对序列化整帧跑现有的"无 ≥64 位 hex / 无 key"断言风格）
- `src/registry.rs:4354` 的既有结构测试不改（legacy 形态 `engines` 缺席的断言继续有效）。

桌面（`[D]`）：

1. `shared/signalWire.ts:153`：给 `SignalRuntimeStatus` 增一个**窄投影**（建议 `storeMigrations?: SignalStoreMigrationStatus[]`，字段 `{connectorId?, accountId, state, code, retryable}`），**不把整套 `engines[]` 暴露给渲染层**。
2. `electron/main/signal/connectorSupervisor.ts:1905` `observeRuntimeStartResult`：从 `runtime.start` 结果里同时读 `engines[]`，只挑带 `storeMigration` 的条目存快照（与 `proxyGroupStatuses` 同级）。
3. 新增 `refreshRuntimeStatus()`：`client.request('runtime.status', {})`，覆盖快照；在 (a) IPC `getRuntimeStatus`（`[D] electron/main/signal/registerIpc.ts:902`）与 (b) 账号域请求收到 `CAPABILITY_UNAVAILABLE` 的既有错误归一位置（桌面文案统一由 `[D] src/view/signal/signalErrorCopy.ts` 出词，实现时在该错误分支补一次刷新）各触发一次。
4. `getStatus()`（`:664`）投影该字段；`connectorPool.ts:205` 聚合时把各 connector 的条目合并并在条目上补 `connectorId`。
5. `src/view/signal/signalErrorCopy.ts` 增按键（`store_migration_blocked_key` / `store_migration_blocked_corrupt` / `store_migration_blocked_cipher_unavailable` / `store_migration_retrying` / `store_migration_unknown`），并按既有纪律补 en 兜底（`signalErrorCopy.spec` 钉住）。
6. 账号设置页/账号行渲染（现有账号面：`[D] src/view/signal/settings/SignalSettingsPage.vue`）。

桌面测试：新增 `tests/unit/signalStoreMigrationStatus.spec.ts`（快照解析、缺字段不误判、多 connector 归属、未知 code 兜底）；`signalErrorCopy.spec` 补 en 键。

### 2.6 契约版本

- connector 契约 **1.291**（下一版是 1.290 之后，`[C] docs/implementation-plan.md:21293`）；
- `apiVersion` 仍 `"1.0"`（`[C] src/lib.rs:33`），原地加法演进；
- `ENGINE_CONTRACT_MAX_REVISION` 仍 `"1.286"`（`[C] src/engine_contract.rs:68`）——本案不动 engine 侧协议；
- `schemas/connector-api-v1.schema.json` **零改动**：响应 `result` 是开放面（`[C] schemas/connector-api-v1.schema.json:7289` 的 `response` 定义不约束 result 形状），A 不改错误码/事件词表。

### 2.7 失败模式

**字段撒谎（报了不成立的事实）**

| 风险 | 会不会发生 | 处置 |
|---|---|---|
| `blocked` 但该账号其实在服务 | 构造上不可能：锁存只在"引擎未运行"过闸时写（`[C] src/pool.rs:1285-1290` 先短路 Running，`:1405` 才锁存），且锁存永不清除（`:755`）；一个已在跑的引擎不会再过闸 | 仍加一条不变量测试：`blocked ⇒ engines[].state != running`（同一快照内） |
| `retrying` 但下一次启动已经成功 | 会发生——如果没有清空规则 | 1.2 的清空规则 + `a_successful_start_clears_the_retrying_face` |
| `retrying` 报了"从没试过"的槽（无 data dir / 无派生 key / exit 0） | 不会，如果只在 `Retry`/`Misconfigured` 写 | 测试覆盖 "no data dir → 无 face"（复用 `:650` 场景） |
| `retryable` 与 `state` 互相矛盾 | 派生常量 + 词表常量，理论上不会 | 一个断言把映射钉死（`blocked↔false`、`retrying↔true`）；这是本案**自带的冗余**，见第 5 节 |
| code 是引擎给的、可能超长/诡异 | 会（`[C] src/engine.rs:462-476` 无长度界） | 写入处 clamp 64；测试喂一个 4 KiB code |

**字段过期（曾经对，现在不对）**

| 场景 | 后果 | 处置 |
|---|---|---|
| 冷唤醒期间才锁存 | 桌面没有事件可听（`[C] src/registry.rs:745-755`），看不到，直到下一次读 | 1.5 的"收到 CAPABILITY_UNAVAILABLE 补一次 runtime.status"；这是本案**残留的新鲜度上限**，写进文档不假装实时 |
| 连接器进程重启 | 锁存清空，账号在下次过闸前表现为普通 `stopped`（无原因） | 文档明确"缺席 ≠ 健康"；桌面文案不因缺席渲染任何结论 |
| 账号被删除 | 槽位被丢弃（`[C] src/pool.rs:1452` 从槽读），face 随之消失；无残留条目 | 无需处置（A 的天然优势：face 与槽同生命周期） |
| 桌面把快照存太久 | 显示过期原因 | 每次 `getRuntimeStatus` 优先用刚读到的快照；快照带"读到时刻"，超过一个刷新周期就只显示"上次检查"语义（不新造 wire 字段，纯桌面侧） |

---

## 3. 案 B：`runtime.status` 顶层独立数组 `migrationBlocks[]`

### 3.1 wire 形状

```json
{
  "state": "running",
  "proxyGroups": [],
  "engines": [ /* 与今天完全一致，不加任何成员 */ ],
  "migrationBlocks": [
    { "accountId": "8f1c…", "state": "blocked",  "code": "StoreKeyRequired",       "retryable": false },
    { "accountId": "2b7d…", "state": "retrying", "code": "store_migration_timeout", "retryable": true }
  ]
}
```

- 数组按 `accountId` 升序（可复现）；
- presence：**只有当数组非空且模式非 off 时**才出现；空/off/legacy 形态整键缺席；
- 语义声明：这个数组的成员是"阻碍该账号起引擎的迁移结论"，`state` 词表与 A 相同。

> 命名保留用户给定的 `migrationBlocks`，但要说清：它同时装 `retrying`，名字里的 "blocks" 是"阻碍"而不是"只能装 lock"。评审时若改名，建议 `storeMigrations`（语义更准），但字段名一旦上 wire 就不好改，**建议在动手前定名**。

### 3.2 off 零字段

同 1.4：off → 数组必空 → 整键缺席。因为 B 的键本身是"有话说才出现"，"off 时零字段"比 A 更容易被测试证明（`assert!(wire.get("migrationBlocks").is_none())`）。但要额外挡一层：`RuntimeStatusResult` 里加一个 `store_migration_enabled` 布尔（不上 wire，只决定序列化），否则"空数组"与"off"在投影层无法区分，将来有人把规则改成"总是发空数组"就会破坏约束。

### 3.3 旧端兼容

| 组合 | 行为 |
|---|---|
| 新 connector + 旧桌面 | 顶层未知键被忽略；`[D] connectorSupervisor.getStatus`（`:664-694`）根本不读它，所以旧桌面完全无感——但也**永远看不到它**，直到桌面升级 |
| 新桌面 + 旧 connector | 键缺席 → 桌面"没有可说"（不能推断健康） |
| 多 connector | ⚠️ **必须补归属**：顶层数组没有 `connectorId`，而桌面池聚合是白名单拼装（`[D] connectorPool.ts:231-249`）。要么数组条目自带 `connectorId`（那就不是"纯账号事实"），要么桌面在每 connector 的 detail 里各自保留数组、聚合时再包一层（A 天然如此） |

### 3.4 桌面能说什么话

能力上等同 A（同一套 code→文案），差别在**呈现位置**：

- 通道级：天然合适——「2 个账号的本地数据需要处理：1 个需要恢复存储密钥，1 个本地数据损坏」；
- 账号级：需要**按 `accountId` 与账号列表做一次 join**（`accounts[].id` 与槽的 `accountId` 同源：`[C] src/store.rs:3292-3296`、`[C] src/store.rs:1221-1235`），join 不上（账号已删）就丢弃；
- 不能说的话：不能把原因直接画在"引擎状态"旁边而不做 join，否则会出现"某账号停着但旁边没有原因"的空窗。

### 3.5 改动文件与测试

连接器（`[C]`）：

1. `src/pool.rs`：新增 `StoreMigrationObstruction{account_id, state, code, retryable}`；`AccountPool` 新增 `store_migration_snapshot()`（一次遍历同时返回 `Vec<StoreMigrationObstruction>`，供 B 用）。
2. `src/registry.rs:158-207`：`RuntimeStatusResult` 增 `migration_blocks: Vec<…>` 与序列化开关；`RuntimeStatusWire`（`:196`）增 `migrationBlocks: Option<&[…]>`；`status()`（`:908`）填值；`:941` 与测试字面量 `:4355/:4368/:4381` 全部要改（**B 的改动面比 A 大，就是这里**）。
3. 文档 §4.277 + 契约 1.291。

测试：

- 同 A 的六个用例，外加：
  - `an_empty_obstruction_list_omits_the_key`（健康池 → 无 key）
  - `engines_and_migration_blocks_never_disagree`（并发 start 与读状态交替，断言"数组里有该账号 ⇒ `engines` 里该账号不是 running"，或反向；用一个确定性 hook 制造撕裂窗口）
- `src/registry.rs:4354` 的 legacy 断言要扩一条"legacy 形态也不得出现 `migrationBlocks`"。

桌面（`[D]`）：

1. `shared/signalWire.ts:153`：仍建议窄投影（`storeMigrations?[]`，含 `connectorId`），渲染层不要直接吃顶层数组。
2. `connectorSupervisor.ts:1905`：从 `runtime.start` 结果读 `migrationBlocks`；`refreshRuntimeStatus()` 同上（1.5）。
3. `connectorPool.ts:205`：聚合时给每条补 `connectorId`（否则多 connector 无法归属）。
4. 文案与渲染同 A。

### 3.6 契约版本

同 A：**1.291**、`apiVersion` 1.0、engine ceiling 1.286、schema 零改动（响应开放面）。

### 3.7 失败模式

**字段撒谎**

| 风险 | 会不会发生 | 处置 |
|---|---|---|
| 数组与 `engines[]` 互相矛盾（一个说停、一个说跑，或数组列了已删账号） | **会**，如果两者分别读池（两次取快照） | 单一快照函数 + `engines_and_migration_blocks_never_disagree` 测试；实现上必须"一次遍历出两份投影" |
| 数组缺了某个被锁存账号 | 会（过滤 bug、或只装 blocked 不装 retrying） | 词表只有两个值，测试枚举两臂；生产断言"槽有记录 ⇒ 数组必含" |
| 名字撒谎（`migrationBlocks` 里出现 retrying） | 会（语义层面） | 文档写死语义"阻碍"；或改名（建议动手前定） |

**字段过期**

- 与 A 相同的三条（冷唤醒无事件、进程重启清空、桌面缓存过久）；
- **额外的过期面**：数组是"另一路投影"，一旦有人把"只在锁存时更新数组"写进代码，下一次成功启动就不会从数组里消失——必须与 retry 记录的清空规则共用同一个写入点（1.2），不能各写一份。

---

## 4. 案 C：只做错误面（不做状态，靠 start 失败文案）

C 有两个强度版本，都要评：

- **C1（字面版）**：wire 零新增。只改 `RUNTIME_START_FAILED` 的 message 文案，让运维在日志里看出"可能是本地数据迁移问题"。
- **C2（错误面最强版）**：新增错误码 `STORE_MIGRATION_BLOCKED`，`retryable:false`，`data:{blockedAccounts, code?}`，让宿主至少知道"这次启动失败是终态的、别重试"。

### 4.1 wire 形状

- C1：没有形状变化。失败响应仍是 `{code:"RUNTIME_START_FAILED", message:"…", retryable:true}`（`[C] src/host.rs:4558-4563`），只是 message 换一句。
- C2：

```json
{
  "apiVersion": "1.0",
  "requestId": "…",
  "error": {
    "code": "STORE_MIGRATION_BLOCKED",
    "message": "one or more accounts cannot start: their local store migration ended in a terminal failure",
    "retryable": false,
    "data": { "blockedAccounts": 1, "code": "StoreKeyRequired" }
  }
}
```

注意 C2 的 message 必须 ≤256（`[C] schemas/connector-api-v1.schema.json:9589-9591`），也就是**不能**直接复用 `store_migration_block_message` 的 320/365 字长句（`[C] src/pool.rs:281-336`）——现状的 `CAPABILITY_UNAVAILABLE` 已经越界，C2 会把这个漂移带进启动面。

### 4.2 off 零字段

- C1：天然满足（无线变化）。
- C2：错误码只在"确实有锁存"时出现，off 时不可能有锁存 → 满足；但**错误码词表是 wire 可见的**（schema error enum，`[C] schemas/connector-api-v1.schema.json:9473-9587` 区间，`RUNTIME_START_FAILED` 在 `:9491`），属于"vocabulary 变更"而非"字段变更"，需要单独认可。

### 4.3 旧端兼容

- C1：全兼容（旧桌面按 `runtime_start_failed` 出通用文案，`[D] src/view/signal/signalErrorCopy.ts:15`）。
- C2：旧桌面收到未知码会落到 `SIGNAL_GENERIC_ERROR_COPY_ZH` 兜底（`[D] src/view/signal/signalErrorCopy.ts:83`），不会崩。不过现有的桌面文案表只按 code 出词、不读 `retryable`，所以 `retryable:false` 对旧桌面只是数据，不会改变行为——**C2 的止血能力要等桌面升级才生效**。

### 4.4 桌面能说什么话

- C1：一句都不会变好——桌面根本不显示 connector 的 message（`[D] src/view/signal/signalErrorCopy.ts:1-9` 的纪律：技术原文只进日志）。所以 C1 的用户可见变化是**零**；除非桌面自己改文案（那就不靠 connector 了）。
- C2：启动失败时能说「Signal 通道启动失败：有账号的本地数据需要处理（不可重试）」。**说不出是哪个账号、什么问题、怎么修**。
- 账号级唯一的既有点：账号请求撞上锁存时的 `CAPABILITY_UNAVAILABLE`。但它的桌面文案现在归因为代理分组（`[D] src/view/signal/signalErrorCopy.ts:36`），C 路线下必须**同时**改这句，否则用户被告知"检查通道配置"——错的补救。

### 4.5 改动文件与测试

连接器：

- C1：`src/host.rs:4551-4564`（message 一句）；`src/service.rs:1137-1141`（引擎启动失败同族文案是否跟着改，需决策：它是"引擎起不来"，与迁移无关，**建议不动**）。零新码、零 schema。
- C2：`src/registry.rs:244-253`（`StartFailure` 增 `StoreMigrationBlocked{blocked, code}`）、`src/registry.rs:1019-1022`（在"全部没起来"分支先查 `pool.migration_block()`，有锁存就答新变体）、`src/host.rs:4551-4564`（映射新码）、`schemas/connector-api-v1.schema.json:9473-9587`（error enum 加一项）、`tests/schema_consistency.rs:212`（自动对齐，无需手改，但会要求码侧存在字面量锚点）。

测试：

- C1：改一条断言（message 含 "store" 关键字），其余不变。**注意：现状测试没有钉 start 失败 message，等于没有回归网。**
- C2：`tests/store_migrate_orchestration.rs` 加 `an_all_blocked_pool_answers_a_terminal_start_failure`（1 账号 11 锁存 → start 返回新码、retryable=false、data.blockedAccounts=1）；`tests/schema_consistency.rs` 自动跑。

桌面：

- C1：零改动（也因此零收益）。
- C2：`src/view/signal/signalErrorCopy.ts` 加 `store_migration_blocked` 一句 + 纠正 `:36` 的 `capability_unavailable` 归因；`tests/unit/` 补一条。

### 4.6 契约版本

- C1：**1.291（wire 无变更）**——但这是"文档写了一条没人能观测的行为"，价值可疑；
- C2：**1.291（wire 增错误码 + error.data）**，schema enum 变更，需要过 schema 一致性门。

### 4.7 失败模式

**字段撒谎**

| 风险 | 说明 |
|---|---|
| `RUNTIME_START_FAILED retryable:true` 对终态锁存 | **今天就在撒谎**（`[C] src/host.rs:4558-4563`）。C1 不修，只是把文案写得像有事发生；宿主行为不变 |
| 盲区：部分账号被锁存，其余正常 | `runtime.start` **成功**（`[C] src/registry.rs:1019-1023`），C 连一句话都没有。这是最常见的多账号形态，C 在这里完全失明 |
| `CAPABILITY_UNAVAILABLE` 的归因 | 桌面把它说成代理分组问题（`[D] signalErrorCopy.ts:36`），C 必须连带修，否则错误面自己在撒谎 |
| C2 的 `data.code` | 只带第一个锁存账号的 code，用户会以为"只有一个问题"；带 `blockedAccounts` 计数又不足以定位 |

**字段过期**

- 没有状态字段，所以没有"字段过期"；换来的是**错误文本过期**：桌面 `lastError` 保留到下一次成功启动（`[D] connectorSupervisor.ts:1529` 才清），期间修好了也还挂着旧话。
- 冷唤醒期的锁存：C 完全静默，直到用户点那个账号。

---

## 5. 三案对比

| 维度 | A（engines[].storeMigration） | B（顶层 migrationBlocks[]） | C（仅错误面） |
|---|---|---|---|
| 能说出"哪个账号、为什么、能不能自愈" | ✅ 三件全有 | ✅ 三件全有（需 join） | ❌ 至多"有账号出问题，别重试"（C2） |
| 原子性（同一答案内自洽） | ✅ 一个结构体，一次遍历 | ⚠️ 两路投影，必须共用一次快照 | —（无状态） |
| 多 connector 归属 | ✅ 由 `connectors[]` 外层给出 | ⚠️ 顶层数组无归属，桌面聚合层必须补 `connectorId` | — |
| off 零字段可证明性 | ✅ 双重（结构 + 投影）+ 测试 | ✅ 更直观（空则不出现），但需挡"总是发空数组" | ✅ 天然 |
| 旧桌面无感 | ✅（engines 本就不读） | ✅（未知键忽略，但也永远读不到） | ✅ |
| 新桌面 + 旧 connector | ✅ 缺席即不说 | ✅ 同 | ✅ |
| 连接器改动面 | 小：1 个结构体 + 1 个字段 + 1 个投影函数 + 闸内 2 处写/清 | 中：`RuntimeStatusResult`/`RuntimeStatusWire`/`status()`/3 处测试字面量 + 新快照函数 | C1 极小 / C2 中（`StartFailure` 变体 + 错误码 + schema） |
| 桌面改动面 | 中：窄投影 + 一次 `runtime.status` 刷新 + 文案 | 中：同上（且必须处理归属） | C1 零（零收益）/ C2 小 |
| 契约成本 | 1.291，schema 零改动 | 1.291，schema 零改动 | C1 1.291 无 wire；C2 1.291 + 错误码枚举 |
| 撒谎风险 | 低（冗余的 `retryable` 是唯一自伤点） | 中（撕裂 / 漏项 / 名字不达意） | **高**（今天就在撒谎：retryable=true、归因错误） |
| 过期风险 | 中（冷唤醒无事件；进程重启清空） | 中 + 多一路投影 | 无字段过期，但错误文本过期 + 常见形态失明 |
| 用户可见收益 | 账号级原因 + 可操作补救 | 同上，呈现偏通道级 | C1 零；C2 仅"别重试" |
| 测试成本 | 低（现有 fake engine 装置够用） | 中（多一条撕裂测试 + 改 3 处字面量） | C1 极低 / C2 中 |

一句话概括差异：

- **A 是"把原因贴在它解释的那个状态旁边"**；
- **B 是"另开一张表，桌面自己 join"**；
- **C 是"什么都不记，等失败那一秒喊一嗓子"**——而最常见的那种失败（部分账号坏、通道照常起）它连喊的机会都没有。

---

## 6. 推荐：案 A

### 6.1 理由

1. **原子性最好**：A 把"停着"和"为什么停"放进同一个结构体（`[C] src/pool.rs:599`），一次遍历出一个答案；B 天然是两路投影，必须靠纪律（共用快照）才能不撕裂，而纪律会被人改坏。
2. **归属免费**：池化下 `engines[]` 已经挂在各自 connector 的 `connectors[]` 里（`[D] connectorPool.ts:231-249`），A 不需要在多 connector 聚合层再造一个 `connectorId`；B 需要，而且桌面聚合层是**白名单拼装**，不加就静默丢字段。
3. **改动面最小**：A 的 connector 侧只碰 `pool.rs`（结构体 + 字段 + 闸内两处 + `statuses()`）；B 要改 `RuntimeStatusResult`、wire 结构、`status()` 和 3 处测试字面量（`[C] src/registry.rs:158/196/908/941/4355/4368/4381`），改动面越大，越容易在"off 零字段"上出事故。
4. **和既有设计一致**：仓库已经把 `engines[]` 定为"逐账号详情的唯一状态面"（`[C] src/registry.rs:628-635`、`:745-755` 的原话），A 是往既定面里加成员；B 是**新开一个面**，与既有纪律并行，长期要维护两套投影。
5. **off 零字段可证明**：A 有两道保险（闸在 off 时不写记录 + 投影时再看开关），测试可以断言"整帧不含 `storeMigration`"；B 的"空数组"与"off"在投影层不可区分，需要额外一个内部布尔才能证明，且将来容易被改成"总是发空数组"。
6. **A 的唯一自伤点可控**：`retryable` 与 `state` 语义重叠（见 2.7），是"第二个会撒谎的地方"。既然字段形状已按用户给定保留它，就用"派生常量 + 映射断言"把它钉死；若评审允许，**更干净的做法是去掉 `retryable`**，让 `state` 唯一承载二值语义（这一点建议在动手前拍板，wire 一旦发出去就难收回）。

### 6.2 为什么不选 B / C

- **B**：能力等价但成本更高（两路投影 + 归属 + 3 处字面量），且它的两个真实优势都不成立：
  - "桌面不用读 `engines[]` 也能用" —— 桌面今天两个都不读（`[D] connectorSupervisor.ts:1905-1917`），无论 A/B 都要新增投影；
  - "数组更省 wire" —— 状态面本来就是按"有话说才出现"设计的，A 的空缺同样零成本。
- **C**：C1 的用户可见变化是零（桌面不显示 message），C2 只能回答"别重试"，答不出"哪个账号/怎么修"；而且它最需要的场景（部分账号坏、通道照常起）它完全失明（`[C] src/registry.rs:1019-1023`）。C 还有一个必须顺手修的账：`RUNTIME_START_FAILED retryable:true` 对锁存是假话（`[C] src/host.rs:4558-4563`）——**不管选哪个案，这条都该修**。

### 6.3 落地顺序（若批准）

1. **connector A 案**（1.291）：字段 + 闸内写/清 + 投影 + 六个测试；off 帧字节断言先落地。
2. **桌面窄投影 + 文案**：`shared/signalWire.ts` 只加窄类型；`connectorSupervisor` 读 start 结果；账号页渲染。
3. **取数缺口**（1.5）：`refreshRuntimeStatus()` 挂在 `getRuntimeStatus` IPC 与 `CAPABILITY_UNAVAILABLE` 分支；`RUNTIME_START_FAILED` 后补读一次。
4. **顺带修错误面**：`retryable` 对锁存的假话 + `capability_unavailable` 的错误归因（两项独立于 A，可并行）。
5. 暂不做：新事件（`storeMigration.changed`）—— 它会引入事件词表与新订阅面，等 A 的字段被真实消费、确认"冷唤醒延迟"在产品上不可接受再评估。

### 6.4 验收清单（可逐条跑）

- [ ] off（未设 / `off` / 乱写一个值）：`runtime.status` 与 `runtime.start` 的整帧里不含 `storeMigration`（字节级断言）。
- [ ] apply + exit 11：该账号条目带 `{state:"blocked", code, retryable:false}`，且同一快照 `engines[].state != "running"`。
- [ ] apply + exit 10 耗尽：条目带 `{state:"retrying", …, retryable:true}`，下一次 start **仍然会再跑迁移器**（不是锁存）。
- [ ] 重试成功后 `retrying` 立刻消失（同进程内）。
- [ ] 无 data dir / 无派生 key / exit 0：不出现任何 face。
- [ ] 未知 code：wire 原样透传（clamp 后），桌面走兜底文案。
- [ ] 整帧无 key、无号码、无路径、无 ≥64 位 hex。
- [ ] 全槽锁死：`runtime.start` 仍可答 `RUNTIME_START_FAILED`（或后续改码），但桌面补读 `runtime.status` 后能列出每个账号的原因。
- [ ] 多 connector：每条原因归属到正确的 `connectorId`。
- [ ] 旧桌面 + 新 connector：无异常、无字段误读（`engines[]` 不被读）。

---

## 7. 本方案不做，以及顺带发现

**不做**

- 不加新事件（`runtime.stateChanged` 保持聚合形状，`[C] src/registry.rs:745-755`）；
- 不改 `runtime.doctor`（池化下它本来就看不到槽，`[C] src/doctor.rs:397-417`；要补也是另一件事）；
- 不动 engine 侧协议（`ENGINE_CONTRACT_MAX_REVISION` 保持 1.286，`[C] src/engine_contract.rs:68`）；
- 不改 `degraded` 语义（全槽锁死仍是 `stopped + degraded:false`，`[C] src/registry.rs:858-860`）——通道级徽标仍然说不出"被锁存"，这个缺口由桌面从 face 自行派生，不新造聚合位。

**顺带发现（都是现状，不是本案引入）**

1. **`error.message` 越界**：schema 上界 256（`[C] schemas/connector-api-v1.schema.json:9589-9591`），而迁移相关句子是 320/365 字符（`[C] src/pool.rs:281-336`）。现状的 `CAPABILITY_UNAVAILABLE` 已经越界，C2 会把它带进启动面。建议单开一条：要么抬上界并写清理由，要么把这族文案压到 256。
2. **`code` 无长度上界**：引擎可以给任意长字符串（`[C] src/engine.rs:462-476`），今天只进日志，一旦上状态面就会被反复渲染。A/B 都应在写入处 clamp。
3. **doctor 的 `lastMigrationFailure` 名字撞车**：它讲的是 SQLite schema 迁移（`[C] src/store.rs:1015-1025`），与 engine store 格式迁移是两件事。桌面文案里必须区分，别把两者混成一句话。
