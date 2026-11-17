# store 迁移前置判定（preflight）：A / B / C 三案对比与推荐

**状态**：方案，只读评估，未改一行码。本文只回答"该怎么做"，不承诺已实现。
**范围**：`kt-signal-connector` 本仓。engine 与桌面只作为契约对端出现；本仓看不见的引擎行为统一列进 §7。
**上游**：`docs/implementation-plan.md` §4.275（M6 C：按账号注入 engine store key）、§4.276（M6 D：迁移编排 off / dry-run / apply）。
**一句话**：`REQUIRE_ENCRYPTED=on` + `KT_ENGINE_STORE_MIGRATE=off` + 盘上仍有明文 engine store 时，要让它"起不来并说人话"，而不是"起来了然后把这个账号锁成终态"。

---

## 1. 问题

### 1.1 终态只有两条来路

1. **闸锁存**：`pool::gate_slot_start`（`src/pool.rs:1264`）把迁移器 exit 11 翻成 `StoreMigrationBlock`，锁在槽位上（`src/pool.rs:719`）。此后本进程内任何 start / 唤醒 / watchdog 只读锁存，既不 spawn 迁移器也不 spawn 引擎；对外是不可重试的 `CAPABILITY_UNAVAILABLE`。
2. **engine 侧拒绝明文库**（engine 仓，本仓不可见）。

两条的共同点：**恢复动作是"删本地数据再重新 link"**，代价是该账号全部本地历史与已下载媒体（§4.275 回滚三条事实）。"打成终态"的实质不是"这次没起来"，而是**要拿数据换**。

### 1.2 为什么最坏组合偏偏是 REQUIRE_ENCRYPTED=on + MIGRATE=off

- `REQUIRE_ENCRYPTED=on` 是一句**承诺**：这个客户端不许出现可读的明文库。
- `KT_ENGINE_STORE_MIGRATE=off` 是**唯一能把明文变成加密的动作**（§4.276：off = 不派生、不 spawn、不读盘）。
- 两个键各自都"对"，合起来是"承诺在、动作没有"。盘上的明文不会自己变；等某个账号被引擎拒绝时，用户看到的是"这个号坏了"。

所以这不是迁移失败问题，是**配置组合把可恢复状态翻译成不可恢复状态**的问题。

### 1.3 本仓现状（证据）

- `REQUIRE_ENCRYPTED` 在本仓**零命中**（`grep -rn REQUIRE_ENCRYPTED` 无结果）。它今天是桌面的承诺，connector 侧没有任何代码读它；三案都要求先把它变成 connector 能读的输入（下文记作 `KT_ENGINE_STORE_REQUIRE_ENCRYPTED`，命名归属见 §7）。
- 迁移开关只有三档、默认 off（`src/pool.rs:117`），在运行时装配时读一次（`src/registry.rs:3625`）。
- 迁移闸只挂在池化的两个启动入口（常驻窗口 `start_resident`、冷启动唤醒 `ensure_resident`→`gate_slot_start`）；**supervisor 自己的崩溃重启不过这道闸**（§4.276 边界已记）。

---

## 2. 判定能依赖什么、不能依赖什么

### 2.1 header-only 是唯一可用的判定

`db_file_state`（`src/store.rs:15173`）只做三件事：`metadata` → 零长度判 `Absent` → 读前 16 字节，等于 `SQLITE_PLAINTEXT_HEADER`（`src/store.rs:173`）判 `Plaintext`，否则判 `Encrypted`。

- 成本：**1 次 stat + 1 次 16 字节 read**。不 open 库、不要 key、不拿 SQLite 连接、不拿 flock、不碰 `-wal`/`-shm`。
- 语义：加密库与随机字节不可分。`Encrypted` 只意味"不是明文"，**不是"能打开"**。这条要写死，免得有人把 preflight 当库可用性检查。
- 扫描**不得 open 任何库**——包括 connector 自己的 `connector.sqlite3`。16 字节就是全部信息量。
- 三案都必须复用这同一份 16 字节判定，不许在别处再写一份（现在 `db_file_state` 是私有函数，需要提到 `pub(crate)`）。

### 2.2 判定对象只有 engine store，不是 connector 自己的库

connector 自己的 `connector.sqlite3` 不需要这份判定：`Store::open`（`src/store.rs:3482`）已经分流完了——有 key + 明文 → 当场迁移；无 key + 明文 → `PlaintextStoreRequiresKey`；无 key → `StoreKeyRequired`；加密库换 key → `StoreKeyRejected`。这些全是**进程级 fail-closed**（已经是"起不来并说人话"），不是账号终态。

preflight 唯一要看的是**每个账号的 engine store**：

```text
<signal-data>/engines/<accountId>/accounts/lk-*/store.db        # 池化，src/migrate.rs:1-30
<signal-data>/accounts/lk-*/store.db                            # legacy 默认组
<signal-data>/proxy-groups/<group>/accounts/lk-*/store.db       # legacy 分组
```

### 2.3 扇出的目录上限是算得出来的

| 拓扑 | 走几个目录 | 读几个文件头 |
|---|---|---|
| 池化（本次上限场景） | 1（`engines/`）+ 8 账号 × 2（槽目录 + `accounts/`）= **≤17 次 read_dir** | **≤8 次** 16 字节 read |
| legacy | 1（`accounts/`）+ 1（`proxy-groups/`）+ ≤8 组 × 2 = **≤19 次 read_dir** | 组内账号数不定，靠 `MAX_SCAN_ENTRIES=64` 条目上限封住（与 `MAX_SNAPSHOT_SCAN` 同形） |
| connector 自己的库 | 0 | 1（只报数，不作判据） |

硬上限来自 `MAX_PER_ACCOUNT_ENGINES = 8`（`src/pool.rs:68`）与 `MAX_PROXY_GROUPS = 8`（`src/groups.rs:22`）。这是"一次启动、几毫秒、纯只读"的量级；慢盘/漫游目录的风险用条目上限封住，不靠"应该很快"。

### 2.4 只读纪律：不能直接复用 `AccountPool::discover`

`discover`（`src/pool.rs:829`）会 `ensure_private_dir(engines_root)`（**建目录**）并给每个槽 `DataDirLock::acquire`（**建锁文件**）。preflight 要在任何写之前跑，只能自己走一遍 `read_dir`，并且：

- 不建目录：`engines/` 不存在 = 空集，不是错误；
- 不跟随符号链接（`symlink_metadata`，与 `remove_slot_directory`、`migrate.rs` 同纪律），命中记 `Unverifiable`；
- 单文件只读 16 字节，不读 `engine-state.json`、不进 `migration-snapshots/`；
- 不写 marker（warn 档留痕就写日志，不落文件）。

### 2.5 "仍有明文库"必须先分流，否则稳态必被误拒

盘上有五类以 `SQLite format 3\0` 开头的文件，但只有第一类算"仍有明文库"：

| 类别 | 是否判据 | 依据 |
|---|---|---|
| 某账号的 **serving** `store.db` | **算** | 它就是这个账号将被引擎打开的库 |
| connector 自己的 `connector.sqlite3.plaintext-backup` | 不算（债务，只 warn） | Phase 3 回滚副本，保留 7 天（`PLAINTEXT_BACKUP_RETENTION_MS`，`src/store.rs:65-70`），由启动后的保留 pass 剪掉（`src/store.rs:3731` ← `src/supervisor.rs:1104`）。**一次成功迁移之后它必然存在**：算进判据 = 每台机器迁完必被拒 7 天 |
| `.encrypting` 暂存（迁移中途崩） | 不算 | 目标是 SQLCipher 库，半成品头是随机字节，通常本就判 `Encrypted` |
| `migration-snapshots/pre-migration-*.sqlite3` | 不算 | 快照用 `VACUUM INTO` 在 keyed 连接上拍，SQLCipher 用同一把 key 重新加密目标文件——"the snapshot is never a plaintext copy"（`src/store.rs:15568-15600`） |
| 池化拓扑下 legacy 目录里的明文 `store.db` | 不算（债务，只 warn） | 池化下 legacy 目录不参与服务（`migrate.rs` 用 rename 搬走，源目录只留 registry） |

一句话：**判据只认"当前拓扑下会被服务的那个文件名"**，其余全部进"债务/残渣"清单——进日志、进 doctor，绝不进拒绝条件。这是 A 能不能用的分水岭。

### 2.6 两个现有承诺会被打破，必须写进契约

1. **off = 不读盘**（§4.276 开关表第一行）。A 与 B 都要在 off 档读 16 字节：契约文字必须改成"off 仍不派生、不 spawn、不写盘；`REQUIRE_ENCRYPTED` 打开时，进程启动做一次只读文件头扫描"（A）或"每次启动该账号时读一次"（B）。不改文字就改行为，等于文档撒谎。
2. **supervisor 的重启面不过闸**。A 不需要动它（拒绝发生在任何引擎存在之前）；**B 必须动它**，否则"首次访问才拒绝"是句空话——watchdog 可以把一个明文槽直接拉起来。

---

## 3. 三案

### 3.1 A：启动时扫描明文库，三条件同时成立才拒绝启动

**判据**

```text
refuse  ⟺  ① KT_ENGINE_STORE_REQUIRE_ENCRYPTED = on
         ∧  ② StoreMigrationOptions.mode = Off            （dry-run / apply 一律不拒）
         ∧  ③ 池化拓扑（--per-account-engines）
         ∧  ④ 当前拓扑的 serving 位仍有 ≥1 个明文 store
```

①②④ 是题目说的三条件；③ 是我加的第 0 条前置：**legacy 组引擎拿不到账号级 key，结构上就迁不了**（`src/registry.rs:3679-3690`，§4.276 边界）。少了 ③，A 会把所有 legacy 客户端打成永久起不来——那是 A 唯一的"自杀式"误拒，必须先堵。

**判定成本**

- 扇出：见 §2.3，池化 ≤17 次 `read_dir` + ≤8 次 16 字节 read；不 open 库、不拿锁、不建目录。
- 是否只读：**是**；且拒绝时零写入（preflight 放在 `lock_plan_data_dirs`（`src/main.rs:460`）**之前**，连 `.kt-signal-connector.lock` 都不建）。
- 频次：每进程一次。诊断优先级上有一个已知取舍：preflight 排在 store key 解析之前，所以"key 缺失 + 有明文库"会先报 preflight，修完 `MIGRATE` 再报 `STORE_KEY_REQUIRED`——多一次重启，换"拒绝零写入"。

**误拒风险（迁移完成后的稳态）**

| 稳态场景 | 结果 | 说明 |
|---|---|---|
| 全部已加密、无残渣 | 放行 | ④ 不成立 |
| 已加密 + `connector.sqlite3.plaintext-backup` 在 7 天窗口内 | 放行（warn 债务） | 依赖 §2.5 分流；不分流就是**每次迁移后必然误拒 7 天** |
| 已加密 + 快照目录留着 3 个旧快照 | 放行 | 快照本身是加密库 |
| 迁移中途崩，留 `.encrypting` | 放行 | 判 `Encrypted`/残渣 |
| legacy 客户端（`REQUIRE_ENCRYPTED=on` 也满足不了） | 放行（warn） | 靠前置 ③ |
| 一个账号从旧备份还原成明文、其余已加密 | **拒绝** | 正确拒绝：改 `MIGRATE=apply` 重启即迁完 |
| 新 link 的账号还没建库 | 放行 | 缺文件/零长度 = `Absent` |
| store 不可读（权限/EIO） | 放行 + `Unverifiable` | 见下 |

"不可读"要写死为**不拒绝、只记 `Unverifiable`**：它是新的失败面（网络盘、EIO），而不可读的库引擎自己也打不开——preflight 不该比引擎更早把客户端判死。

结论：稳态误拒 **0**；唯一拒绝的场景是"确实还有账号在用明文库"，而它恰好是应该拒的那一个，补救是**改一个键 + 重启，不重新 link，不丢数据**。

**fail-closed 语义**

进程级、启动期、不可重试、零副作用：

- 位置：`serve_command`（`src/main.rs:396`）里，`build_group_plan` 之后、`lock_plan_data_dirs` 与 `LocalListener::bind` / `write_listen_announce` **之前**——拒绝时一个字节的 endpoint 都不许 announce（与 §4.274 单账号护栏同形，`src/main.rs:427`）。
- 出口：新增 `StoreError::PlaintextStoreRequiresMigration { accounts }`，并在 `fatal_line_for`（`src/store.rs:879`）加一行
  `KT_FATAL code=STORE_PLAINTEXT_REQUIRES_MIGRATION retryable=false accounts=N`；桌面按既有 `STORE_KEY_*` 套路渲染"去修配置"面板，而不是重试 5 次。
- 不碰账号：不锁存、不写 `StoreMigrationBlock`、不动槽位；进程退出即恢复原状。

**改动文件与测试**

| 文件 | 改动 |
|---|---|
| `src/store.rs` | `DbFileState` / `db_file_state` 提到 `pub(crate)`；新增 `StoreError::PlaintextStoreRequiresMigration` + `class()` + `fatal_line_for` 一支 |
| `src/pool.rs` | 新增 `StoreEncryptionRequirement` 三态解析（on / off / unset；非法值 off + warn 一次，与 mode 同向）；`StoreMigrationOptions::from_env` 保持不动 |
| 新 `src/store_preflight.rs` | `scan(signal_data_dir, state_dir, topology) -> PreflightReport`（`plaintext_serving` 账号指纹集、`debris` 计数、`unverifiable` 计数、`scanned_dirs/files`）+ `decide(requirement, mode, topology, &report) -> Verdict`；纯函数、root 可注入，便于造盘面 |
| `src/main.rs` | `serve_command` 顶层读一次两个键 → 预检 → 拒绝即 `Err`；把同一个 `StoreMigrationOptions` 注入 `RuntimeOptions` 传下去（顺手消掉 registry 里两处独立 `from_env`：`src/registry.rs:3625` 与 `3679`） |
| `src/registry.rs` | 接收注入的 options，不再自己 `from_env` |
| `src/lib.rs` | 挂模块 |
| `docs/implementation-plan.md` | 新增 §4.277（契约 1.291）：三条件、债务分流、新 `KT_FATAL` 码、off 语义微调 |
| `docs/doctor-contract.md` | 不改（A 不需要新 face；进程已死，doctor 跑不起来） |

测试（新 `tests/store_preflight.rs`，env 是进程全局，整段持锁，照 `store_migrate_orchestration.rs` 范式）：

- 矩阵：`require × mode(off/dry-run/apply) × topology(pooled/legacy) × 盘面(明文/加密/空/备份)` 全组合；
- `a_plaintext_account_store_with_require_on_and_migrate_off_refuses_the_launch`：退出码 1、`KT_FATAL` 一行、**无 socket、无 announce、无 lock 文件**；
- `the_connector_plaintext_backup_is_never_a_refusal`（7 天窗口内）；
- `migration_snapshots_and_staging_files_are_never_a_refusal`；
- `a_zero_length_store_is_absent_not_plaintext`；
- `an_unreadable_store_is_unverifiable_and_never_refuses`；
- `a_symlinked_slot_is_not_followed`；
- `require_on_with_migrate_apply_never_refuses`；
- `require_on_in_the_legacy_topology_warns_and_starts`；
- `require_off_reads_no_header_at_all`（扫 0 次：用不可读目录或注入 reader 反证）；
- 日志断言：无路径、无 key、无账号全 id、无 ≥64 位 hex（照 §4.276 既有用例）。

单测：解析矩阵、`decide` 矩阵、`fatal_line_for` 新码、`class()` 新值。

**运维可见性**

- 拒绝：`KT_FATAL code=STORE_PLAINTEXT_REQUIRES_MIGRATION retryable=false accounts=N`（进程没起来时这是唯一的机器可读通道）+ 一行
  `store_preflight outcome=refused require_encrypted=on store_migration=off topology=pooled plaintext_accounts=N`。
- 放行：一行 `store_preflight outcome=pass plaintext_accounts=0 debris=K unverifiable=J`，warn 档才能在现网数点。
- 桌面：新码映射到"迁移未开"的修复面板（与 `STORE_KEY_REQUIRED` 同一套），文案只说"改 `KT_ENGINE_STORE_MIGRATE=apply` 后重启，账号数据未被改动"。

### 3.2 B：启动只 warn，首次访问该账号时拒绝

**判据**：`require=on ∧ 池化 ∧ 该槽 serving store 是明文` → 该账号的任何 start / 唤醒被拒。`MIGRATE` 不再是条件（off 也拒）。

**判定成本**

- 扇出：每账号 1 次（槽目录 + `accounts/` + 16 字节），挂在 `gate_slot_start` 与 `ensure_resident` 两个入口；一次会话累计与 A 同量级，但**摊在请求路径上**（冷启动唤醒本就在亚秒级，多 3 个 syscall 不是问题）。
- 是否只读：是。
- 额外：必须在 off 档就读盘（打破 §2.6-1），且要新增"每次唤醒都读"的频次语义（加缓存又会引入"库被换回明文后不重判"的洞）。

**误拒风险**

- 稳态（已加密）不拒；但若把 `.plaintext-backup` 算进判据，就变成"每个账号迁移后 7 天内不可用"——比 A 更糟（A 是整机拒，B 是逐账号拒，用户观感是"这些号都坏了"）。
- 真正的洞在别处：**supervisor 的崩溃重启不过这道闸**（§4.276 边界）。B 拒的是"连接器发起的启动"，watchdog 仍可能把明文槽拉起来——B 的 fail-closed 是**局部的**，恰好漏在"引擎反复崩"这种最需要它的场景。

**fail-closed 语义**

账号级、可重算（不锁存）、必须与 M2 的删除出口对齐：

- `SlotWakeRefusal` 增加一支 `StorePreflight`；`ensure_resident` 映射成不可重试的 `CAPABILITY_UNAVAILABLE`，但**不写 `StoreMigrationBlock`**，下次 start 重判（改 env + 重启即恢复）。
- `account.delete` 必须照 M2 走纯 store 路径，否则"被拒的账号删不掉"——又造一个终态。

**改动文件与测试**

`src/store.rs`（同 A 的 `pub(crate)`）、`src/pool.rs`（`EnginePoolConfig` 加 `require_encrypted`；`gate_slot_start` 前置判定；`SlotWakeRefusal` 新支；`start_resident` 跳过该槽；删除出口对齐）、`src/registry.rs`、`src/main.rs`、`src/service.rs`/`src/host.rs`（错误面文案）、`docs/implementation-plan.md`（§4.277 + **改 §4.276 的 off 行**）。

测试（`tests/store_migrate_orchestration.rs` 增）：

- `a_plaintext_slot_is_refused_on_first_access_and_other_accounts_start`；
- `the_refusal_is_not_latched_and_heals_after_a_restart_with_migrate_apply`；
- `a_refused_slot_can_still_be_deleted`（M2 同形）；
- `the_resident_window_skips_only_the_plaintext_slot`；
- `a_watchdog_restart_of_a_plaintext_slot_still_starts_it`（**把 B 的洞钉进测试**，而不是只写进文档）。

**运维可见性**

启动一行 warn（每账号指纹）；访问拒绝一行 error + 文案（含"改 migrate=apply 或关 require"）。没有 `KT_FATAL`（进程起来了、有 socket、doctor 能跑），但 doctor **今天没有 store face**，要看"哪几个账号是明文"仍得翻日志或加 face（= 契约变更）。

### 3.3 C：不改 connector，靠 dashboard / doctor 提示

**判据**：无。connector 不做任何判定。

**判定成本**

- connector 侧 **0**。
- 桌面侧要自己走同一组目录、读同一 16 字节——**同一判定出现两份实现**（本仓 `SQLITE_PLAINTEXT_HEADER` 一份、桌面一份），这正是仓库一直在防的"plan 与 runtime 漂移"。

**误拒风险**：0（没有拒绝路径）。代价是"误报也没人兜"：dashboard 说"3 个号明文"，实际可能是备份残渣——桌面拿不到 §2.5 那套分流规则，只能再实现一遍。

**fail-closed 语义**：无。明文库照样被引擎打开或拒绝，账号照样可能被打成终态。C 缩短的是"发现时间"，不是"终态"。

**改动文件与测试**

- connector：无（`docs/doctor-contract.md` 也不动）。
- 若坚持让 doctor 回答"盘上有几个明文库"，那就是**加 store face + 契约升版 + 桌面渲染**——已经不是 C，而是"A 的观察档放进 doctor"。
- 测试：桌面侧为主，本仓无新增。

**运维可见性**：取决于桌面做到什么程度。最弱一档是"用户报障 → 运维翻 `store_migration_outcome=disabled` 日志"，而这条日志今天只说明"开关是关的"，不说明"盘上还有明文"。

---

## 4. 横向对比

| 维度 | A（启动判 + 拒启） | B（warn + 访问拒） | C（不改 connector） |
|---|---|---|---|
| REQUIRE_ENCRYPTED 成为真不变量 | **是**（进程根本不带明文起来） | 局部（supervisor 面漏） | 否 |
| 判定成本 | 每进程 1 次，≤17 dir / ≤8 read | 每唤醒 1 次，摊在请求路径 | connector 0；桌面重复实现 |
| 只读 | 是，且拒绝零写入 | 是 | 是 |
| 稳态误拒 | 0（前提：§2.5 分流 + 前置 ③） | 0（同前提），但逐账号放大观感 | 0 |
| 失败时爆炸半径 | 进程（全客户端暂时不可用） | 单账号（看起来像"这个号坏了"） | 无（终态照旧） |
| 恢复代价 | 改一个 env + 重启，**不丢数据** | 改 env + 重启；被拒账号期间不可用 | 重新 link（丢历史/媒体） |
| 是否动 off 契约 | 要（一句） | 要（每唤醒读盘） | 不要 |
| 是否动 supervisor 启动面 | **不要** | 要（否则不成立） | 不要 |
| 代码面 | 新模块 + 1 个错误类 + 1 行 fatal | 新模块 + 唤醒枚举 + 删除出口 + supervisor | 0（本仓） |
| 可测性 | 最高（启动即判，不 spawn 引擎） | 中（要造多槽与重启时序） | 低（测不到） |

---

## 5. 推荐：A，按"两段 + 两条前置"落地

**推荐 A。** 三条理由，按重要性排：

1. **只有 A 把承诺变成不变量。** `REQUIRE_ENCRYPTED` 的意思是"这个客户端不许有可读明文库"。B 只保证"连接器自己不去开它"——watchdog 那条路照样能把明文槽拉起来（§4.276 边界）；C 什么都不保证。要么把承诺从桌面文案里撤回，要么就得在**任何引擎存在之前**判一次——那是 A 的位置。
2. **A 把"数据换可用性"换成了"可用性换可用性"。** 现状的失败是持久 damage（重 link = 历史 + 媒体全丢）；A 的失败是暂时的：改 `KT_ENGINE_STORE_MIGRATE=apply`（或关掉 require）重启，明文库原样迁过去，一个字节不丢。同一个配置错误，A 的代价是"这次没起来"，B 是"这个号看起来坏了、用户去点删除"，C 是"真的坏了"。
3. **A 的改动面最小且最可测。** 不碰唤醒枚举、不碰删除出口、不碰 supervisor 启动面、不需要"每唤醒读盘"的频次语义；启动即判、拒绝零写入，CI 里不造多槽时序就能把矩阵钉死。

**两条前置（不满足就别上 A）**

1. **桌面侧把两个键绑起来：`REQUIRE_ENCRYPTED=on ⇒ MIGRATE=apply`。** 这是根因修复，preflight 只是安全网。两个键互相独立本身就是 bug——A 只是让这个 bug 表现为"起不来"，而不是"账号坏了"。
2. **判据必须带前置 ③（池化）与 §2.5 的债务分流。** 少任何一个，A 就变成新的终态制造机：legacy 用户永久起不来；迁移成功的机器在 7 天备份窗口内起不来。

**两段上线**

- **R1（warn 档）**：照 A 全量实现，只把 `refused` 换成 `would_refuse` + 一行 warn。这一步拿到的正是 C 想要的可见性，但放在**拥有真相的进程里**，不是复制到 dashboard。同时把 `outcome=pass` 也打出来，好算分母。
- **R2（拒启档）**：现网 `would_refuse` 连续一个发布周期为 0（或每次命中都能解释成真明文）后再打开。开关做成发布档，不新增第四个 env——能少一个键就少一个。

**为什么不选 B**：它把"配置错"降级成"某个账号坏了"，正是题目要避免的终态观感；而且它要成立必须动 supervisor 启动面（§4.276 明确推迟的那块），改动面反而更大，最后还漏一条路。
**为什么不选 C**：不改 connector 就没有任何强制点；"让 doctor 回答"本身就等于改 connector + 升契约。C 唯一的价值是可见性——那已经包含在 A 的 R1 里。

---

## 6. 验收清单（A）

- [ ] `require=on + mode=off + 池化 + 1 个明文 store` → 退出码 1、`KT_FATAL code=STORE_PLAINTEXT_REQUIRES_MIGRATION retryable=false accounts=1`、无 socket、无 announce、无 lock 文件、state dir 字节不变；
- [ ] 同盘面把 `mode` 改成 `apply` → 不拒绝，迁移照 §4.276 跑，迁完后**下一次启动不再拒绝**；
- [ ] 迁移完成后的 7 天窗口内（`connector.sqlite3.plaintext-backup` 还在）→ 不拒绝，只 warn 债务；
- [ ] legacy 拓扑 + `require=on` → 不拒绝，warn 一次"legacy 无账号级 key，加密要求无法满足"；
- [ ] 零长度 / 缺文件 / 不可读 / 符号链接 → `Absent` / `Absent` / `Unverifiable` / `Unverifiable`，均不拒绝；
- [ ] 关掉 `require` → 启动路径**零 header 读**（用不可读目录反证）；
- [ ] 日志里没有路径、key、账号全 id、≥64 位 hex；
- [ ] `KT_FATAL` 行能被桌面解析并映射到"迁移未开"修复面板（跨仓联调用例）。

---

## 7. 未决证据 / 归属

1. **engine 拿到 key 却面对明文 store 的行为**（自动迁 / 拒绝 / 照常打开）：本仓不可见，engine 侧另报。**在它清楚之前，不能把"引擎会兜住"当前提**——这也是 A 的理由之一：本仓唯一能控的强制点只有自己的启动闸。
2. **`REQUIRE_ENCRYPTED` 的键名与归属**：本仓零命中。若桌面已有同名键，connector 照抄名字（AGENTS：legacy 名字不许被"修"）；否则用 `KT_ENGINE_STORE_REQUIRE_ENCRYPTED`，并在 §4.277 记档。
3. **engine 的 storeMigrate 成功路径是否留明文副本**：决定 §2.5 债务清单是否完整。已知 connector 自己会留 `.plaintext-backup` 七天；engine 侧待确认。
4. **`MIGRATE=dry-run` 的定位**：本方案里 dry-run 不触发拒绝（它是观察档，拒了就没法观察）。若产品要求"dry-run 下也不许服务明文"，那是另一条需求，别混进 A。
