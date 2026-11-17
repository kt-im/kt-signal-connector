# 反方评审：M6 C（按账号注入 engine store key）与 M6 D（store 迁移编排）现在两个都不该做

- 评审对象：`963cee6`（D，store 迁移编排 + 锁存槽删除出口）、`d87ff46`（C，按账号注入 store key）
- 基线：本 worktree HEAD = `963cee6`，工作区干净
- 我的立场：**两个都不做**。若被迫二选一，也只能选 D，而 D 单独做会把库迁成引擎打不开的形态（见 §2.1），所以「二选一」实际上也不成立。
- 先说清楚：这两个提交的**工程质量明显高于本仓平均线**——失败分档（exit 0/2/10/11）、日志只带指纹不带材料、`kill_on_drop`、节流、上千行端到端用例，都是好事。我反对的不是写得糙，而是**它们组合后的默认配置是三种组合里最差的那一种**，而「不做」的代价被高估了。

一句话结论：C 是单向门且没有开关，D 有开关但默认关闭所以今天不产生收益；C 默认开 + D 默认关恰好制造出「引擎拿着 key、库还是明文」这个**引擎侧未定义**的状态，而引擎侧的语义不在本仓、本仓的测试也测不到它（`tests/store_migrate_orchestration.rs` 用 python stub 假扮迁移器）。

---

## 0. 事实基线（先钉住「改了什么」，否则讨论会跑偏）

| 维度 | C（`d87ff46`） | D（`963cee6`） |
|---|---|---|
| 行为面 | 每个池化槽位把 `HKDF(root, accountId)` 写进子进程 `KT_SIGNAL_STORE_KEY`（`src/pool.rs:1612-1613` → `src/engine.rs:3129-3152`） | 槽位启动前跑一次 `storeMigrate` 子进程，按退出码决定起不起引擎（`src/pool.rs:1264-1447`） |
| 开关 | **没有**。root key 存在就派发（`src/pool.rs:1612` 无条件调用） | 有，`KT_ENGINE_STORE_MIGRATE`，默认 off（`src/pool.rs:117,191,1266-1270`） |
| 可逆性 | 计划自己写：**单向门**（`docs/implementation-plan.md:21226-21257`） | 关开关重启即回到明文库路径（`docs/implementation-plan.md:21361-21365`） |
| 新增可观测面 | 一行 info，三值枚举（`src/store.rs:1182-1188`） | 只在日志；`runtime.status` 无字段（计划自认：`docs/implementation-plan.md:21443-21445`） |
| 新增代码量 | +1119 行（其中 721 行测试） | +2825 行（其中 1079 行测试），`src/pool.rs` 单文件 +1062 |
| 端到端验证对象 | `tests/fixtures/fake-engine.py`（真引擎不在环内） | 同一 fake engine + 测试内生成的 python stub 假扮 `storeMigrate` |

现网行为（今天装着的二进制）：

1. 引擎子进程**没有** `KT_SIGNAL_STORE_KEY`：C 之前那行是无条件 `.env_remove(crate::store::STORE_KEY_ENV)`，注释写着「Phase 3: keys travel the bootstrap channel only」（见 `git show d87ff46 -- src/engine.rs` 里被删的旧行）。
2. `KT_ENGINE_STORE_MIGRATE` 未设 → 闸在第一个分支就 return（`src/pool.rs:1266-1270`），不 spawn、不读盘。
3. 连接器自己的库是 SQLCipher，且 `Store::open` 在「有 key + 明文文件」时会**自己就地迁移**（`src/store.rs:3487-3491`），并带 §4.266 的快照 / 完整性闸 / 失败回滚（`docs/implementation-plan.md:20601-20651`）。

---

## 1. 不做会怎样

### 1.1 不做 C：唯一的损失是「安全姿态」，而且被同目录的明文导出物稀释

**场景 C-1：本地同用户代码读取 engine 库**

- 触发条件：`<signal-data>/engines/<acct>/accounts/lk-*/store.db` 是明文 SQLite（`docs/implementation-plan.md:21178-21184` 写的就是这个现状），任何以该用户身份运行的进程 `sqlite3 store.db .dump` 即可拿到全部会话与消息。
- 概率（估算，需现网取证）：这不是「设备丢失」概率，而是「本地代码执行」概率 × 1。设备丢失/送修是低频事件（每年个位数百分比量级），但一旦发生就是 100% 生效；恶意本地进程是中等偏低概率、但覆盖用户面广。**可查的判断依据不是概率，而是 state-dir 是否落在云同步目录**——这一条能直接查，不用猜。
- 影响面：该客户端**全部账号**的全部本地历史（引擎按账号一个 data dir；`AGENTS.md` 记录硬上限 8 个）。

**场景 C-2：同一个 state-dir 里已经有一份明文全量导出**

- `state_dir/plaintext-exports/<accountId>/plaintext-export-<stamp>.jsonl` 是本仓**已上线**的能力（`src/backup_export.rs:961-975`，wire 面 `backups.export*`，schema 描述在 `schemas/connector-api-v1.schema.json:6777`）。
- 它**没有保留期**：唯一清理点是 account.delete（`src/backup_export.rs:1233-1242`，被 `src/registry.rs:1747-1754` 调用）。
- 结论：C 上线后，「磁盘上有一份可读的全部历史」这件事**仍然成立**（只要用户点过一次导出）。所以 C 的收益不是「消灭明文」，而是「把默认路径的明文收窄到导出物」。这个收益是真的，但它把「不做 C 的代价」从「灾难」降级成「默认姿态不够好」，性价比判断随之改变。

**不做 C 不会产生任何运行时故障**：不起引擎失败、不误拒、不丢数据。它只有一个安全姿态缺口，而这个缺口有一个已经上线、更宽的同源兄弟（C-2）。

### 1.2 不做 D：收益完全条件于一个不在本仓的发布

**场景 D-1：engine C 发布后，存量明文库全部打不开**

- 前提：engine 侧「没有 key 就不工作 / 拒绝明文库」的硬语义在 engine 仓（`docs/implementation-plan.md:21289`）。这条前提**今天不成立**，因为 engine C 还没落地；一旦落地，所有存量客户端 100% 命中（存量全是明文库）。
- 影响面：该客户端全部账号同时不可用；且 `src/registry.rs:1020-1022` 的决定是——**全槽都没起来就整机 `RUNTIME_START_FAILED`**，不是「某个账号坏了」。
- 这是支持 D 的最强论据。我的回应不是「不用管」，而是：**这件事的解不必长在 connector 的启动路径上**（见 §3.D、§3.E）。

**场景 D-2：没有编排 = 人工逐账号迁移**

- 操作者要拿到每个账号的派生 key 才能跑迁移器，而 root 只在 `Zeroizing` 内存里、connector 侧没有任何落盘副本（`docs/implementation-plan.md:21226-21257`）。也就是说「人工跑」这条路**今天根本走不通**——没人能手工算出 `HKDF(root, accountId)`。
- 影响面：迁移不可执行（不是「慢」）。这条恰好说明：真正缺的不是「编排」，而是**一个能安全拿到派生物的运维入口**（CLI 或 doctor），而不是把迁移塞进请求路径。

### 1.3 小结

| | 不做 | 做 |
|---|---|---|
| C | 默认路径明文（与已上线的明文导出物同源）；零运行时故障 | 单向门；root 备份前置条件不成立；制造 key+明文库未定义态 |
| D | 今天零故障；engine C 发布后才成为硬需求 | 默认关闭 = 今天零收益；打开后有 5 分钟级启动阻塞与误拒面 |

---

## 2. 做了会引入什么新风险

### 2.1 组合矩阵：三种组合没有一种是安全的（最致命）

| 组合 | 库 | 引擎 env | 结果 |
|---|---|---|---|
| 只 C | 明文 | 有 key | **引擎侧未定义**。若引擎按「有 key ⇒ 库必须是密文」fail-closed，则整机全账号停；本仓测试测不到（fake engine 只是把 env 读出来回报，`tests/fixtures/fake-engine.py:411`） |
| 只 D | 迁移后密文 | 无 key | 计划自己判定：C 之前的 binary 面对密文库是 fail-closed 终态、不是明文回退（`docs/implementation-plan.md:21228-21235`）→ **把库迁成引擎打不开** |
| C+D（默认） | D 默认 off → 明文 | 有 key | 等价于「只 C」，而且是**发布即可得**的默认状态（`src/pool.rs:1612` 无条件 + `src/pool.rs:191` 默认 Off） |

要点：`root_store_key` 在 serve 拓扑下**必然存在**——`Store::open` 无 key 是 `StoreKeyRequired` / `PlaintextStoreRequiresKey` 终结（`src/store.rs:3487-3488`），而 `src/registry.rs:3538-3539` 把同一把 key 交给 pool 当 root。所以 C 里那个「防御性 `RootKeyMissing` 分支」（计划自认 serve 下走不到，`docs/implementation-plan.md:21210-21213`）在生产里等于不存在：**C 实际是「100% 的池化引擎全部拿到 key，无开关」**。

这就是我反对「现在做」的核心：**C 把全量用户的第一天变成上表中间那一行；D 是唯一能把它变成第三行的手段，而 D 默认关着。**

### 2.2 单向门 + 前置条件（root 独立备份）今天不成立

- 计划把 root 的独立备份写成 C 上线的**前置条件**（`docs/implementation-plan.md:21257`），并在 21226-21248 逐条论证「回滚只能向前」。
- 本仓**没有任何备份/取回工具**：`src/main.rs:40-237` 的子命令是 serve / package / migrate-pool / manifest / sign / verify / stage / activate / rollback / measure-idle，没有一条与 root 相关；`docs/doctor-contract.md:177-230` 的 credentials / data-directory 面也不含 root。
- 也就是：交付物里「前置条件」是**别人去办的事**，代码里没有任何东西能证明它办过。评审口径上，这等于把一次不可逆的数据格式变更押在一份备忘录上。

### 2.3 时间预算自相矛盾：最坏 360.6 s > 外层 300 s

- 单槽 apply 最坏墙钟：`STORE_MIGRATION_ATTEMPTS = 3`（`src/pool.rs:139`）× `STORE_MIGRATION_BUDGET = 120 s`（`src/pool.rs:128`）+ 退避 0.6 s（`src/pool.rs:142,1442`）≈ **360.6 s**。
- 外层预算：`HOST_DISPATCH_STALL_WARN_AFTER = 300 s`（`src/host.rs:135`），除 `link.*` 外所有 dispatch 都被它包住（`src/host.rs:1007,1065-1076`）。`runtime.start`（`src/host.rs:1566`）与账号寻址的 `ensure_resident`（`src/pool.rs:1460-1467`）都在内。
- 超时后果不是「下次再来」：dispatch 被 abandon，响应是 `INTERNAL_ERROR` **retryable=true**（`src/host.rs:1528-1535`），而迁移子进程带着 `kill_on_drop(true)`（`src/engine.rs:370`）被就地杀掉——**不产生分类结果、不锁存、不置 migrated 标记**，且这次强杀不在 engine 设计的失败路径里（§3.0/§9 的「零写入」承诺覆盖的是它自己的退出路径）。
- 概率：exit 10 的定义就是「忙 / 瞬时 IO」（`src/pool.rs:134-138` 注释原文 "busy store, transient I/O"）。在计划自己强调的「越需要迁移的慢盘」上，三次都 10 属于设计预期内的结果，此时该槽必然超过 300 s。宿主按 retryable 语义重试（这是既有约定）→ 从第一个槽重来 → **永不收敛**。
- 8 槽是串行的（`src/pool.rs:1187` 的 for 循环逐个 `gate_slot_start().await`），所以哪怕每槽只 40 s，整机启动也是分钟级且无法中断。

### 2.4 误拒启动：三种退出码的全部结论都是「该账号此刻没有引擎」

- exit 2 / 10 / 11 都走不到 Start 分支（`src/pool.rs:417-468`）；`start_resident` 直接 `continue`（`src/pool.rs:1197-1200`），`wake_slot` 直接返回错误（`src/pool.rs:1499-1502`）。
- 全槽被拒 → 整机 `StartFailed`（`src/registry.rs:1020-1022`）。
- **混版是设计里假设会发生的事**，不是假设之外的意外：exit 2 的文案自己写着「connector 与 engine 版本不同 / 该 build 没有 storeMigrate」（`src/pool.rs:337-341`），exit 11 的 `StoreCipherUnavailable` 文案自己写着「connector 与 engine 必须同一 release」（`src/pool.rs:304-311`）。作者为混版准备了两条面向用户的话术，等于承认它会在现场发生；而它一旦发生，结论就是「这个账号没有引擎」。

### 2.5 闸的覆盖不完整：计划自己承认的那条路径，正好最危险

- 计划原文：supervisor 自己的崩溃重启路径不经过这道闸，把闸下沉到 supervisor「不在本阶段文件域内」（`docs/implementation-plan.md:21446-21448`）。
- 代码：`RuntimeSupervisor::restart_engine` 直接用**同一份** `EngineConfig` 起引擎（`src/supervisor.rs:3452-3472`），watchdog 在 `src/supervisor.rs:3817` 与 `src/supervisor.rs:4282` 调用它；`EngineConfig` 里带着 C 注入的 `store_key`。另有 link 路径直接 `supervisor().start()`（`src/registry.rs:1329`）。
- 后果：`src/pool.rs:1257-1260` 那句 "No migration ever runs behind a live engine, and no engine ever opens a store the migrator is still writing" **不是进程级不变量**，只是两个调用点上的约定。watchdog 重启出来的引擎会带着 key 打开一个可能还在迁移的库；计划 21449 所说的「store-migrate.lock 是唯一互斥」只互斥迁移器之间，不互斥引擎。

### 2.6 维护两套语义（一次性成本里最贵的一项）

1. **删除两套**：新加的 engine-free 删除路径（`src/registry.rs:1651-1726`）与 supervisor 的引擎删除路径并存；`src/registry.rs:1728-1754` 是同一提交里的 follow-up 补丁。这条分支存在的唯一原因是 §2.4 的误拒，而它自己又要再补一次文件半场——这是复杂度自我繁殖的样本：为 A 引入异常路径，异常路径再引入补丁。
2. **迁移两套**：仓里已有 `migrate-pool`（布局迁移，`src/main.rs:140`，有 `--dry-run`，有 fail-closed 文案 `src/registry.rs:3670-3673`），现在多一个 `storeMigrate`（加密迁移）。运维/支持看到「迁移」要分清是哪一种，而 doctor 没有任何字段能区分。
3. **一个环境变量三种含义**：`KT_SIGNAL_STORE_KEY` 在父进程是 dev 覆盖（`src/store.rs:1117-1124`）、在子进程是派生 key（`src/engine.rs:365`）、在 bootstrap 通道是 root（`src/store.rs:174-180` 注释原文 "a seam on both sides of the boundary"）。仓里为此专门开了一个测试二进制 `tests/engine_store_key_inheritance.rs` 去证明「父进程的导出不会变成子进程的 key」——**需要专门写测试来防的秘密泄漏，就是设计上的脚枪**。

### 2.7 wire 变形：字面没有，软变形四条

计划写「无 wire 变更」（`docs/implementation-plan.md:21443-21445`），字面成立。但：

1. **`CAPABILITY_UNAVAILABLE` 再扩载**：锁存用同一个码（`src/pool.rs:269-275`）。该码在 `src/` 下已有 49 处引用（含单测），schema 里它的既有含义是「这个 face 还没实现 / 未启用」（`schemas/connector-api-v1.schema.json:5930`、`:5955`）。宿主拿到的码无法区分「引擎缺能力」「媒体未开」「这个账号要重新 link」。
2. **`retryable` 被重新分配**：exit 11 → `retryable=false`（`src/pool.rs:271`），exit 2 也是 false（`src/pool.rs:355-359`）。宿主只知道「别重试了」，不知道为什么。
3. **整机启动失败面的语义扩展**：同一份 `RUNTIME_START_FAILED` 现在也可能是「迁移闸拒绝」（`src/registry.rs:1020-1022`），而宿主对该码的既有处置（重启 connector）恰好会重跑迁移，把失败放大。
4. **状态存在但不可表达**：锁存不进 `runtime.status`（计划 21444）。这一版必然要再改一次 wire 才能让 UI 显示它——今天先合、以后再补，第二次改动的成本会以「已知缺口」的形式留在文档里。

---

## 3. 更便宜的替代（按性价比排序）

### A. 先治明文导出物（最高性价比，零依赖）

- 动作：给 `plaintext-exports/` 加保留期（N 份 / N 天）+ 退出时清理；删除路径已有（`src/backup_export.rs:1233`）。
- 为什么更便宜：不碰 key、不碰引擎、不改启动路径；`SNAPSHOT_KEEP = 3` 的淘汰逻辑在 §4.266 已是现成范式（`docs/implementation-plan.md:20610-20617`）。
- 它覆盖 §1.1 里**更宽的那个洞**；做完再看 C 的剩余收益是否还值得一次单向门。

### B. doctor + 周期日志告警（覆盖「看不见」，不动启动路径）

- 现成挂点：`spawn_metrics_log` 每轮已经在打 `log_store_health`（`src/host.rs:1304-1320`，字段见 `src/metrics.rs:482-493`），并且已按槽打 `log_engine_rss`。
- 建议加的最小字段（都无内容、无 key）：
  - 每槽 `engine_store_key=injected|root_key_missing|group_engine_no_account_key`（C 已有这三值，`src/store.rs:1182-1188`）；
  - 每槽 `engine_store=plaintext|encrypted|unknown`（读 `store.db` 头 16 字节，只读）；
  - 进程级 `engine_store_migration_pending=<n>`。
- 为什么更便宜：约 30-50 行，零状态机、零子进程、零锁存、零 wire 改动，且**立刻**把「有 key 的引擎 + 明文库」变成可告警的日志。§2.1 的风险今天就可见，不用等 D。

### C. runbook + doctor 文案（0 行代码）

- 计划 21361-21365 已经写好「关开关 / 重启 / 修原因」三条；把它挪到 `docs/handover.md` 的运维段落，配套三条命令（doctor、`migrate-pool --dry-run`、`runtime.status`）。
- 覆盖 §1.2 的 D-2 里「人不知道该干什么」那一半；不覆盖「人拿不到派生 key」那一半（见 D）。

### D. CLI `store-migrate`（照 `MigratePool` 形态）+ 启动前 fail-closed 文案

- 形态：`src/main.rs:140-156` 的 `MigratePool` 已证明这条路可行（子命令 + `--dry-run` + 失败给可操作文案）；再加一个子命令复用 `engine::run_store_migration`（`src/engine.rs:354`）与 `store::derive_engine_store_key`（`src/store.rs:1152`），**不进请求路径**。
- 好处（逐条对上 §2 的风险）：
  - 不被 300 s dispatch 预算截断（§2.3 消失）；
  - 不需要锁存，所以不需要 engine-free 删除路径（§2.6-1 消失）；
  - 失败就是一条命令失败，可重跑、可 `--dry-run`（§2.4 的误拒面从「账号起不来」降为「命令失败」）；
  - 闸不用下沉 supervisor（§2.5 不再是缺口，因为启动路径上没有闸）。
- 引擎侧「拒绝明文库」的落地方式照本仓既有范式：启动前 fail-closed + 一句可操作文案，位置就在 `src/registry.rs:3670-3673` 旁边（同一段代码已经在做「布局不对就拒绝启动并给命令」）。
- 成本估算：300-500 行（含测试），对比 D 的 2825 行。

### E. 复用 contract handshake 取代 exit 2 的语义

- 仓里已有引擎契约握手与锁存（`src/engine_contract.rs`；`src/pool.rs:1226-1233` 的 `contract_fault`）。「这个 engine build 有没有 storeMigrate / 有没有 cipher」是**能力协商**问题，应当是握手的一部分，而不是「起一个子进程看它退 2」。
- 它覆盖 §2.4 的全部：混版在握手期就被判定，而不是等每个账号被拒一次。

---

## 4. 如果必须做：最小可行切片

顺序不能颠倒。每一步都可单独回滚，且都不改变「今天能起引擎」这件事。

### 切片 0（0 行代码，本周）

runbook 三页 + doctor 文案：明确「引擎库仍为明文」「root 的唯一权威副本在桌面 safeStorage」「root 丢失 = 全部账号 + state dir 一起重建」。验收：能照着文档回答「客户丢了 root 怎么办」。

### 切片 1（约 150-250 行）：派生 + dry-run，**不给长驻引擎注入**

- 只做：`derive_engine_store_key`（已有，`src/store.rs:1152`）+ `kt-signal-connector store-migrate --dry-run`（照 MigratePool 形态）+ 结果进日志。
- **不做**：不给 `EngineHandle::start` 加 env 注入（即暂不合 `src/engine.rs:3129-3152`）；不碰 `pool.rs` 的启动路径。
- 为什么这样切：dry-run 一个字节都不写（计划 21300-21305 自述），风险只剩「把一把一次性派生交给一个一次性子进程」；它换来的关键信息是——**现场那个 engine build 到底认不认 `storeMigrate`**。这个信息今天完全空白，而它决定后面两片要不要做。
- 验收：沿用现有用例的断言形状——「干跑后 `store.db` 字节不变」（现有 `dry_run_only_plans_and_still_starts_the_engine` 已这么写）。

### 切片 2（约 50 行）：观测面，不改变任何决策

- `doctor.store` 增 `engineStore{accountFingerprint, keyDecision, state}` + 周期日志行同字段（挂点见 §3.B）。
- 验收：doctor 结构单测 + 「日志行不含 ≥64 位十六进制串」的断言（`src/pool.rs` 内已有同类写法）。

### 切片 3（等四件事齐了再做）：真正的 apply

前置条件（缺一条就不做）：

1. engine 侧「key + 明文库」的语义钉死并有跨仓用例（否则 §2.1 的中间行永远悬着）；
2. root 独立备份进受控台账，且有人演练过一次恢复；
3. §2.3 的预算矛盾解决（`STORE_MIGRATION_ATTEMPTS` 降到 2 以内使 3 次内不超 300 s，或迁移不在 dispatch 内跑）；
4. §2.5 的闸下沉到 supervisor，或明确写「watchdog 重启不受闸约束」并在 §2.1 的矩阵里标红。

**最小切片的「不做清单」**（比做什么更重要）：不做锁存、不做 engine-free 删除路径、不做 exit 2 节流、不做 `already_migrated` 进程内标记、不给长驻引擎注入 key、不在 `start_resident` / `wake_slot` 里插入任何新分支。

---

## 5. 我在什么条件下改判

1. engine C 的发布窗口在两周内，且 engine 侧对「key + 明文库」有明确 fail-closed 语义 + 用例 → C 不可避免，我改为要求「C 与 D 同批发布，且 D 默认 **on**」。
2. root 独立备份真的进了台账并演练过 → §2.2 的反对理由消失。
3. 300 s 预算矛盾修掉、闸下沉 supervisor → §2.3/§2.5 消失；那时 D 的残余风险只剩「两套删除语义」，可当「可接受的债」过。

在这三条之前：**C 不合，D 不合，先做 §3.A + §3.B + §3.C。**

---

## 6. 证据索引

| # | 主张 | 依据 |
|---|---|---|
| 1 | C 无开关，root 存在即注入 | `src/pool.rs:1612-1613`；`src/engine.rs:3129-3152` |
| 2 | serve 拓扑下 root 必然存在 | `src/store.rs:3487-3488`；`src/registry.rs:3538-3539` |
| 3 | 今天子进程无 key（C 之前是 env_remove） | `git show d87ff46 -- src/engine.rs`（被删的 `env_remove` 行） |
| 4 | D 默认 off | `src/pool.rs:117,191,1266-1270` |
| 5 | 只 D 会把库迁成引擎打不开 | `docs/implementation-plan.md:21228-21235` |
| 6 | 单向门 / root 备份是前置条件 | `docs/implementation-plan.md:21226-21257` |
| 7 | 3×120 s 与 300 s 预算冲突 | `src/pool.rs:128,139,142` vs `src/host.rs:135,1007` |
| 8 | 超预算会强杀迁移器且无分类 | `src/engine.rs:370,384-407`；`src/host.rs:1528-1535` |
| 9 | 全槽被拒 → 整机启动失败 | `src/registry.rs:1020-1022` |
| 10 | 闸不覆盖 supervisor / watchdog / link | `docs/implementation-plan.md:21446-21448`；`src/supervisor.rs:3452-3472,3817,4282`；`src/registry.rs:1329` |
| 11 | 锁存对外不可见 | `docs/implementation-plan.md:21443-21445`；`migration_block` 仅测试引用 |
| 12 | 两套删除路径 | `src/registry.rs:1651-1726,1728-1754` |
| 13 | 一变量三义 | `src/store.rs:174-180,1117-1124`；`src/engine.rs:365`；`tests/engine_store_key_inheritance.rs:1-16` |
| 14 | `CAPABILITY_UNAVAILABLE` 已过载 | `src/pool.rs:269-275`；`schemas/connector-api-v1.schema.json:5930,5955` |
| 15 | 明文导出物无保留期 | `src/backup_export.rs:961-975,1233-1242`；`schemas/connector-api-v1.schema.json:6777` |
| 16 | 已有 doctor / metrics 挂点 | `src/host.rs:1304-1320`；`src/metrics.rs:482-493`；`docs/doctor-contract.md:177-245` |
| 17 | 已有 CLI 迁移先例 | `src/main.rs:140-156`；`src/registry.rs:3670-3673` |
| 18 | 本仓 store 迁移自带快照/闸/回滚（可作范式） | `docs/implementation-plan.md:20601-20651`；`src/store.rs:3489-3491` |
| 19 | 迁移器只有 stub，真引擎不在环内 | `tests/store_migrate_orchestration.rs:1-70` |
| 20 | 8 槽上限 + 串行启动 | `src/pool.rs:68,74,527,1187`；`AGENTS.md`（硬上限 8） |

---

### 附：一句话给评审会

「这两个改动都不是错的，是**太早**：C 把不可逆的东西在没有备份的情况下塞进默认路径，D 把一个两分钟级的 I/O 动作塞进五秒级的请求路径（而外层只有 300 秒就把它掐死）。先花半天做导出物保留期 + 观测字段 + runbook，能拿回这两个改动今天想要的一半收益，而且都不需要一张单向门。」
