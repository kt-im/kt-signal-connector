// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;
use std::process::{Command as ProcessCommand, Stdio};
use std::time::Duration;

use clap::{Parser, Subcommand};
#[cfg(unix)]
use kt_signal_connector::API_VERSION;
use kt_signal_connector::auth::{load_bootstrap_payload, load_bootstrap_payload_from_reader};
use kt_signal_connector::datalock;
use kt_signal_connector::engine::SocksProxy;
use kt_signal_connector::groups;
use kt_signal_connector::host::serve;
use kt_signal_connector::ipc::LocalListener;
#[cfg(windows)]
use kt_signal_connector::ipc::harden_private_directory;
use kt_signal_connector::lkg::RuntimeLayout;
use kt_signal_connector::manifest::{
    LicenseRef, RuntimeManifest, artifact_for_file, build_local_unsigned_manifest,
    load_signing_key, load_verifying_key,
};
use kt_signal_connector::parent::{
    PARENT_EXIT_BUDGET, ParentDown, record_owner_marker_if_root, resolve_parent_pid, watch_parent,
};
use kt_signal_connector::pool::EnginePoolPolicy;
use kt_signal_connector::registry::{RuntimeOptions, open_group_runtime_with_options};
use kt_signal_connector::resource::{measure_child_idle, write_report};
use kt_signal_connector::store::store_key_from_env;

#[derive(Debug, Parser)]
#[command(name = "kt-signal-connector", version, about)]
struct Cli {
    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    /// Serve the private KT host protocol.
    Serve {
        #[arg(long, required_unless_present = "listen")]
        endpoint: Option<PathBuf>,
        /// Listen for the host on a loopback TCP port instead of the private
        /// unix socket (contract 1.147, §4.145 — the R2 dual-stack batch;
        /// e.g. 127.0.0.1:0, where port 0 has the kernel assign a free port).
        /// After the bind succeeds, exactly one NDJSON announce line carries
        /// the bound port on stdout and serve-mode stdout stays silent. The
        /// TCP transport is Unix-only: Windows keeps the named pipe endpoint.
        #[arg(
            long,
            value_name = "HOST:PORT",
            conflicts_with = "endpoint",
            value_parser = parse_loopback_listen
        )]
        listen: Option<std::net::SocketAddr>,
        #[arg(
            long,
            conflicts_with = "bootstrap_secret_stdin",
            required_unless_present = "bootstrap_secret_stdin"
        )]
        bootstrap_secret_file: Option<PathBuf>,
        #[arg(
            long,
            default_value_t = false,
            conflicts_with = "bootstrap_secret_file"
        )]
        bootstrap_secret_stdin: bool,
        #[arg(long)]
        parent_pid: Option<u32>,
        /// Path to the kt engine executable — the connector's signal sidecar
        /// speaking the pinned JSON-RPC face (ADR 0003: the only engine).
        /// A legacy spelling of this flag stays accepted as a hidden
        /// compatibility alias for launchers written before the naming batch
        /// (§4.148); both spellings are the same argument and the alias never
        /// appears in help.
        #[arg(long, alias = "signal-cli")]
        engine_bin: PathBuf,
        #[arg(long)]
        java_home: Option<PathBuf>,
        /// SOCKS proxy for the engine child as host:port (env:
        /// KT_SIGNAL_SOCKS_PROXY, preferred so it stays off the connector
        /// command line). The connector passes it to the child as `-D` argv
        /// properties.
        #[arg(long, env = "KT_SIGNAL_SOCKS_PROXY", value_name = "HOST:PORT")]
        socks_proxy: Option<SocksProxy>,
        /// Additional proxy group as ID=HOST:PORT; may be repeated (env:
        /// KT_SIGNAL_PROXY_GROUPS adds comma-separated entries). The implicit
        /// `default` group keeps this legacy SOCKS proxy and data directory.
        #[arg(long = "proxy-group", value_name = "ID=HOST:PORT")]
        proxy_group: Vec<String>,
        /// Media ingest opt-in (ADR 0004; the launcher decision is the whole
        /// decision since contract 1.121, §4.102): arming the flag drops
        /// `--ignore-attachments` from the child argv, arms the media
        /// governor, and advertises `attachment-download` (the §4.54 locator
        /// chain serves bytes on demand); without it every media method
        /// answers CAPABILITY_UNAVAILABLE.
        #[arg(long, default_value_t = false)]
        media_ingest: bool,
        /// Disappearing-message sweep cadence in ms (env:
        /// KT_SIGNAL_EXPIRE_SWEEP_INTERVAL_MS). The production default (30s)
        /// trades latency for quiet; integration tests tighten it.
        #[arg(
            long,
            env = "KT_SIGNAL_EXPIRE_SWEEP_INTERVAL_MS",
            default_value_t = 30_000
        )]
        expire_sweep_interval_ms: u64,
        /// Per-account engine pool (engine-pool design S1, launcher input, env:
        /// KT_SIGNAL_PER_ACCOUNT_ENGINES). Default off: the pre-pool runtime is
        /// byte-identical. When on, every NEW link provisions its own engine
        /// under `<signal-data>/engines/<accountId>`; existing accounts stay
        /// on their legacy proxy-group engine (mixed mode).
        #[arg(long, env = "KT_SIGNAL_PER_ACCOUNT_ENGINES", default_value_t = false)]
        per_account_engines: bool,
        #[arg(long)]
        signal_data_dir: PathBuf,
        #[arg(long)]
        state_dir: PathBuf,
    },
    /// Local packaging / LKG helpers (production signatures required by default).
    Package {
        #[command(subcommand)]
        command: PackageCommand,
    },
    /// Migrate legacy per-group engine data directories to the per-account
    /// pool layout (`<signal-data>/engines/<accountId>/`). Idempotent and
    /// journaled under `<signal-data>/migration/`; `--dry-run` validates and
    /// prints the plan without touching the filesystem. Requires exclusive
    /// occupancy of the data directory (no connector may be running).
    MigratePool {
        #[arg(long)]
        signal_data_dir: PathBuf,
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// The launcher's bootstrap payload (line 2 carries the store key).
        /// KT_SIGNAL_STORE_KEY, when set, wins exactly like serve mode.
        #[arg(long)]
        bootstrap_secret_file: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum PackageCommand {
    /// Build an unsigned local runtime manifest over an existing bundle directory.
    Manifest {
        #[arg(long)]
        bundle_dir: PathBuf,
        #[arg(long)]
        bundle_id: String,
        #[arg(long, default_value = env!("CARGO_PKG_VERSION"))]
        connector_version: String,
        #[arg(long)]
        platform: Option<String>,
        #[arg(long, default_value = "bin/kt-signal-connector")]
        connector_path: String,
        #[arg(long)]
        source_archive_path: Option<String>,
        #[arg(long = "license", value_name = "COMPONENT:SPDX:PATH")]
        licenses: Vec<String>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Apply an Ed25519 production signature to a complete manifest.
    Sign {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        private_key_file: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify artifact hashes and, when required, an Ed25519 production signature.
    Verify {
        #[arg(long)]
        bundle_dir: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value_t = false)]
        require_signature: bool,
        #[arg(long)]
        trusted_key_id: Option<String>,
        #[arg(long)]
        trusted_public_key_file: Option<PathBuf>,
    },
    /// Copy a verified bundle into runtime versions/ and mark it staged.
    Stage {
        #[arg(long)]
        runtime_root: PathBuf,
        #[arg(long)]
        version_id: String,
        #[arg(long)]
        bundle_dir: PathBuf,
        #[arg(long, default_value_t = false)]
        allow_unsigned: bool,
        #[arg(long)]
        trusted_key_id: Option<String>,
        #[arg(long)]
        trusted_public_key_file: Option<PathBuf>,
    },
    /// Promote staged -> active and move previous active to LKG.
    Activate {
        #[arg(long)]
        runtime_root: PathBuf,
        #[arg(long, default_value_t = false)]
        allow_unsigned: bool,
        #[arg(long)]
        trusted_key_id: Option<String>,
        #[arg(long)]
        trusted_public_key_file: Option<PathBuf>,
    },
    /// Point active back at LKG.
    Rollback {
        #[arg(long)]
        runtime_root: PathBuf,
        #[arg(long, default_value_t = false)]
        allow_unsigned: bool,
        #[arg(long)]
        trusted_key_id: Option<String>,
        #[arg(long)]
        trusted_public_key_file: Option<PathBuf>,
    },
    /// Short idle RSS sample of an executable (smoke measurement, not a 24h gate).
    MeasureIdle {
        #[arg(long)]
        executable: PathBuf,
        #[arg(long = "arg")]
        args: Vec<String>,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 500)]
        settle_ms: u64,
    },
}

/// The `--listen` argv gate (contract 1.147, §4.145): the value must parse
/// as a HOST:PORT socket address and must be an IPv4 loopback one —
/// wildcard, off-host, and IPv6 addresses are usage errors before anything
/// touches the filesystem. The message never echoes the value, the same
/// discipline as the proxy diagnostics (R10). The loopback shape is checked
/// again at the listener boundary (`LocalListener::bind_tcp`).
fn parse_loopback_listen(value: &str) -> Result<std::net::SocketAddr, String> {
    let address: std::net::SocketAddr = value
        .parse()
        .map_err(|_| "listen must be a HOST:PORT address".to_string())?;
    if !(address.is_ipv4() && address.ip().is_loopback()) {
        return Err("listen must be an IPv4 loopback host:port".to_string());
    }
    Ok(address)
}

struct ServeOptions {
    endpoint: Option<PathBuf>,
    listen: Option<std::net::SocketAddr>,
    bootstrap_secret_file: Option<PathBuf>,
    bootstrap_secret_stdin: bool,
    parent_pid: Option<u32>,
    engine_bin: PathBuf,
    java_home: Option<PathBuf>,
    socks_proxy: Option<SocksProxy>,
    proxy_group: Vec<String>,
    media_ingest: bool,
    expire_sweep_interval_ms: u64,
    per_account_engines: bool,
    signal_data_dir: PathBuf,
    state_dir: PathBuf,
}

/// Diagnostics go through `tracing` (AGENTS.md log discipline: no message
/// bodies, numbers, contacts, QR payloads, secrets, tokens, or key paths).
/// The final sink is stderr, same as the previous `eprintln!` output. Level
/// defaults to INFO; KT_SIGNAL_LOG overrides it (e.g. "debug").
fn init_tracing() {
    let level = std::env::var("KT_SIGNAL_LOG")
        .ok()
        .and_then(|value| value.parse::<tracing::Level>().ok())
        .unwrap_or(tracing::Level::INFO);
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(level)
        .try_init();
}

#[tokio::main]
async fn main() {
    init_tracing();
    let cli = Cli::parse();
    // The fatal handler needs the typed error, not just its message: the
    // launcher's structured lines (KT_FATAL ...) are rendered from the error
    // class itself (contract revision 1.284, §4.268), so the store error must
    // survive the `?` chain instead of being flattened to a string here.
    let result: Result<(), Box<dyn std::error::Error>> = match cli.command {
        CliCommand::Serve {
            endpoint,
            listen,
            bootstrap_secret_file,
            bootstrap_secret_stdin,
            parent_pid,
            engine_bin,
            java_home,
            socks_proxy,
            proxy_group,
            media_ingest,
            expire_sweep_interval_ms,
            per_account_engines,
            signal_data_dir,
            state_dir,
        } => {
            serve_command(ServeOptions {
                endpoint,
                listen,
                bootstrap_secret_file,
                bootstrap_secret_stdin,
                parent_pid,
                engine_bin,
                java_home,
                socks_proxy,
                proxy_group,
                media_ingest,
                expire_sweep_interval_ms,
                per_account_engines,
                signal_data_dir,
                state_dir,
            })
            .await
        }
        CliCommand::Package { command } => package_command(command).map_err(Into::into),
        CliCommand::MigratePool {
            signal_data_dir,
            state_dir,
            dry_run,
            bootstrap_secret_file,
        } => migrate_pool_command(
            &signal_data_dir,
            &state_dir,
            dry_run,
            bootstrap_secret_file.as_deref(),
        ),
    };
    if let Err(error) = result {
        // The final exit diagnostic: the classified message of the failing
        // error type (Display is content-free across this crate).
        let message = error.to_string();
        tracing::error!(error = %message, "connector exiting with an error");
        // Structured, machine-readable fatal cause for the launcher. This is
        // the only channel available when the store cannot open (the RPC
        // socket never exists), so the desktop can map a rejected key — or a
        // store written by a newer connector — to the repair surface instead
        // of retrying the same spawn five times. The class owns its line; an
        // error without a launcher contract prints nothing extra.
        if let Some(line) = kt_signal_connector::store::fatal_line_for(error.as_ref()) {
            eprintln!("{line}");
        }
        std::process::exit(1);
    }
}

/// Contract 1.147 (§4.145): the TCP leg announces its kernel-assigned port
/// with exactly one NDJSON line on stdout — the byte shape the desktop's
/// batch-2 parser matches (`apiVersion`, `event`, `transport`, `host`,
/// `port`, in this order). Written only after the bind succeeded, and the
/// last stdout byte serve mode ever emits: everything after it goes to
/// stderr, so the launcher can hold one announce line and then drain
/// without a backpressure hazard.
#[cfg(unix)]
fn write_listen_announce(address: std::net::SocketAddr) -> std::io::Result<()> {
    use std::io::Write;

    let line = format!(
        "{{\"apiVersion\":\"{API_VERSION}\",\"event\":\"listening\",\"transport\":\"tcp\",\
         \"host\":\"{}\",\"port\":{}}}\n",
        address.ip(),
        address.port()
    );
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(line.as_bytes())?;
    stdout.flush()
}

async fn serve_command(options: ServeOptions) -> Result<(), Box<dyn std::error::Error>> {
    let ServeOptions {
        endpoint,
        listen,
        bootstrap_secret_file,
        bootstrap_secret_stdin,
        parent_pid,
        engine_bin,
        java_home,
        socks_proxy,
        proxy_group,
        media_ingest,
        expire_sweep_interval_ms,
        per_account_engines,
        signal_data_dir,
        state_dir,
    } = options;
    if cfg!(windows) && !bootstrap_secret_stdin {
        return Err("Windows requires the inherited bootstrap secret pipe".into());
    }
    if cfg!(windows) && parent_pid.is_none() {
        return Err("Windows requires the parent process monitor".into());
    }
    // Proxy-group configuration is validated before anything else touches
    // the filesystem or the bootstrap payload: a malformed spec must fail the
    // launch without leaking any endpoint into diagnostics (ADR 0001 R10).
    // Flag entries come first in launcher order, then environment entries;
    // duplicates across the two sources are rejected rather than merged.
    // Capability shaping for the kt engine (the media-ingest pass-through
    // and the ignored --java-home) happens in `open_group_runtime`.
    let env_spec = std::env::var("KT_SIGNAL_PROXY_GROUPS").ok();
    let plan = groups::build_group_plan(
        &proxy_group,
        env_spec.as_deref(),
        socks_proxy,
        &signal_data_dir,
    )?;
    // ADR 0002 occupancy guard: exclusive cross-process locks over every
    // planned data directory (the `default` root and each proxy-group
    // subdirectory), acquired before the bootstrap payload is read and held
    // for process lifetime. A second connector over any shared data
    // directory fails fast here without touching secrets or publishing an
    // endpoint; a crashed holder's locks die with the process (kernel
    // release), so this can never brick the next start.
    let _data_dir_locks = datalock::lock_plan_data_dirs(&plan)?;
    // P1 ownership marker: the root data directory records this generation's
    // pid so an immediate restart whose launcher did not pass --parent-pid
    // can still bridge to it (see parent.rs). Best effort, after the lock is
    // held and before any engine can be started.
    record_owner_marker_if_root(&signal_data_dir, std::time::SystemTime::now());
    let payload = if bootstrap_secret_stdin {
        load_bootstrap_payload_from_reader(std::io::stdin().lock())?
    } else {
        load_bootstrap_payload(
            bootstrap_secret_file
                .as_deref()
                .ok_or("bootstrap secret source is required")?,
        )?
    };
    // Phase 3 key contract: the desktop delivers the 32-byte store key as
    // bootstrap payload line 2; KT_SIGNAL_STORE_KEY is the dev/test override
    // and wins when set. The key never crosses the socket, never enters the
    // wire protocol, and is never logged.
    let store_key = match store_key_from_env()? {
        Some(key) => Some(key),
        None => payload.store_key,
    };
    #[cfg(windows)]
    {
        let root = state_dir
            .parent()
            .ok_or("Windows state directory must have a profile root")?;
        std::fs::create_dir_all(root)?;
        std::fs::create_dir_all(&signal_data_dir)?;
        std::fs::create_dir_all(&state_dir)?;
        harden_private_directory(root)?;
        harden_private_directory(&signal_data_dir)?;
        harden_private_directory(&state_dir)?;
    }
    // Contract 1.147 (§4.145): the transport is the launcher's choice — the
    // legacy unix-socket endpoint, or the R2 loopback TCP leg. The TCP bind
    // carries the UDS leg's timing exactly: the port exists before anything
    // announces it (bind first, announce second — no probe TOCTOU window),
    // and a runtime-open failure after the announce converges to the same
    // START_FAILED the UDS leg's post-bind failures always produced.
    let listener = match listen {
        Some(address) => {
            #[cfg(windows)]
            {
                let _ = &address;
                return Err(
                    "the TCP listen transport is Unix-only; Windows keeps the named pipe endpoint"
                        .into(),
                );
            }
            #[cfg(unix)]
            {
                let listener = LocalListener::bind_tcp(address).await?;
                write_listen_announce(listener.tcp_address()?)?;
                listener
            }
        }
        None => {
            let endpoint = endpoint.expect("clap requires --endpoint unless --listen is given");
            LocalListener::bind(&endpoint)?
        }
    };
    let runtime = open_group_runtime_with_options(
        plan,
        engine_bin,
        &state_dir,
        java_home,
        store_key,
        media_ingest,
        Duration::from_millis(expire_sweep_interval_ms),
        RuntimeOptions {
            per_account_engines,
            // Full pooling keeps every linked account resident by default;
            // KT_SIGNAL_POOL_MAX_RESIDENT is the low-memory opt-out.
            pool_policy: if per_account_engines {
                EnginePoolPolicy::from_env()
            } else {
                EnginePoolPolicy::default()
            },
            ..RuntimeOptions::default()
        },
    )?;
    // P0 parent watch (every platform). The engine self-exits on stdin EOF,
    // but a connector whose launcher was SIGKILLed never sees that EOF and
    // never closes its own end — so the launcher pid is watched directly and
    // the runtime teardown (which carries the engine children) runs once it
    // is gone. Windows passes --parent-pid on every start; Unix uses the flag
    // when the launcher sends it, otherwise the parent-of-record and the
    // ownership marker bridged in above.
    // The operator opt-out is evaluated first and covers both the armed and
    // the unarmed case identically: with it set the connector never watches a
    // launcher for this process lifetime (task requirement: one env key, no
    // restart-side effects).
    let watch_disabled = kt_signal_connector::parent::parent_watch_disabled();
    let recorded_parent = if watch_disabled {
        tracing::warn!(
            env = kt_signal_connector::parent::PARENT_WATCH_DISABLE_ENV,
            "connector parent watch disabled by operator; this process may outlive its launcher"
        );
        None
    } else {
        resolve_parent_pid(parent_pid, &signal_data_dir, std::time::SystemTime::now())
    };
    match recorded_parent {
        Some(recorded) => {
            tracing::info!(
                parent_via = recorded.via,
                interval_ms = kt_signal_connector::parent::PARENT_POLL_INTERVAL.as_millis() as u64,
                "connector parent watch armed"
            );
            spawn_parent_watch(recorded, runtime.clone(), signal_data_dir.clone());
        }
        None => {
            if !watch_disabled {
                tracing::info!("connector parent watch not armed (no launcher pid evidence)");
            }
        }
    }
    // 会话终局即退（outbound_evidence 诊断批根因修复）：serve 返回就是进程
    // 终态——有界 teardown（HOST_SHUTDOWN_TIMEOUT 预算 + 子进程收割）已在
    // serve 内跑完，宿主断开 / ctrl_c / 父进程消失三出口在此汇合。这里必须
    // 显式定局退出，不能走隐式 Runtime drop：a9e5cd9 的 P0 parent-watch 是
    // blocking 任务，按设计只在 launcher 死亡时返回；launcher 仍活着时
    // （真实桌面正常活着重启会话、测试 harness）隐式 drop 在
    // BlockingPool::shutdown 上永久挂死，「host 断开即退」失锚（探针实测
    // 25s+ 不退；栈采样 main 卡 BlockingPool Condvar、blocking 线程卡
    // parent::wait_for_parent_exit nanosleep）。与既有两处 process::exit
    // 纪律同构（上方错误出口 exit(1)；parent-down 出口 exit(0)）：
    // flock/管道随进程由内核回收，engine 子进程 stdin EOF 自退。
    match serve(listener, payload.secret, runtime).await {
        Ok(()) => std::process::exit(0),
        Err(error) => Err(error)?,
    }
}

/// The P0 exit path: the launcher is gone, so the connector must not outlive
/// it. The runtime teardown runs under a bounded budget (every engine child
/// is stopped, or killed directly when the budget expires), the engine
/// children are then reaped so no zombie survives this process, and only
/// then does the process exit without serving anything else.
///
/// The `data_dir` field is the only path this line carries: it names the
/// directory that was about to be stranded, which is what an operator needs
/// to correlate the exit with the failed next start. Nothing account-shaped
/// (numbers, ACIs, key paths) ever rides along.
fn spawn_parent_watch(
    recorded: kt_signal_connector::parent::RecordedParent,
    runtime: std::sync::Arc<kt_signal_connector::registry::ProxyGroupRuntime>,
    data_dir: std::path::PathBuf,
) {
    tokio::spawn(async move {
        let down = watch_parent(recorded).await;
        let reason = match down {
            ParentDown::Reparented => kt_signal_connector::parent::REASON_REPARENTED,
            ParentDown::Vanished => kt_signal_connector::parent::REASON_VANISHED,
        };
        // The engine pids are read before the teardown clears the runtime: a
        // child the supervisor already dropped is not ours to reap, but one
        // it is about to drop is, and the wait below must not race it.
        let child_pids = runtime.engine_pids().await;
        tracing::warn!(
            reason,
            data_dir = %data_dir.display(),
            engines = child_pids.len(),
            budget_ms = PARENT_EXIT_BUDGET.as_millis() as u64,
            "launcher is gone; stopping the runtime and exiting"
        );
        match tokio::time::timeout(PARENT_EXIT_BUDGET, runtime.shutdown()).await {
            Ok(Ok(())) => tracing::info!(reason, "runtime stopped after launcher loss"),
            Ok(Err(error)) => {
                tracing::warn!(reason, error_class = ?error, "runtime teardown after launcher loss failed")
            }
            Err(_) => tracing::warn!(
                reason,
                "runtime teardown after launcher loss exceeded its budget; exiting anyway"
            ),
        }
        // P1 zombie discipline: the runtime normally reaps its children, but a
        // teardown that hit the budget leaves them unreaped (Z) until this
        // process is gone — and this process exits by definition right here.
        // Bounded, and a no-op for pids the tokio child handle already reaped.
        kt_signal_connector::parent::reap_children(&child_pids, PARENT_EXIT_BUDGET / 2).await;
        std::process::exit(0);
    });
}

/// `migrate-pool`: the explicit operator face of the automatic startup
/// migration. It takes the same data-directory occupancy lock the connector
/// takes, so it can never move stores under a live engine. `--dry-run` runs
/// every validation and prints the same report shape as the applied pass.
fn migrate_pool_command(
    signal_data_dir: &std::path::Path,
    state_dir: &std::path::Path,
    dry_run: bool,
    bootstrap_secret_file: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let _lock = datalock::DataDirLock::acquire("default", signal_data_dir)?;
    let key = match store_key_from_env()? {
        Some(key) => Some(key),
        // Read line 2 without the launcher's read-and-destroy loader: the
        // desktop may still need that bootstrap file for its next launch.
        None => match bootstrap_secret_file {
            Some(path) => Some(read_store_key_line(path)?),
            None => None,
        },
    };
    // The store error is deliberately not flattened: a newer-schema refusal is
    // a launcher-visible class, and its fixed fatal line needs the numbers
    // (contract revision 1.284, §4.268).
    let store = kt_signal_connector::store::Store::open(state_dir, key)?;
    let report = kt_signal_connector::migrate::run(&store, signal_data_dir, state_dir, dry_run)?;
    let rendered = serde_json::to_string_pretty(&report)?;
    println!("{rendered}");
    Ok(())
}

/// Read the store key (payload line 2) without consuming the launcher's
/// bootstrap file. `KT_SIGNAL_STORE_KEY` remains the preferred override.
fn read_store_key_line(
    path: &std::path::Path,
) -> Result<kt_signal_connector::store::StoreKey, String> {
    let payload = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    let line = payload
        .lines()
        .nth(1)
        .ok_or("bootstrap payload line 2 (store key) is missing")?;
    let bytes = hex::decode(line.trim()).map_err(|_| "store key is not hexadecimal")?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "store key must be exactly 32 bytes")?;
    Ok(kt_signal_connector::store::StoreKey::from_bytes(key))
}

fn package_command(command: PackageCommand) -> Result<(), String> {
    match command {
        PackageCommand::Manifest {
            bundle_dir,
            bundle_id,
            connector_version,
            platform,
            connector_path,
            source_archive_path,
            licenses,
            output,
        } => {
            let mut manifest = build_local_unsigned_manifest(
                &bundle_dir,
                bundle_id,
                connector_version,
                &connector_path,
            )
            .map_err(|error| error.to_string())?;
            if let Some(platform) = platform {
                if !matches!(
                    platform.as_str(),
                    "macos-arm64" | "macos-x64" | "windows-x64"
                ) {
                    return Err("unsupported production runtime platform".into());
                }
                manifest.platform = platform;
            }
            if let Some(source_archive_path) = source_archive_path {
                manifest.source_archive = Some(
                    artifact_for_file(&bundle_dir, &source_archive_path)
                        .map_err(|error| error.to_string())?,
                );
            }
            if !licenses.is_empty() {
                manifest.licenses = licenses
                    .iter()
                    .map(|value| parse_license_spec(&bundle_dir, value))
                    .collect::<Result<Vec<_>, _>>()?;
            }
            manifest.save(&output).map_err(|error| error.to_string())?;
            println!(
                "wrote unsigned local manifest for {} at {}",
                manifest.platform,
                output.display()
            );
            Ok(())
        }
        PackageCommand::Verify {
            bundle_dir,
            manifest,
            require_signature,
            trusted_key_id,
            trusted_public_key_file,
        } => {
            let manifest = RuntimeManifest::load(&manifest).map_err(|error| error.to_string())?;
            if require_signature {
                let key_id = trusted_key_id
                    .as_deref()
                    .ok_or("--trusted-key-id is required with --require-signature")?;
                let key_path = trusted_public_key_file
                    .as_deref()
                    .ok_or("--trusted-public-key-file is required with --require-signature")?;
                let key = load_verifying_key(key_path).map_err(|error| error.to_string())?;
                manifest
                    .verify_production(&bundle_dir, key_id, &key)
                    .map_err(|error| error.to_string())?;
            } else {
                if trusted_key_id.is_some() || trusted_public_key_file.is_some() {
                    return Err("trusted key options require --require-signature".into());
                }
                manifest
                    .verify_artifacts(&bundle_dir)
                    .map_err(|error| error.to_string())?;
            }
            println!("manifest artifacts verified");
            Ok(())
        }
        PackageCommand::Sign {
            manifest,
            key_id,
            private_key_file,
            output,
        } => {
            let bundle_dir = manifest
                .parent()
                .ok_or("manifest must have a bundle directory")?
                .to_path_buf();
            let mut manifest =
                RuntimeManifest::load(&manifest).map_err(|error| error.to_string())?;
            manifest
                .verify_artifacts(&bundle_dir)
                .map_err(|error| error.to_string())?;
            let key = load_signing_key(&private_key_file).map_err(|error| error.to_string())?;
            manifest
                .sign_ed25519(key_id, &key)
                .map_err(|error| error.to_string())?;
            manifest.save(&output).map_err(|error| error.to_string())?;
            println!("signed runtime manifest");
            Ok(())
        }
        PackageCommand::Stage {
            runtime_root,
            version_id,
            bundle_dir,
            allow_unsigned,
            trusted_key_id,
            trusted_public_key_file,
        } => {
            let layout = RuntimeLayout::new(runtime_root);
            let trust =
                load_optional_trust(allow_unsigned, trusted_key_id, trusted_public_key_file)?;
            let path = if let Some((key_id, key)) = trust.as_ref() {
                layout.stage_production_bundle(&version_id, &bundle_dir, key_id, key)
            } else {
                layout.stage_bundle(&version_id, &bundle_dir)
            }
            .map_err(|error| error.to_string())?;
            println!("staged {} at {}", version_id, path.display());
            Ok(())
        }
        PackageCommand::Activate {
            runtime_root,
            allow_unsigned,
            trusted_key_id,
            trusted_public_key_file,
        } => {
            let layout = RuntimeLayout::new(runtime_root);
            let trust =
                load_optional_trust(allow_unsigned, trusted_key_id, trusted_public_key_file)?;
            let active = if let Some((key_id, key)) = trust.as_ref() {
                layout.activate_staged_production(key_id, key)
            } else {
                layout.activate_staged()
            }
            .map_err(|error| error.to_string())?;
            println!("activated {}", active.version_id);
            Ok(())
        }
        PackageCommand::Rollback {
            runtime_root,
            allow_unsigned,
            trusted_key_id,
            trusted_public_key_file,
        } => {
            let layout = RuntimeLayout::new(runtime_root);
            let trust =
                load_optional_trust(allow_unsigned, trusted_key_id, trusted_public_key_file)?;
            let active = if let Some((key_id, key)) = trust.as_ref() {
                layout.rollback_to_lkg_production(key_id, key)
            } else {
                layout.rollback_to_lkg()
            }
            .map_err(|error| error.to_string())?;
            println!("rolled back to {}", active.version_id);
            Ok(())
        }
        PackageCommand::MeasureIdle {
            executable,
            args,
            output,
            settle_ms,
        } => {
            let child = ProcessCommand::new(&executable)
                .args(&args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|error| error.to_string())?;
            let (report, mut child) =
                measure_child_idle("target", child, Duration::from_millis(settle_ms))
                    .map_err(|error| error.to_string())?;
            let _ = child.kill();
            let _ = child.wait();
            write_report(&output, &report).map_err(|error| error.to_string())?;
            println!("wrote resource report to {}", output.display());
            Ok(())
        }
    }
}

fn parse_license_spec(bundle_dir: &std::path::Path, value: &str) -> Result<LicenseRef, String> {
    let mut parts = value.splitn(3, ':');
    let component = parts.next().unwrap_or_default();
    let spdx = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    if component.is_empty()
        || component.len() > 128
        || spdx.is_empty()
        || spdx.len() > 128
        || path.is_empty()
    {
        return Err("license must use COMPONENT:SPDX:PATH".into());
    }
    artifact_for_file(bundle_dir, path).map_err(|error| error.to_string())?;
    Ok(LicenseRef {
        component: component.into(),
        spdx: spdx.into(),
        path: path.into(),
    })
}

fn load_optional_trust(
    allow_unsigned: bool,
    trusted_key_id: Option<String>,
    trusted_public_key_file: Option<PathBuf>,
) -> Result<Option<(String, ed25519_dalek::VerifyingKey)>, String> {
    if allow_unsigned {
        if trusted_key_id.is_some() || trusted_public_key_file.is_some() {
            return Err("trusted key options are not accepted with --allow-unsigned".into());
        }
        return Ok(None);
    }
    let key_id = trusted_key_id.ok_or("--trusted-key-id is required unless --allow-unsigned")?;
    let key_path = trusted_public_key_file
        .ok_or("--trusted-public-key-file is required unless --allow-unsigned")?;
    let key = load_verifying_key(&key_path).map_err(|error| error.to_string())?;
    Ok(Some((key_id, key)))
}
