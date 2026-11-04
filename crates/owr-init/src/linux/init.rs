//! PID 1 boot sequence: everything between the kernel handing over control and the event loop.
//!
//! Order (see `README.md`): pseudo filesystems -> console -> journal/tracing -> watchdog ->
//! board -> data partition -> failsafe decision -> root overlay + `pivot_root` -> hostname ->
//! services (kmodloader, coldplug, `owr-apply`, daemons) under the event loop.
//!
//! Nothing here may panic or return an error to the kernel: unrecoverable problems end in the
//! rescue loop (a restarting console shell), never in a kernel panic.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::thread::sleep;
use std::time::{Duration, Instant};

use owr_board::Board;
use owr_common::paths::{BOARD_FILE, CONFIG_DIR, CONFIG_FILE, RUN_DIR};
use rustix::fs::{Mode, OFlags};
use rustix::process::{WaitOptions, wait};

use super::mount_exec::run_steps;
use super::runtime::{self, RuntimeConfig};
use super::shutdown;
use super::watchdog::Watchdog;
use super::{buttons, console_log, init_tracing};
use crate::boot::{
    BOOTCOUNT_NAME, BootDecision, BootInputs, BootPlan, DEFAULT_HOSTNAME, MARKER_NAME,
    data_config_dir, decide, factory_reset_marker, hostname_from_config, is_initramfs_boot,
    parse_bootcount,
};
use crate::journal::{Journal, shared};
use crate::led::{LEDS_ROOT, LedState, led_writes};
use crate::mounts::{
    BootMode, DATA_MOUNT, base_plan, parse_mountinfo, root_fstype, root_plan, storage_plan,
};
use crate::services::{
    APPLY_BIN, CHILD_PATH, SETSID_BIN, ServiceContext, build_services, console_argv,
    ssh_enabled_marker,
};

/// Journal directory on the persistent overlay.
fn journal_dir() -> PathBuf {
    Path::new(CONFIG_DIR).join("journal")
}

/// Last resort: a restarting console shell. Never returns.
fn rescue(reason: &str, watchdog: Option<&Watchdog>) -> ! {
    console_log(format_args!("FATAL: {reason}; starting rescue shell"));
    if let Some(w) = watchdog {
        // init is deliberately parked in the shell: do not let the stall check reset the board.
        w.handle().keep_alive();
    }
    loop {
        while let Ok(Some(_)) = wait(WaitOptions::NOHANG) {}
        // Own session (when setsid exists), so Ctrl-C on the console does not reach init.
        let argv = console_argv(&["/bin/sh".to_owned()], Path::new(SETSID_BIN).exists());
        let (shell, shell_args) = argv
            .split_first()
            .map_or(("/bin/sh", &[][..]), |(p, a)| (p, a));
        match Command::new(shell)
            .args(shell_args)
            .env_clear()
            .env("PATH", CHILD_PATH)
            .status()
        {
            Ok(status) => console_log(format_args!("rescue shell exited ({status})")),
            Err(e) => console_log(format_args!("cannot start {shell}: {e}")),
        }
        sleep(Duration::from_secs(1));
    }
}

/// Point stdin/stdout/stderr at `/dev/console` (without acquiring it as controlling tty, so
/// Ctrl-C on the console cannot signal init).
fn setup_console() {
    let opened = rustix::fs::open("/dev/console", OFlags::RDWR | OFlags::NOCTTY, Mode::empty());
    match opened {
        Ok(fd) => {
            let _ = rustix::stdio::dup2_stdin(&fd);
            let _ = rustix::stdio::dup2_stdout(&fd);
            let _ = rustix::stdio::dup2_stderr(&fd);
        }
        Err(e) => console_log(format_args!("cannot open /dev/console: {e}")),
    }
}

fn apply_leds(board: Option<&Board>, state: LedState) {
    let Some(board) = board else { return };
    for w in led_writes(Path::new(LEDS_ROOT), &board.leds, state) {
        if let Err(e) = fs::write(&w.path, &w.value) {
            tracing::debug!("led write {}: {e}", w.path.display());
        }
    }
}

fn load_board() -> Option<Board> {
    match Board::load(Path::new(BOARD_FILE)) {
        Ok(b) => {
            tracing::info!("board {} ({})", b.board.id, b.board.model);
            Some(b)
        }
        Err(e) => {
            tracing::error!("cannot load {BOARD_FILE}: {e}");
            None
        }
    }
}

/// Wipe the persistent overlay if a factory reset was requested (data partition is mounted,
/// overlay not yet).
fn maybe_factory_reset() {
    let marker = factory_reset_marker();
    if !marker.exists() {
        return;
    }
    tracing::warn!("factory reset requested: wiping the persistent overlay");
    for dir in ["upper", "work"] {
        let path = Path::new(DATA_MOUNT).join(dir);
        if let Err(e) = fs::remove_dir_all(&path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::error!("factory reset: cannot remove {}: {e}", path.display());
        }
    }
    if let Err(e) = fs::remove_file(&marker) {
        tracing::error!("factory reset: cannot remove marker: {e}");
    }
}

/// Persistent boot state as read from the data partition.
struct PersistentState {
    failed_boots: u32,
    marker_present: bool,
}

fn read_persistent_state() -> PersistentState {
    let dir = data_config_dir();
    let failed_boots =
        fs::read_to_string(dir.join(BOOTCOUNT_NAME)).map_or(0, |t| parse_bootcount(&t));
    PersistentState {
        failed_boots,
        marker_present: dir.join(MARKER_NAME).exists(),
    }
}

fn write_bootcount(n: u32) {
    let dir = data_config_dir();
    if let Err(e) = fs::create_dir_all(&dir) {
        tracing::warn!("cannot create {}: {e}", dir.display());
        return;
    }
    let text = crate::boot::format_bootcount(n);
    if let Err(e) = owr_common::atomic_write(&dir.join(BOOTCOUNT_NAME), text.as_bytes(), 0o600) {
        tracing::warn!("cannot write boot counter: {e}");
    }
}

fn set_hostname() {
    let name = fs::read_to_string(CONFIG_FILE)
        .ok()
        .and_then(|t| hostname_from_config(&t))
        .unwrap_or_else(|| DEFAULT_HOSTNAME.to_owned());
    match rustix::system::sethostname(name.as_bytes()) {
        Ok(()) => tracing::info!("hostname {name}"),
        Err(e) => tracing::warn!("cannot set hostname {name}: {e}"),
    }
}

/// Outcome of mounting the data partition.
struct DataState {
    /// The board has an overlay partition and we tried to mount it.
    has_data: bool,
    /// Something is wrong with storage (no board, bad description, mount/mkfs failure).
    error: bool,
}

/// Format-if-blank and mount the data partition. Never touched when booted from an initramfs
/// test image.
fn mount_data(board: Option<&Board>, initramfs: bool) -> DataState {
    let mut state = DataState {
        has_data: false,
        error: !initramfs && board.is_none(),
    };
    if initramfs {
        tracing::info!("initramfs boot (root filesystem in RAM): data partition untouched");
    } else if let Some(b) = board {
        match storage_plan(&b.storage) {
            Ok(steps) if steps.is_empty() => tracing::info!("board has no overlay partition"),
            Ok(steps) => {
                state.has_data = true;
                if let Err(e) = run_steps(&steps, Some(&b.storage.device)) {
                    tracing::error!("data partition unavailable: {e}");
                    state.error = true;
                }
            }
            Err(e) => {
                tracing::error!("invalid storage description: {e}");
                state.error = true;
            }
        }
    }
    state
}

/// Choose normal vs failsafe boot and apply the counter/marker side effects and LED state.
fn decide_mode(board: Option<&Board>, cmdline: &str, data: &DataState) -> BootDecision {
    let data_ok = data.has_data && !data.error;
    if data_ok {
        maybe_factory_reset();
    }
    let persisted = if data_ok {
        read_persistent_state()
    } else {
        PersistentState {
            failed_boots: 0,
            marker_present: false,
        }
    };

    // Failsafe prompt: fast blink while listening for the reset button.
    apply_leds(board, LedState::Failsafe);
    // The window starts when the input device is opened, not at init start: mounting/mkfs
    // above may already have taken longer than the window.
    let button_pressed = board.is_some_and(buttons::button_pressed_in_window);
    let decision = decide(&BootInputs {
        button_pressed,
        cmdline,
        marker_present: persisted.marker_present,
        failed_boots: persisted.failed_boots,
        storage_ok: !data.error,
    });
    let plan = BootPlan::from_decision(&decision);
    if let Some(reason) = plan.reason {
        tracing::warn!("FAILSAFE boot: {}", reason.name());
    } else {
        tracing::info!(
            "normal boot (failed boots so far: {})",
            persisted.failed_boots
        );
    }
    tracing::info!("boot plan: {:?}", plan.phases);
    if data_ok {
        if let Some(n) = decision.write_bootcount {
            write_bootcount(n);
        }
        if decision.consume_marker
            && let Err(e) = fs::remove_file(data_config_dir().join(MARKER_NAME))
        {
            tracing::warn!("cannot consume failsafe marker: {e}");
        }
    }
    let led = if decision.mode == BootMode::Failsafe {
        LedState::Failsafe
    } else {
        LedState::Boot
    };
    apply_leds(board, led);
    decision
}

/// Entry point when running as PID 1. Never returns control to the kernel.
pub(super) fn run() -> ExitCode {
    let started = Instant::now();
    rustix::process::umask(Mode::from_raw_mode(0o022));

    if let Err(e) = run_steps(&base_plan(), None) {
        rescue(&format!("base mounts failed: {e}"), None);
    }
    setup_console();
    let journal = shared(Journal::default());
    init_tracing(&journal);
    tracing::info!("owr-init {} starting as PID 1", env!("CARGO_PKG_VERSION"));

    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").unwrap_or_else(|e| {
        tracing::error!("cannot read /proc/self/mountinfo: {e}");
        String::new()
    });
    let mounts = parse_mountinfo(&mountinfo);
    let root_fs = root_fstype(&mounts);
    tracing::info!("root filesystem: {}", root_fs.unwrap_or("unknown"));
    let initramfs = is_initramfs_boot(root_fs);
    let watchdog = match Watchdog::start(Path::new("/dev/watchdog")) {
        Ok(w) => Some(w),
        Err(e) => {
            tracing::warn!("no hardware watchdog: {e}");
            None
        }
    };
    let board = load_board();

    let data = mount_data(board.as_ref(), initramfs);
    let data_ok = data.has_data && !data.error;
    let decision = decide_mode(board.as_ref(), &cmdline, &data);

    if !initramfs {
        // Root overlay + pivot. After this the persistent files live at their final paths.
        if let Err(e) = run_steps(&root_plan(data_ok, decision.mode), None) {
            rescue(&format!("root switch failed: {e}"), watchdog.as_ref());
        }
    }
    if let Err(e) = fs::create_dir_all(RUN_DIR) {
        tracing::warn!("cannot create {RUN_DIR}: {e}");
    }
    set_hostname();

    let ctx = ServiceContext {
        failsafe: decision.mode == BootMode::Failsafe,
        apply_present: Path::new(APPLY_BIN).exists(),
        ssh_enabled: Path::new(&ssh_enabled_marker()).exists(),
        radio_phys: board
            .as_ref()
            .map(|b| b.wifi.radios.iter().map(|r| r.phy_index).collect())
            .unwrap_or_default(),
    };
    let persistent = data_ok && decision.mode == BootMode::Normal;
    let cfg = RuntimeConfig {
        pid1: true,
        mode: decision.mode,
        reason: decision.reason,
        run_dir: PathBuf::from(RUN_DIR),
        specs: build_services(&ctx),
        board,
        watchdog: watchdog.as_ref().map(Watchdog::handle),
        journal,
        journal_dir: persistent.then(journal_dir),
        bootcount_path: persistent.then(|| Path::new(CONFIG_DIR).join(BOOTCOUNT_NAME)),
        persistent,
        started,
    };

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => rescue(
            &format!("cannot start async runtime: {e}"),
            watchdog.as_ref(),
        ),
    };
    let exit = rt.block_on(runtime::run(cfg));
    drop(rt);
    shutdown::finish(&exit, watchdog)
}
