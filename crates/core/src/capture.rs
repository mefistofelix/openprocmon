//! Live capture: drive the driver, scope events, and optionally write a `.PML`.
//!
//! Connect the driver, enable requested sources, and relay events on a background
//! thread. Each event passes the dynamic [`PidScope`] and static capture filter
//! before publication and optional persistence; the capture's own process is
//! always excluded. A capture stops on size, duration, disconnection, or an
//! explicit request. The transient streaming path never allocates a PML writer.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use procmon_sdk::{
    DriverLoader, Event, EventClass, MonitorController, MonitorFlags, PmlWriter, Result,
};
use serde::Serialize;

use crate::query::Expr;
use crate::scope::PidScope;

/// The capture target ("who" + "what"). `process_names`/`pids`/`include_children`
/// /`launch` are the dynamic scope; `filters` is the static capture filter
/// (same `Clause` vocabulary as a query); `monitors` selects the driver sources.
pub struct TargetSpec {
    pub process_names: Vec<String>,
    pub pids: Vec<u32>,
    pub include_children: bool,
    pub launch: Option<Vec<String>>,
    pub monitors: MonitorFlags,
    pub filter: Option<Expr>,
}

impl Default for TargetSpec {
    fn default() -> Self {
        TargetSpec {
            process_names: Vec::new(),
            pids: Vec::new(),
            include_children: true,
            launch: None,
            monitors: MonitorFlags::PROCESS
                | MonitorFlags::FILE
                | MonitorFlags::REGISTRY
                | MonitorFlags::NETWORK,
            filter: None,
        }
    }
}

/// Builds [`MonitorFlags`] from source names (`process`/`file`/`registry`/
/// `network`, case-insensitive). Empty/all-unknown yields all sources.
pub fn parse_monitors(names: &[String]) -> MonitorFlags {
    if names.is_empty() {
        return MonitorFlags::PROCESS
            | MonitorFlags::FILE
            | MonitorFlags::REGISTRY
            | MonitorFlags::NETWORK;
    }
    let mut f = MonitorFlags::empty();
    for n in names {
        match n.to_ascii_lowercase().as_str() {
            "process" | "proc" => f |= MonitorFlags::PROCESS,
            "file" | "filesystem" => f |= MonitorFlags::FILE,
            "registry" | "reg" => f |= MonitorFlags::REGISTRY,
            "network" | "net" => f |= MonitorFlags::NETWORK,
            _ => {}
        }
    }
    f
}

/// Stop conditions for a capture.
#[derive(Clone, Copy)]
pub struct CaptureLimits {
    /// Stop once the written events reach this many bytes (default 512 MiB).
    pub max_bytes: usize,
    /// Optional wall-clock duration limit.
    pub duration: Option<Duration>,
}

impl Default for CaptureLimits {
    fn default() -> Self {
        CaptureLimits {
            max_bytes: 512 * 1024 * 1024,
            duration: None,
        }
    }
}

/// Why a capture stopped.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoppedReason {
    Manual,
    Duration,
    SizeLimit,
    Disconnected,
}

/// The result of a finished capture.
#[derive(Clone, Debug, Serialize)]
pub struct CaptureOutcome {
    pub pml_path: String,
    pub events_written: usize,
    pub stopped_reason: StoppedReason,
}

/// A running background capture, with optional `.PML` persistence.
pub struct CaptureSession {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<Result<CaptureOutcome>>>,
    pml_path: PathBuf,
}

impl CaptureSession {
    /// Starts capturing `spec` to `out_path` and returns immediately. The driver
    /// is loaded on demand (`Error::NotElevated` if that needs admin). If
    /// `spec.launch` is set, that process is started and added to the scope.
    pub fn start(
        loader: DriverLoader,
        spec: TargetSpec,
        limits: CaptureLimits,
        out_path: impl Into<PathBuf>,
    ) -> Result<Self> {
        Self::start_inner(loader, spec, limits, out_path.into(), None, true)
    }

    /// Starts a capture and returns a receiver that yields every scoped,
    /// filtered event immediately after it is accepted by the PML writer.
    /// Consumers can render or forward the events without waiting for capture
    /// finalization; dropping the receiver does not stop the capture.
    pub fn start_streaming(
        loader: DriverLoader,
        spec: TargetSpec,
        limits: CaptureLimits,
        out_path: impl Into<PathBuf>,
    ) -> Result<(Self, crossbeam_channel::Receiver<Event>)> {
        let (event_tx, event_rx) = crossbeam_channel::unbounded();
        let session =
            Self::start_inner(loader, spec, limits, out_path.into(), Some(event_tx), true)?;
        Ok((session, event_rx))
    }

    /// Starts a filtered live stream without allocating a PML writer or creating
    /// a file. This is the low-overhead path for line-oriented stdout consumers.
    pub fn start_streaming_transient(
        loader: DriverLoader,
        spec: TargetSpec,
        limits: CaptureLimits,
    ) -> Result<(Self, crossbeam_channel::Receiver<Event>)> {
        let (event_tx, event_rx) = crossbeam_channel::unbounded();
        let session =
            Self::start_inner(loader, spec, limits, PathBuf::new(), Some(event_tx), false)?;
        Ok((session, event_rx))
    }

    fn start_inner(
        loader: DriverLoader,
        spec: TargetSpec,
        limits: CaptureLimits,
        out_path: PathBuf,
        event_tx: Option<crossbeam_channel::Sender<Event>>,
        persist_pml: bool,
    ) -> Result<Self> {
        let mut controller = MonitorController::connect_with_driver(loader)?;
        if spec.monitors.contains(MonitorFlags::NETWORK) {
            controller.set_resolve_addresses(true);
        }
        let rx = controller.start_with(spec.monitors)?;

        // Seed the scope: explicit pids, already-running name matches, and the
        // launched process (if any). Name matches also grow dynamically.
        let mut scope = PidScope::new(&spec.process_names, &spec.pids, spec.include_children);
        for rec in controller.processes().snapshot() {
            let base = procmon_sdk::basename(&rec.info.image_path);
            if spec
                .process_names
                .iter()
                .any(|n| n.eq_ignore_ascii_case(base))
            {
                scope.add_pid(rec.info.pid);
            }
        }
        if let Some(cmd) = &spec.launch {
            if let Some(pid) = launch_process(cmd) {
                scope.add_pid(pid);
            }
        }

        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread_out = out_path.clone();
        let filter = spec.filter;
        let monitors = spec.monitors;
        let handle = std::thread::Builder::new()
            .name("procmon-capture".into())
            .spawn(move || {
                run_capture(
                    controller,
                    rx,
                    scope,
                    filter,
                    monitors,
                    limits,
                    thread_stop,
                    thread_out,
                    event_tx,
                    persist_pml,
                )
            })
            .map_err(|e| procmon_sdk::Error::Parse(format!("spawn capture thread: {e}")))?;

        Ok(CaptureSession {
            stop,
            handle: Some(handle),
            pml_path: out_path,
        })
    }

    /// The `.PML` path this capture writes to (valid once finished).
    pub fn pml_path(&self) -> &Path {
        &self.pml_path
    }

    /// Whether the capture thread is still running.
    pub fn is_running(&self) -> bool {
        self.handle.as_ref().is_some_and(|h| !h.is_finished())
    }

    /// Waits for the capture to self-stop (size/duration limit) and finalizes.
    pub fn wait(mut self) -> Result<CaptureOutcome> {
        self.join()
    }

    /// Signals a manual stop, waits for the thread to finalize the PML, and
    /// returns the outcome.
    pub fn stop(mut self) -> Result<CaptureOutcome> {
        self.stop.store(true, Ordering::Relaxed);
        self.join()
    }

    fn join(&mut self) -> Result<CaptureOutcome> {
        match self.handle.take() {
            Some(h) => h
                .join()
                .map_err(|_| procmon_sdk::Error::Parse("capture thread panicked".into()))?,
            None => Err(procmon_sdk::Error::Parse("capture already finished".into())),
        }
    }
}

impl Drop for CaptureSession {
    fn drop(&mut self) {
        // Stop a still-running capture so the driver/thread are torn down.
        if self.handle.is_some() {
            self.stop.store(true, Ordering::Relaxed);
            let _ = self.join();
        }
    }
}

/// One-shot capture: start, run until a limit (or stop), finalize, return.
/// With no practical size/duration limit it runs until explicitly stopped or
/// until the driver channel disconnects.
pub fn capture(
    loader: DriverLoader,
    spec: TargetSpec,
    limits: CaptureLimits,
    out_path: impl Into<PathBuf>,
) -> Result<CaptureOutcome> {
    CaptureSession::start(loader, spec, limits, out_path)?.wait()
}

/// Whether an event of `class` should be written, given the user's `--monitor`
/// selection. Process monitoring is always on at the kernel (infrastructure),
/// so its events reach here even when the user did not select Process — this
/// gate keeps them out of the PML unless they asked. Profiling / Other are not
/// source-selectable, so they pass through.
fn category_selected(class: EventClass, monitors: MonitorFlags) -> bool {
    match class {
        EventClass::Process => monitors.contains(MonitorFlags::PROCESS),
        EventClass::File => monitors.contains(MonitorFlags::FILE),
        EventClass::Registry => monitors.contains(MonitorFlags::REGISTRY),
        EventClass::Network => monitors.contains(MonitorFlags::NETWORK),
        EventClass::Profiling | EventClass::Other => true,
    }
}

/// The relay thread body: drain events into the scoped, filtered PML writer.
#[allow(clippy::too_many_arguments)]
fn run_capture(
    mut controller: MonitorController,
    rx: crossbeam_channel::Receiver<Event>,
    mut scope: PidScope,
    filter: Option<Expr>,
    monitors: MonitorFlags,
    limits: CaptureLimits,
    stop: Arc<AtomicBool>,
    out_path: PathBuf,
    event_tx: Option<crossbeam_channel::Sender<Event>>,
    persist_pml: bool,
) -> Result<CaptureOutcome> {
    let own_pid = std::process::id();
    let mut writer = persist_pml.then(|| {
        let mut writer = PmlWriter::new(cfg!(target_pointer_width = "64"));
        writer.stamp_host();
        // Reuse the capture's module-version cache (pre-warmed from image-load
        // events) so finalize doesn't block on thousands of version reads.
        writer.use_module_versions(Arc::clone(controller.metadata().module_versions()));
        writer
    });
    let mut bytes = 0usize;
    let mut written = 0usize;
    let start = Instant::now();

    let reason = loop {
        if stop.load(Ordering::Relaxed) {
            break StoppedReason::Manual;
        }
        if let Some(dur) = limits.duration {
            if start.elapsed() >= dur {
                break StoppedReason::Duration;
            }
        }
        if bytes >= limits.max_bytes {
            break StoppedReason::SizeLimit;
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(ev) => {
                scope.observe(&ev);
                // Process monitoring is always on at the kernel (infrastructure:
                // process table + module list for stack resolution), but only the
                // categories the user selected via `--monitor` are written — so a
                // network-only capture gets process metadata/stacks without the
                // process/image-load event rows. This is the write-side mirror of
                // the GUI's per-category display filter.
                if ev.pid() != own_pid
                    && category_selected(ev.class(), monitors)
                    && scope.contains(&ev)
                    && filter.as_ref().is_none_or(|f| f.matches(&ev))
                {
                    let event_bytes = ev.byte_size();
                    if let Some(writer) = &mut writer {
                        writer.push_event(&ev);
                    }
                    if let Some(tx) = &event_tx {
                        // An unbounded channel keeps stdout/IPC backpressure off
                        // the driver ingest thread. If the consumer disappeared,
                        // capture and optional PML writing continue normally.
                        let _ = tx.send(ev);
                    }
                    bytes = bytes.saturating_add(event_bytes);
                    written += 1;
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                break StoppedReason::Disconnected
            }
        }
    };

    controller.stop();
    if let Some(mut writer) = writer {
        // Carry the full process table (pre-existing, event-silent processes
        // included — their INIT seeds never surface as events) so parent chains
        // survive when the PML is reopened.
        writer.stamp_processes(controller.processes());
        writer.finish_live_to_path(&out_path)?;
    }
    Ok(CaptureOutcome {
        pml_path: if persist_pml {
            out_path.to_string_lossy().into_owned()
        } else {
            String::new()
        },
        events_written: written,
        stopped_reason: reason,
    })
}

/// Spawns a process (argv) and returns its pid, or `None` on failure.
fn launch_process(argv: &[String]) -> Option<u32> {
    let (prog, args) = argv.split_first()?;
    std::process::Command::new(prog)
        .args(args)
        .spawn()
        .ok()
        .map(|child| child.id())
}
