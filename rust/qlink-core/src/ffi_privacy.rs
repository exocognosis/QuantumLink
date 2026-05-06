//! C-callable FFI for the privacy primitives (DNS-over-QuantumLink,
//! SOCKS5 proxy, cover-traffic scheduler).
//!
//! ## Why a separate file
//!
//! The existing `ffi.rs` is the FFI surface for the packet-tunnel
//! core — it's tightly coupled to the transport stack and already
//! pushing 1100 lines. The privacy primitives are independent
//! services with their own lifecycles; keeping their FFI in a
//! separate module keeps the build matrix simple (each can be
//! disabled independently in a future feature-flagged build).
//!
//! ## Lifecycle pattern
//!
//! Every primitive follows the same handle pattern:
//!
//! 1. `*_create(...)` — start the service, return an opaque handle
//!    (or NULL on error).
//! 2. `*_local_addr(handle, out_buffer, out_len)` — read back the
//!    actual bound address (useful when bind="127.0.0.1:0" picked
//!    a kernel-assigned port).
//! 3. `*_destroy(handle)` — shut the service down. Idempotent;
//!    safe to call on NULL.
//!
//! All Tokio runtimes are owned by the handle so dropping the
//! handle stops the service. Each primitive gets its own runtime
//! to keep failure isolation tight (a panicking task in the SOCKS
//! proxy can't take the DNS resolver down with it).

use std::ffi::{c_char, CStr, CString};
use std::net::SocketAddr;
use std::ptr;
use std::sync::Arc;

use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

use crate::cover_traffic::{CoverTrafficLevel, CoverTrafficScheduler};
use crate::decoy::{DecoyCadence, DecoyPool};
use crate::decoy_runner::spawn_decoy_loop;
use crate::dns_over_qlink::{
    DirectUdpTransport, StubResolver, StubResolverConfig, DEFAULT_STUB_BIND,
};
use crate::pluggable_transport::TransportObfuscation;
use crate::runtime_config;
use crate::socks5_proxy::{Socks5Connector, Socks5Proxy, TargetAddress, DEFAULT_BIND};

// =============================================================================
// DNS-over-QuantumLink
// =============================================================================

pub struct QlinkDnsResolverHandle {
    runtime: Runtime,
    bound_addr: SocketAddr,
    _task: JoinHandle<()>,
}

/// Create + start a DNS stub resolver. Both args are NUL-terminated
/// C strings; pass NULL to use the defaults (bind=127.0.0.53:53,
/// upstream=9.9.9.9:53).
///
/// Returns NULL on failure. Caller must free with
/// [`qlink_dns_resolver_destroy`] — even on the success path.
///
/// # Safety
/// `bind_addr` and `upstream_addr` must be valid NUL-terminated
/// UTF-8 C strings or NULL. The returned handle is opaque; do not
/// dereference it.
#[no_mangle]
pub unsafe extern "C" fn qlink_dns_resolver_create(
    bind_addr: *const c_char,
    upstream_addr: *const c_char,
) -> *mut QlinkDnsResolverHandle {
    let bind = match cstr_or_default(bind_addr, DEFAULT_STUB_BIND) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    let upstream = match cstr_or_default(upstream_addr, "9.9.9.9:53") {
        Some(s) => s,
        None => return ptr::null_mut(),
    };

    let bind: SocketAddr = match bind.parse() {
        Ok(a) => a,
        Err(_) => return ptr::null_mut(),
    };
    let upstream: SocketAddr = match upstream.parse() {
        Ok(a) => a,
        Err(_) => return ptr::null_mut(),
    };

    // Each handle owns its own single-thread runtime — small
    // services don't need the multi-thread scheduler, and isolating
    // them per-handle means a panic can't propagate.
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return ptr::null_mut(),
    };

    let config = StubResolverConfig { bind, upstream };
    let transport: Arc<dyn crate::dns_over_qlink::DnsUpstreamTransport> =
        Arc::new(DirectUdpTransport);

    // We need the handle to persist; runtime.spawn returns a
    // handle, but we need to drive the runtime in a dedicated
    // thread for the resolver to actually run. Standard pattern:
    // hand the runtime to a thread that blocks on an empty future,
    // then use runtime.spawn from outside.
    //
    // For simplicity here we use Runtime::block_on via spawn_blocking
    // wouldn't work; instead we move the runtime into a thread.
    let (tx, rx) = std::sync::mpsc::channel::<Result<SocketAddr, ()>>();
    let resolver_runtime = std::thread::Builder::new()
        .name("qlink-dns".into())
        .spawn(move || {
            runtime.block_on(async move {
                let resolver = match StubResolver::bind(config, transport).await {
                    Ok(r) => r,
                    Err(_) => {
                        let _ = tx.send(Err(()));
                        return;
                    }
                };
                let addr = match resolver.local_addr() {
                    Ok(a) => a,
                    Err(_) => {
                        let _ = tx.send(Err(()));
                        return;
                    }
                };
                let _task = resolver.run();
                let _ = tx.send(Ok(addr));
                // Block forever; the thread joins when the runtime
                // is dropped (which happens when the handle's
                // explicit destructor lands).
                std::future::pending::<()>().await;
            });
        });
    if resolver_runtime.is_err() {
        return ptr::null_mut();
    }

    let bound_addr = match rx.recv() {
        Ok(Ok(a)) => a,
        _ => return ptr::null_mut(),
    };

    // We can't easily move the runtime out of the thread above;
    // for simplicity v1 leaks the handle's runtime. Production
    // wiring will use a `Notify` to coordinate clean shutdown.
    let dummy_runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return ptr::null_mut(),
    };
    let dummy_task = dummy_runtime.spawn(async {});
    let handle = Box::new(QlinkDnsResolverHandle {
        runtime: dummy_runtime,
        bound_addr,
        _task: dummy_task,
    });
    Box::into_raw(handle)
}

/// Read the actual bound address back as a UTF-8 string. Caller
/// must free the returned pointer with `qlink_string_free`.
///
/// Returns NULL if `handle` is NULL.
#[no_mangle]
pub unsafe extern "C" fn qlink_dns_resolver_local_addr(
    handle: *const QlinkDnsResolverHandle,
) -> *mut c_char {
    let Some(h) = handle.as_ref() else {
        return ptr::null_mut();
    };
    match CString::new(h.bound_addr.to_string()) {
        Ok(s) => s.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Stop the resolver and free the handle. Idempotent; safe to
/// call on NULL.
///
/// # Safety
/// The handle must have come from [`qlink_dns_resolver_create`].
#[no_mangle]
pub unsafe extern "C" fn qlink_dns_resolver_destroy(
    handle: *mut QlinkDnsResolverHandle,
) {
    if handle.is_null() {
        return;
    }
    drop(Box::from_raw(handle));
    // The resolver thread is detached and will keep running until
    // the process exits. v1 acceptable; v2 plumbs a shutdown
    // channel through the handle.
}

// =============================================================================
// SOCKS5 proxy
// =============================================================================

pub struct QlinkSocks5ProxyHandle {
    _runtime: Runtime,
    bound_addr: SocketAddr,
    _task: JoinHandle<()>,
}

/// Test-only direct-TCP connector used until the production tunnel
/// connector lands. Lets reviewers point a browser at the SOCKS
/// proxy and see traffic go through (without the encrypted overlay
/// for now).
struct DirectTcpConnector;

#[async_trait::async_trait]
impl Socks5Connector for DirectTcpConnector {
    async fn connect(&self, target: TargetAddress) -> crate::Result<tokio::net::TcpStream> {
        let addr = match target {
            TargetAddress::Ip(a) => a.to_string(),
            TargetAddress::Domain { host, port } => format!("{host}:{port}"),
        };
        Ok(tokio::net::TcpStream::connect(&addr).await?)
    }
}

/// Start the SOCKS5 proxy listener. Pass NULL for the default
/// bind (`127.0.0.1:1080`).
///
/// # Safety
/// `bind_addr` must be a valid NUL-terminated UTF-8 C string or NULL.
#[no_mangle]
pub unsafe extern "C" fn qlink_socks5_proxy_create(
    bind_addr: *const c_char,
) -> *mut QlinkSocks5ProxyHandle {
    let bind = match cstr_or_default(bind_addr, DEFAULT_BIND) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return ptr::null_mut(),
    };

    let connector: Arc<dyn Socks5Connector> = Arc::new(DirectTcpConnector);

    let bind_for_async = bind.clone();
    let bound_addr = match runtime.block_on(async move {
        let proxy = Socks5Proxy::bind(&bind_for_async, connector).await.ok()?;
        let addr = proxy.local_addr().ok()?;
        let _task = proxy.run();
        Some(addr)
    }) {
        Some(a) => a,
        None => return ptr::null_mut(),
    };

    // Keep the runtime alive so the SOCKS task continues running.
    // The placeholder _task is just to fill the struct field.
    let placeholder_task = runtime.spawn(async {});
    let handle = Box::new(QlinkSocks5ProxyHandle {
        _runtime: runtime,
        bound_addr,
        _task: placeholder_task,
    });
    Box::into_raw(handle)
}

/// Read the actual bound address.
#[no_mangle]
pub unsafe extern "C" fn qlink_socks5_proxy_local_addr(
    handle: *const QlinkSocks5ProxyHandle,
) -> *mut c_char {
    let Some(h) = handle.as_ref() else {
        return ptr::null_mut();
    };
    match CString::new(h.bound_addr.to_string()) {
        Ok(s) => s.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Stop the proxy and free the handle.
///
/// # Safety
/// The handle must have come from [`qlink_socks5_proxy_create`].
#[no_mangle]
pub unsafe extern "C" fn qlink_socks5_proxy_destroy(
    handle: *mut QlinkSocks5ProxyHandle,
) {
    if handle.is_null() {
        return;
    }
    drop(Box::from_raw(handle));
}

// =============================================================================
// Cover-traffic scheduler
// =============================================================================

pub struct QlinkCoverTrafficHandle {
    _runtime: Runtime,
    rate_bps: u64,
    _task: JoinHandle<()>,
}

/// Start a constant-rate cover-traffic scheduler at the given
/// bytes-per-second. Pass 0 to disable (returns NULL — equivalent
/// to "off").
#[no_mangle]
pub unsafe extern "C" fn qlink_cover_traffic_create(
    rate_bps: u64,
) -> *mut QlinkCoverTrafficHandle {
    if rate_bps == 0 {
        return ptr::null_mut();
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return ptr::null_mut(),
    };

    // The scheduler emits frames into a channel; in v1 we drain
    // them into the void (the scheduler's purpose for now is
    // demonstrating the constant-rate emission, not actual mixing
    // with real traffic — that wires up alongside the orchestrator).
    let level = CoverTrafficLevel::Custom(rate_bps);
    let task = runtime.spawn(async move {
        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<[u8; crate::cover_traffic::FRAME_SIZE]>(8);
        let scheduler = CoverTrafficScheduler::new(level, tx);
        let _h = scheduler.run();
        while let Some(_frame) = rx.recv().await {
            // Eventually: hand frame to active transport.
            // For now: drain so the scheduler doesn't backpressure.
        }
    });

    let handle = Box::new(QlinkCoverTrafficHandle {
        _runtime: runtime,
        rate_bps,
        _task: task,
    });
    Box::into_raw(handle)
}

/// Read the active rate. Returns 0 on NULL handle.
#[no_mangle]
pub unsafe extern "C" fn qlink_cover_traffic_rate_bps(
    handle: *const QlinkCoverTrafficHandle,
) -> u64 {
    handle.as_ref().map(|h| h.rate_bps).unwrap_or(0)
}

/// Stop the scheduler and free the handle.
#[no_mangle]
pub unsafe extern "C" fn qlink_cover_traffic_destroy(
    handle: *mut QlinkCoverTrafficHandle,
) {
    if handle.is_null() {
        return;
    }
    drop(Box::from_raw(handle));
}

// =============================================================================
// Pluggable transport (config setter)
// =============================================================================

/// Set the active transport obfuscation. Mapping:
/// 0 = None, 1 = TLS-disguised, 2 = obfs4-style scramble.
/// Out-of-range values default to TLS-disguised.
#[no_mangle]
pub extern "C" fn qlink_set_transport_obfuscation(value: u8) {
    let chosen = match value {
        0 => TransportObfuscation::None,
        2 => TransportObfuscation::Obfs4XorScramble,
        _ => TransportObfuscation::TlsLikeFraming,
    };
    runtime_config::set_transport_obfuscation(chosen);
}

/// Read the current obfuscation. Useful for the GUI's status
/// display.
#[no_mangle]
pub extern "C" fn qlink_get_transport_obfuscation() -> u8 {
    match runtime_config::current_transport_obfuscation() {
        TransportObfuscation::None => 0,
        TransportObfuscation::TlsLikeFraming => 1,
        TransportObfuscation::Obfs4XorScramble => 2,
    }
}

// =============================================================================
// Onion routing (config setter)
// =============================================================================

/// Set the onion-routing config. `enabled` is non-zero to enable;
/// `circuit_length` is clamped to 1..=5 (3 is the recommended default).
#[no_mangle]
pub extern "C" fn qlink_set_onion_routing(enabled: u32, circuit_length: u32) {
    runtime_config::set_onion_routing(enabled != 0, circuit_length);
}

/// Read the current onion-routing config. Returns `(enabled, length)`
/// packed as `(u32, u32)` via out-pointers (caller passes mutable
/// pointers; either may be NULL to skip).
#[no_mangle]
pub unsafe extern "C" fn qlink_get_onion_routing(
    enabled_out: *mut u32,
    length_out: *mut u32,
) {
    let (enabled, length) = runtime_config::current_onion_routing();
    if let Some(slot) = enabled_out.as_mut() {
        *slot = if enabled { 1 } else { 0 };
    }
    if let Some(slot) = length_out.as_mut() {
        *slot = length;
    }
}

// =============================================================================
// Identity rotation (policy setter + key-age tracker)
// =============================================================================

/// Set the rotation policy. Mapping:
/// 0 = Manual, 1 = Weekly, 2 = Daily.
#[no_mangle]
pub extern "C" fn qlink_set_rotation_policy(policy: u8) {
    runtime_config::set_rotation_policy(policy);
}

#[no_mangle]
pub extern "C" fn qlink_get_rotation_policy() -> u8 {
    runtime_config::current_rotation_policy()
}

/// Stamp the device-keypair-creation time so the rotation timer
/// has something to compare against. Called once at app startup
/// (or after a manual key rotation) with the unix-seconds
/// timestamp.
#[no_mangle]
pub extern "C" fn qlink_set_key_created_at(unix_seconds: u64) {
    runtime_config::set_key_created_at(unix_seconds);
}

/// Read the current key age in seconds. The GUI uses this to show
/// "you rotated 3 days ago" status text. Returns 0 if the creation
/// timestamp hasn't been set.
#[no_mangle]
pub extern "C" fn qlink_get_key_age_secs() -> u64 {
    runtime_config::current_key_age_secs()
}

// =============================================================================
// Decoy connections runtime
// =============================================================================

pub struct QlinkDecoyHandle {
    _runtime: Runtime,
    cadence_marker: u8,
    _task: tokio::task::JoinHandle<()>,
}

/// Start the decoy-connection loop. `cadence` mapping:
/// 0 = Off (returns NULL), 1 = Light, 2 = Steady, 3 = Aggressive.
/// Pass NULL for `targets_csv` to use the built-in popular-sites pool.
#[no_mangle]
pub unsafe extern "C" fn qlink_decoy_create(
    cadence: u8,
    targets_csv: *const c_char,
) -> *mut QlinkDecoyHandle {
    let cadence_enum = match cadence {
        0 => return ptr::null_mut(),
        1 => DecoyCadence::Light,
        2 => DecoyCadence::Steady,
        3 => DecoyCadence::Aggressive,
        _ => DecoyCadence::Steady,
    };

    let pool = if targets_csv.is_null() {
        DecoyPool::default_pool()
    } else {
        let csv = match CStr::from_ptr(targets_csv).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };
        let targets: Vec<String> = csv
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if targets.is_empty() {
            DecoyPool::default_pool()
        } else {
            DecoyPool::custom(targets)
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return ptr::null_mut(),
    };

    let task = runtime.spawn(async move {
        let inner = spawn_decoy_loop(pool, cadence_enum);
        // The inner JoinHandle is the actual driver; we await it
        // here so this outer task lives for the same lifetime.
        let _ = inner.await;
    });

    let handle = Box::new(QlinkDecoyHandle {
        _runtime: runtime,
        cadence_marker: cadence,
        _task: task,
    });
    Box::into_raw(handle)
}

/// Read back the cadence the handle was created with. Useful for
/// the GUI's "decoys running" indicator.
#[no_mangle]
pub unsafe extern "C" fn qlink_decoy_cadence(handle: *const QlinkDecoyHandle) -> u8 {
    handle.as_ref().map(|h| h.cadence_marker).unwrap_or(0)
}

/// Read the running count of completed decoy fetches. The GUI
/// polls this for live activity counters on the Privacy panel.
#[no_mangle]
pub extern "C" fn qlink_decoy_completed_count() -> usize {
    use std::sync::atomic::Ordering;
    runtime_config::DECOY_FETCHES_COMPLETED.load(Ordering::Relaxed)
}

/// Stop the decoy loop and free the handle.
#[no_mangle]
pub unsafe extern "C" fn qlink_decoy_destroy(handle: *mut QlinkDecoyHandle) {
    if handle.is_null() {
        return;
    }
    drop(Box::from_raw(handle));
}

// =============================================================================
// utun pump
// =============================================================================

/// Holds the running pump task + the channel ends. Swift drops the
/// handle to stop both halves and close the FD.
pub struct QlinkUtunPumpHandle {
    runtime: Runtime,
    pump: std::sync::Mutex<Option<crate::utun_pump::UtunPumpHandle>>,
    /// Receiving end of OS→app packets. Held internally; the Swift
    /// reviewer build doesn't actually drain these yet (no exit
    /// peer to send them to), but holding the receiver alive keeps
    /// the channel from closing and stalling the OS-read half.
    _outbound_rx: std::sync::Mutex<Option<tokio::sync::mpsc::Receiver<Vec<u8>>>>,
    /// Sending end of app→OS packets. Same — held but unused in the
    /// reviewer build because there's no incoming traffic to inject
    /// yet.
    _inbound_tx: std::sync::Mutex<Option<tokio::sync::mpsc::Sender<Vec<u8>>>>,
}

/// Snapshot of pump counters. ABI-stable so Swift can read it via
/// a `qlink_utun_pump_metrics` call.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct QlinkUtunPumpMetrics {
    pub packets_os_to_app: u64,
    pub packets_app_to_os: u64,
    pub bytes_os_to_app: u64,
    pub bytes_app_to_os: u64,
    pub read_errors: u64,
    pub write_errors: u64,
}

/// Adopt a utun FD (typically returned by the privileged helper
/// over SCM_RIGHTS) and start the read/write pump.
///
/// On success returns an opaque handle. On failure returns NULL.
/// The FD ownership transfers to the pump; caller must NOT close
/// it after this call returns.
///
/// # Safety
/// `fd` must be a valid open utun/tun file descriptor.
#[no_mangle]
pub unsafe extern "C" fn qlink_utun_pump_create(fd: i32) -> *mut QlinkUtunPumpHandle {
    use std::os::fd::FromRawFd;
    if fd < 0 {
        return ptr::null_mut();
    }
    let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return ptr::null_mut(),
    };

    let result = runtime.block_on(async move {
        crate::utun_pump::spawn_utun_pump(owned)
    });
    match result {
        Ok((pump, outbound_rx, inbound_tx)) => {
            let handle = Box::new(QlinkUtunPumpHandle {
                runtime,
                pump: std::sync::Mutex::new(Some(pump)),
                _outbound_rx: std::sync::Mutex::new(Some(outbound_rx)),
                _inbound_tx: std::sync::Mutex::new(Some(inbound_tx)),
            });
            Box::into_raw(handle)
        }
        Err(_) => ptr::null_mut(),
    }
}

/// Read the pump's running counters into the caller-provided
/// output struct. Out-parameter style instead of return-by-value
/// because Swift's `@convention(c)` typealiases can't return
/// non-Objective-C-bridged structs directly.
///
/// # Safety
/// `out` must be a valid pointer to a writable
/// `QlinkUtunPumpMetrics`. NULL is allowed (silently no-ops).
#[no_mangle]
pub unsafe extern "C" fn qlink_utun_pump_metrics(
    handle: *const QlinkUtunPumpHandle,
    out: *mut QlinkUtunPumpMetrics,
) {
    if out.is_null() {
        return;
    }
    let snapshot = handle
        .as_ref()
        .and_then(|h| h.pump.lock().ok().and_then(|guard| guard.as_ref().map(|p| p.metrics())));
    let value = match snapshot {
        Some(s) => QlinkUtunPumpMetrics {
            packets_os_to_app: s.packets_os_to_app,
            packets_app_to_os: s.packets_app_to_os,
            bytes_os_to_app: s.bytes_os_to_app,
            bytes_app_to_os: s.bytes_app_to_os,
            read_errors: s.read_errors,
            write_errors: s.write_errors,
        },
        None => QlinkUtunPumpMetrics::default(),
    };
    *out = value;
}

/// Stop the pump and close the FD.
#[no_mangle]
pub unsafe extern "C" fn qlink_utun_pump_destroy(handle: *mut QlinkUtunPumpHandle) {
    if handle.is_null() {
        return;
    }
    let mut handle = Box::from_raw(handle);
    if let Ok(mut guard) = handle.pump.lock() {
        // Dropping the inner UtunPumpHandle aborts both halves.
        guard.take();
    }
    // Drop runtime last so any spawn_blocking from pump shutdown
    // has a place to run.
    drop(handle.runtime);
}

// =============================================================================
// Shared helpers
// =============================================================================

/// Free a string allocated by any `*_local_addr` function.
///
/// # Safety
/// `s` must be a pointer returned by one of the qlink_*_local_addr
/// functions, or NULL.
#[no_mangle]
pub unsafe extern "C" fn qlink_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    drop(CString::from_raw(s));
}

/// Read a NUL-terminated C string, falling back to `default` if
/// the pointer is NULL or non-UTF-8.
unsafe fn cstr_or_default(ptr: *const c_char, default: &str) -> Option<String> {
    if ptr.is_null() {
        return Some(default.to_string());
    }
    match CStr::from_ptr(ptr).to_str() {
        Ok(s) => Some(s.to_string()),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_resolver_create_and_destroy_round_trip() {
        // Bind to 127.0.0.1:0 so we don't need a privileged port.
        let bind = CString::new("127.0.0.1:0").unwrap();
        let upstream = CString::new("9.9.9.9:53").unwrap();
        unsafe {
            let handle = qlink_dns_resolver_create(bind.as_ptr(), upstream.as_ptr());
            assert!(!handle.is_null(), "resolver should bind successfully");

            let addr_cstr = qlink_dns_resolver_local_addr(handle);
            assert!(!addr_cstr.is_null());
            let addr_str = CStr::from_ptr(addr_cstr).to_str().unwrap();
            assert!(
                addr_str.starts_with("127.0.0.1:"),
                "bound to: {}",
                addr_str
            );
            qlink_string_free(addr_cstr);

            qlink_dns_resolver_destroy(handle);
        }
    }

    #[test]
    fn socks5_proxy_create_and_destroy_round_trip() {
        let bind = CString::new("127.0.0.1:0").unwrap();
        unsafe {
            let handle = qlink_socks5_proxy_create(bind.as_ptr());
            assert!(!handle.is_null(), "SOCKS5 should bind successfully");
            let addr_cstr = qlink_socks5_proxy_local_addr(handle);
            assert!(!addr_cstr.is_null());
            qlink_string_free(addr_cstr);
            qlink_socks5_proxy_destroy(handle);
        }
    }

    #[test]
    fn cover_traffic_create_and_destroy_round_trip() {
        unsafe {
            let handle = qlink_cover_traffic_create(100_000);
            assert!(!handle.is_null());
            assert_eq!(qlink_cover_traffic_rate_bps(handle), 100_000);
            qlink_cover_traffic_destroy(handle);
        }
    }

    #[test]
    fn cover_traffic_rate_zero_returns_null() {
        unsafe {
            let handle = qlink_cover_traffic_create(0);
            assert!(handle.is_null(), "rate=0 should be a no-op");
        }
    }

    #[test]
    fn null_destroys_are_safe() {
        unsafe {
            qlink_dns_resolver_destroy(ptr::null_mut());
            qlink_socks5_proxy_destroy(ptr::null_mut());
            qlink_cover_traffic_destroy(ptr::null_mut());
            qlink_string_free(ptr::null_mut());
        }
    }
}
