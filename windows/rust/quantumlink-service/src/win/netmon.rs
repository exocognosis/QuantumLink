//! Windows network-change source — replacement for `NWPathMonitor` in
//! `NetworkPathObserver.swift`.
//!
//! Uses IP Helper change notifications:
//! - `NotifyIpInterfaceChange`  -> `NetworkEvent::PathChanged`
//! - `NotifyNetworkConnectivityHintChange` -> `ReachabilityChanged`
//!
//! Sleep/wake (`PreSleep`/`PostWake`) arrives via the service control
//! handler (`SERVICE_CONTROL_POWEREVENT` in [`super::service`]), not
//! here, mirroring how macOS sourced those from NSWorkspace rather than
//! the path monitor.

use crate::netmon::{EventHandler, NetworkEventSource};
use qlink_core::mesh_connection::NetworkEvent;
use std::ffi::c_void;
use std::sync::{Arc, Mutex};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, NotifyIpInterfaceChange, NotifyNetworkConnectivityHintChange,
    MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE,
};
use windows::Win32::Networking::WinSock::{AF_UNSPEC, NL_NETWORK_CONNECTIVITY_HINT};

struct Registration {
    interface_handle: HANDLE,
    connectivity_handle: HANDLE,
    /// Box kept alive for the duration of the registration; Windows
    /// calls back with this pointer.
    _context: Box<CallbackContext>,
}

// The handles are only used for cancellation from the owning thread.
unsafe impl Send for Registration {}

impl Registration {
    fn cancel(&self) {
        unsafe {
            if !self.interface_handle.is_invalid() {
                let _ = CancelMibChangeNotify2(self.interface_handle);
            }
            if !self.connectivity_handle.is_invalid() {
                let _ = CancelMibChangeNotify2(self.connectivity_handle);
            }
        }
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.cancel();
    }
}

struct CallbackContext {
    handler: EventHandler,
    last_reachable: Mutex<Option<bool>>,
}

#[derive(Default)]
pub struct WindowsNetworkEventSource {
    registration: Mutex<Option<Registration>>,
}

impl NetworkEventSource for WindowsNetworkEventSource {
    fn start(&self, handler: EventHandler) {
        self.stop();

        let context = Box::new(CallbackContext {
            handler,
            last_reachable: Mutex::new(None),
        });
        let context_ptr = &*context as *const CallbackContext as *const c_void;

        let mut interface_handle = HANDLE::default();
        let interface_status = unsafe {
            NotifyIpInterfaceChange(
                AF_UNSPEC,
                Some(on_interface_change),
                Some(context_ptr),
                false,
                &mut interface_handle,
            )
        };
        if interface_status.is_err() {
            tracing::warn!("NotifyIpInterfaceChange registration failed");
        }

        let mut connectivity_handle = HANDLE::default();
        let connectivity_status = unsafe {
            NotifyNetworkConnectivityHintChange(
                Some(on_connectivity_change),
                Some(context_ptr),
                false,
                &mut connectivity_handle,
            )
        };
        if connectivity_status.is_err() {
            tracing::warn!("NotifyNetworkConnectivityHintChange registration failed");
        }

        *self.registration.lock().unwrap() = Some(Registration {
            interface_handle,
            connectivity_handle,
            _context: context,
        });
    }

    fn stop(&self) {
        drop(self.registration.lock().unwrap().take());
    }
}

impl Drop for WindowsNetworkEventSource {
    fn drop(&mut self) {
        self.stop();
    }
}

pub(crate) fn probe_start_stop_restart() -> Result<(), String> {
    let source = WindowsNetworkEventSource::default();
    let callback_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let first_count = Arc::clone(&callback_count);
    source.start(Box::new(move |_| {
        first_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }));
    source.stop();

    let second_count = Arc::clone(&callback_count);
    source.start(Box::new(move |_| {
        second_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }));
    source.stop();

    Ok(())
}

unsafe extern "system" fn on_interface_change(
    caller_context: *const c_void,
    _row: *const MIB_IPINTERFACE_ROW,
    _notification_type: MIB_NOTIFICATION_TYPE,
) {
    if caller_context.is_null() {
        return;
    }
    let context = &*(caller_context as *const CallbackContext);
    (context.handler)(NetworkEvent::PathChanged);
}

unsafe extern "system" fn on_connectivity_change(
    caller_context: *const c_void,
    connectivity_hint: NL_NETWORK_CONNECTIVITY_HINT,
) {
    if caller_context.is_null() {
        return;
    }
    let context = &*(caller_context as *const CallbackContext);
    // ConnectivityLevelHintNone == 0 per nldef.h; anything above "none"
    // counts as reachable for transport re-probe purposes.
    let reachable = connectivity_hint.ConnectivityLevel.0 > 0;
    let changed = {
        let mut last = context.last_reachable.lock().unwrap();
        if *last != Some(reachable) {
            *last = Some(reachable);
            true
        } else {
            false
        }
    };
    if changed {
        (context.handler)(NetworkEvent::ReachabilityChanged { reachable });
    }
}
