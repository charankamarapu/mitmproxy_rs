//! Windows Traffic Redirector Library
//! 
//! This library provides FFI functions for intercepting and redirecting network traffic
//! on Windows using WinDivert. It's designed to be called from Go programs.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use std::{env, thread};
use std::sync::Mutex;
use smoltcp::wire::{Ipv4Packet, Ipv6Packet, TcpPacket, IpProtocol};

use anyhow::{anyhow, Context, Result};
use internet_packet::{ConnectionId, InternetPacket, TransportProtocol};
use log::{debug, error, info, warn};
use lru_time_cache::LruCache;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use windivert::address::WinDivertAddress;
use windivert::prelude::*;
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uint};
use std::sync::atomic::{AtomicBool, Ordering};
use once_cell::sync::Lazy;

// Re-export main functionality for external use
pub use crate::ffi::*;

mod ffi {
    use super::*;
    
    // Local type definitions to replace mitmproxy dependencies
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct ProcessInfo {
        pub pid: u32,
        pub process_name: Option<String>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize, Default)]
    pub struct IncomingTrafficInfo {
        pub is_open_event_sent: bool,
        pub written_bytes: u32,
        pub read_bytes: u32,
    }

    #[derive(Clone, Debug, Serialize, Deserialize, Default)]
    pub struct LocalInterceptConf {
        pub intercept_pids: Vec<u32>,
        pub description: String,
    }

    impl LocalInterceptConf {
        pub fn disabled() -> Self {
            Self {
                intercept_pids: Vec::new(),
                description: "Disabled".to_string(),
            }
        }
        
        pub fn should_intercept(&self, proc_info: &ProcessInfo) -> bool {
            self.intercept_pids.contains(&proc_info.pid)
        }
        
        pub fn description(&self) -> &str {
            &self.description
        }
    }

    // Constants to replace mitmproxy constants
    const MAX_PACKET_SIZE: usize = 65535;

    // Global state for FFI
    static GLOBAL_CONF: Lazy<Mutex<LocalInterceptConf>> = Lazy::new(|| Mutex::new(LocalInterceptConf::disabled()));
    static RUNNING: AtomicBool = AtomicBool::new(false);

    // Stub function to replace get_process_name
    fn get_process_name(pid: u32) -> Result<std::path::PathBuf> {
        // This is a stub implementation - in a real scenario you'd query the Windows API
        Ok(std::path::PathBuf::from(format!("process_{}.exe", pid)))
    }

    // Simple SmolPacket replacement for basic packet manipulation
    #[derive(Clone)]
    struct SimplePacket {
        data: Vec<u8>,
    }

    impl SimplePacket {
        fn try_from(data: Vec<u8>) -> Result<Self> {
            Ok(Self { data })
        }
        
        fn fill_ip_checksum(&mut self) {
            // Stub implementation - in real use you'd calculate proper checksums
            // For now, we'll just leave the packet as-is
        }
        
        fn into_inner(self) -> Vec<u8> {
            self.data
        }
    }

    #[derive(Debug)]
    enum Event {
        NetworkPacket(WinDivertAddress<NetworkLayer>, Vec<u8>),
        SocketInfo(WinDivertAddress<SocketLayer>),
        // Ipc(ipc::InterceptConf), // Commented out - IPC related
    }

    #[derive(Debug)]
    enum ConnectionState {
        Known(ConnectionAction),
        Unknown(Vec<(WinDivertAddress<NetworkLayer>, InternetPacket)>),
    }

    #[derive(Debug, Clone)]
    enum ConnectionAction {
        None,
        InterceptOutgoing(ProcessInfo),
        InterceptIncoming,
    }

    #[derive(Clone, Debug)]
    struct PacketInfo {
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
    }

    // Global HashMap protected with a Mutex for thread safety.
    static mut PACKET_MAP: Option<Mutex<HashMap<u16, PacketInfo>>> = None;
    static mut APP_PORT: u16 = 0;

    pub fn initialize_packet_map() {
        unsafe {
            PACKET_MAP = Some(Mutex::new(HashMap::new()));
        }
    }

    struct ActiveListeners(HashMap<(SocketAddr, TransportProtocol), IncomingTrafficInfo>);

    impl ActiveListeners {
        pub fn new() -> Self {
            Self(HashMap::new())
        }

        pub fn insert(
            &mut self,
            mut socket: SocketAddr,
            protocol: TransportProtocol,
            incoming_traffic_info: IncomingTrafficInfo,
        ) -> Option<IncomingTrafficInfo> {
            if socket.ip() == IpAddr::V6(Ipv6Addr::UNSPECIFIED) {
                // Dual-stack binds: binding to [::] actually binds to 0.0.0.0 as well.
                socket.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
            }
            self.0.insert((socket, protocol), incoming_traffic_info)
        }

        pub fn get(&self, mut socket: SocketAddr, protocol: TransportProtocol) -> Option<&IncomingTrafficInfo> {
            if !self.0.contains_key(&(socket, protocol)) {
                socket.set_ip(Ipv4Addr::UNSPECIFIED.into());
            }
            self.0.get(&(socket, protocol))
        }

        pub fn clear(&mut self) {
            self.0.clear();
        }
    }

    // =======================
    // FFI Interface Functions for Go
    // =======================

    /// Initialize and start the Windows redirector in a background thread
    /// Returns 0 on success, -1 if already running
    #[no_mangle]
    pub extern "C" fn start_redirector() -> c_int {
        if RUNNING.swap(true, Ordering::SeqCst) {
            return -1; // already running
        }
        
        std::thread::spawn(|| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            if let Err(e) = rt.block_on(run_redirector_main()) {
                eprintln!("Redirector error: {:?}", e);
            }
        });
        
        0
    }

    /// Stop the Windows redirector
    /// Returns 0 on success
    #[no_mangle]
    pub extern "C" fn stop_redirector() -> c_int {
        RUNNING.store(false, Ordering::SeqCst);
        0
    }

    /// Check if the redirector is currently running
    /// Returns 1 if running, 0 if not
    #[no_mangle]
    pub extern "C" fn is_redirector_running() -> c_int {
        if RUNNING.load(Ordering::SeqCst) { 1 } else { 0 }
    }

    /// Set the interceptor configuration via JSON
    /// Returns 0 on success, negative values on error
    /// json_ptr: pointer to null-terminated JSON string
    #[no_mangle]
    pub extern "C" fn set_intercept_config(json_ptr: *const c_char) -> c_int {
        if json_ptr.is_null() {
            return -1; // null pointer
        }
        
        let c_str = unsafe { CStr::from_ptr(json_ptr) };
        let json_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => return -2, // invalid UTF-8
        };
        
        let config: LocalInterceptConf = match serde_json::from_str(json_str) {
            Ok(c) => c,
            Err(_) => return -3, // invalid JSON
        };
        
        let mut global_conf = GLOBAL_CONF.lock().unwrap();
        *global_conf = config;
        
        0
    }

    /// Add a PID to the intercept list
    /// Returns 0 on success
    #[no_mangle]
    pub extern "C" fn add_intercept_pid(pid: c_uint) -> c_int {
        let mut global_conf = GLOBAL_CONF.lock().unwrap();
        if !global_conf.intercept_pids.contains(&pid) {
            global_conf.intercept_pids.push(pid);
        }
        0
    }

    /// Remove a PID from the intercept list
    /// Returns 0 on success
    #[no_mangle]
    pub extern "C" fn remove_intercept_pid(pid: c_uint) -> c_int {
        let mut global_conf = GLOBAL_CONF.lock().unwrap();
        global_conf.intercept_pids.retain(|&x| x != pid);
        0
    }

    /// Clear all PIDs from the intercept list
    /// Returns 0 on success
    #[no_mangle]
    pub extern "C" fn clear_intercept_pids() -> c_int {
        let mut global_conf = GLOBAL_CONF.lock().unwrap();
        global_conf.intercept_pids.clear();
        0
    }

    /// Get the current configuration as JSON
    /// Returns pointer to allocated string (caller must free with free_string)
    /// Returns null on error
    #[no_mangle]
    pub extern "C" fn get_intercept_config() -> *mut c_char {
        let global_conf = GLOBAL_CONF.lock().unwrap();
        let json_str = match serde_json::to_string(&*global_conf) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };
        
        let c_string = match CString::new(json_str) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };
        
        c_string.into_raw()
    }

    /// Free a string allocated by this library
    #[no_mangle]
    pub extern "C" fn free_string(ptr: *mut c_char) {
        if !ptr.is_null() {
            unsafe {
                let _ = CString::from_raw(ptr);
            }
        }
    }

    // Async main function that can be called from FFI
    async fn run_redirector_main() -> Result<()> {
        if cfg!(debug_assertions) {
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
        }

        let (event_tx, mut event_rx) = mpsc::unbounded_channel::<Event>();

        let socket_handle: WinDivert<SocketLayer> = WinDivert::socket(
            "tcp",
            1041,
            WinDivertFlags::new().set_recv_only().set_sniff(),
        )?;
        let network_handle: WinDivert<NetworkLayer> = WinDivert::network("tcp", 1040, WinDivertFlags::new())?;
        let inject_handle: WinDivert<NetworkLayer> = WinDivert::network("false", 1039, WinDivertFlags::new().set_send_only())?;

        let tx_clone: UnboundedSender<Event> = event_tx.clone();
        thread::spawn(move || relay_socket_events(socket_handle, tx_clone));
        let tx_clone: UnboundedSender<Event> = event_tx.clone();
        thread::spawn(move || relay_network_events(network_handle, tx_clone));

        let mut state: LocalInterceptConf = LocalInterceptConf::disabled();

        initialize_packet_map();

        let mut connections = LruCache::<ConnectionId, ConnectionState>::with_expiry_duration(
            Duration::from_secs(60 * 10),
        );
        let mut active_listeners: ActiveListeners = ActiveListeners::new();

        loop {
            // Check if we should stop
            if !RUNNING.load(Ordering::SeqCst) {
                info!("Stopping redirector as requested");
                break;
            }
            
            // Update state from global config periodically
            {
                let global_conf = GLOBAL_CONF.lock().unwrap();
                state = global_conf.clone();
            }
            
            let result = event_rx.recv().await.unwrap();
            match result {
                Event::NetworkPacket(address, data) => {
                    // Packet processing logic here - simplified for lib.rs
                    let packet: InternetPacket = match InternetPacket::try_from(data) {
                        Ok(p) => p,
                        Err(e) => {
                            debug!("Error parsing packet: {:?}", e);
                            continue;
                        }
                    };

                    debug!("Received packet: {} {}", packet.connection_id(), packet.tcp_flag_str());
                    
                    // Basic packet forwarding for now
                    inject_handle
                        .send(&WinDivertPacket::<NetworkLayer> {
                            address,
                            data: packet.inner().into(),
                        })
                        .context("failed to re-inject packet")?;
                }
                Event::SocketInfo(address) => {
                    // Socket event processing logic here - simplified for lib.rs
                    debug!("Socket event: {:?} pid={}", address.event(), address.process_id());
                }
            }
        }
        
        Ok(())
    }

    /// Repeatedly call WinDivertRecvEx to get socket info and feed them into the channel.
    fn relay_socket_events(handle: WinDivert<SocketLayer>, tx: UnboundedSender<Event>) {
        loop {
            let packets = handle.recv_ex(1);
            match packets {
                Ok(packets) => {
                    for packet in packets {
                        if tx.send(Event::SocketInfo(packet.address)).is_err() {
                            return; // main thread shut down.
                        }
                    }
                }
                Err(err) => {
                    eprintln!("WinDivert Error: {err:?}");
                    std::process::exit(74);
                }
            };
        }
    }

    /// Repeatedly call WinDivertRecvEx to get network packets and feed them into the channel.
    fn relay_network_events(handle: WinDivert<NetworkLayer>, tx: UnboundedSender<Event>) {
        const MAX_PACKETS: usize = 1;
        let mut buf = [0u8; MAX_PACKET_SIZE * MAX_PACKETS];
        loop {
            let packets = handle.recv_ex(Some(&mut buf), MAX_PACKETS);
            match packets {
                Ok(packets) => {
                    for packet in packets {
                        if tx
                            .send(Event::NetworkPacket(packet.address, packet.data.into()))
                            .is_err()
                        {
                            return; // main thread shut down.
                        }
                    }
                }
                Err(err) => {
                    eprintln!("WinDivert Error: {err:?}");
                    std::process::exit(74);
                }
            };
        }
    }
}