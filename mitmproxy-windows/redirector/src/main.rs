
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use std::{env, thread};
use std::sync::Mutex;
use smoltcp::wire::{Ipv4Packet, Ipv6Packet, TcpPacket, IpProtocol};


use anyhow::{anyhow, Context, Result};
use internet_packet::{ConnectionId, InternetPacket, TransportProtocol};
use log::{debug, error, info, warn};
use lru_time_cache::LruCache;
use mitmproxy::intercept_conf::{InterceptConf, ProcessInfo, IncomingTrafficInfo};
use prost::Message;
use mitmproxy::ipc;
use mitmproxy::packet_sources::windows::IPC_BUF_SIZE;
use mitmproxy::processes::get_process_name;
use mitmproxy::MAX_PACKET_SIZE;
use std::io::Cursor;
// use tokio::io::{AsyncReadExt, AsyncWriteExt};
// use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, PipeMode};
use std::sync::Arc;
use std::io::{Read, Write};
use uds_windows::UnixStream;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use windivert::address::WinDivertAddress;
use windivert::prelude::*;
use mitmproxy::messages::SmolPacket;

#[derive(Debug)]
enum Event {
    NetworkPacket(WinDivertAddress<NetworkLayer>, Vec<u8>),
    SocketInfo(WinDivertAddress<SocketLayer>),
    Ipc(ipc::InterceptConf),
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

static mut SENT_EVENT: bool = false;

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

    pub fn remove(
        &mut self,
        mut socket: SocketAddr,
        protocol: TransportProtocol,
    ) -> Option<IncomingTrafficInfo> {
        if socket.ip() == IpAddr::V6(Ipv6Addr::UNSPECIFIED) {
            socket.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        }
        self.0.remove(&(socket, protocol))
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

#[tokio::main]
async fn main() -> Result<()> {
    if cfg!(debug_assertions) {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }
    // let args: Vec<String> = env::args().collect();

    // let pipe_name: &str = args
    //     .get(1)
    //     .map(|x: &String| x.as_str())
    //     .unwrap_or(r"\\.\pipe\mitmproxy-transparent-proxy");

    // let ipc_client: NamedPipeClient = ClientOptions::new()
    //     .pipe_mode(PipeMode::Message)
    //     .open(pipe_name)
    //     .context("Cannot open pipe")?;

    let pipe_name = r"C:\my.sock";

    let ipc_client = UnixStream::connect(pipe_name).context("Cannot connect to Unix socket")?;

    // Clone the UnixStream to get separate reader and writer handles
    let ipc_writer = ipc_client.try_clone().context("Cannot clone UnixStream")?;
    let ipc_reader = ipc_client; // Original
    let ipc_writer = Arc::new(std::sync::Mutex::new(ipc_writer));


    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<Event>();
    let (mut ipc_tx, ipc_rx) = mpsc::unbounded_channel::<ipc::Message>();

    // We currently rely on handles being automatically closed when the program exits.
    // only needed for forward mode
    // let _icmp_handle = WinDivert::new("icmp", WinDivertLayer::Network, 1042, WinDivertFlags::new().set_drop()).context("Error opening WinDivert handle")?;

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

    let mut state: InterceptConf = InterceptConf::disabled();
    event_tx.send(Event::Ipc(state.clone().into()))?;

    initialize_packet_map();

    tokio::spawn(async move {
        if let Err(e) = handle_ipc(ipc_reader, ipc_writer, ipc_rx, event_tx).await {
            error!("Error handling IPC: {}", e);
            std::process::exit(1);
        }
    });

    let mut connections = LruCache::<ConnectionId, ConnectionState>::with_expiry_duration(
        Duration::from_secs(60 * 10),
    );
    let mut active_listeners: ActiveListeners = ActiveListeners::new();
    // Track ephemeral ports bound by the agent PID
    let mut agent_ephemeral_ports: HashSet<u16> = HashSet::new();

    loop {
        let result = event_rx.recv().await.unwrap();
        match result {
            Event::NetworkPacket(address, data) => {
                // We received a network packet and now need to figure out what to do with it.

                let packet: InternetPacket = match InternetPacket::try_from(data) {
                    Ok(p) => p,
                    Err(e) => {
                        debug!("Error parsing packet: {:?}", e);
                        continue;
                    }
                };

                debug!(
                    "Received packet: {} {} {}",
                    packet.connection_id(),
                    packet.tcp_flag_str(),
                    packet.payload().len()
                );
                

                match connections.get_mut(&packet.connection_id()) {
                    Some(state) => match state {
                        ConnectionState::Known(s) => {
                            unsafe {
                                if packet.dst_port() == APP_PORT {
                                    info!(
                                        "Received packet: {} {} {}",
                                    packet.connection_id(),
                                    packet.tcp_flag_str(),
                                    packet.payload().len()
                                    );
                                }
                            }
                            process_packet(address, packet, s, &inject_handle, &mut ipc_tx, &mut active_listeners, &agent_ephemeral_ports)
                            .await?;
                        }
                        ConnectionState::Unknown(packets) => {
                            unsafe {
                                if packet.dst_port() == APP_PORT {
                                    info!(
                                        "Received packet: {} {} {}",
                                    packet.connection_id(),
                                    packet.tcp_flag_str(),
                                    packet.payload().len()
                                    );
                                }
                            }
                            packets.push((address, packet));
                        }
                    },
                    None => {
                        
                            println!("Captured incoming packet: {} (flags={} size={})", packet.connection_id(), packet.tcp_flag_str(), packet.payload().len());
                            info!(
                                "Received packet: {} {} {}",
                            packet.connection_id(),
                            packet.tcp_flag_str(),
                            packet.payload().len()
                            );
                            // For incoming packets, there won't be a socket event if we capture
                            // before it reaches the socket, so we need to make a decision now.
                            let action: ConnectionAction = {
                                unsafe {
                                    info!("well atleast this worked {} {}", APP_PORT, packet.dst_port());
                                    if packet.dst_port() == APP_PORT {
                                        info!("well atleast this worked");
                                        info!("read this first{} {}", packet.connection_id().src, packet.protocol());
                                        println!("Registering active listener for {} proto={:?}", packet.connection_id().src, packet.protocol());
                                        active_listeners.insert(
                                            packet.connection_id().src,
                                            packet.protocol(),
                                            IncomingTrafficInfo {
                                                is_open_event_sent: false,
                                                written_bytes: 0,
                                                read_bytes: 0,
                                             });
                                       ConnectionAction::InterceptIncoming
                                    } else {
                                        debug!("Unknown inbound packet. Passing through.");
                                        ConnectionAction::None
                                    }
                                }
                            };
                            insert_into_connections(
                                packet.connection_id(),
                                &action,
                                &address.event(),
                                &mut connections,
                                &inject_handle,
                                &mut ipc_tx,
                                &mut active_listeners,
                                &agent_ephemeral_ports,
                            )
                            .await?;
                            process_packet(address, packet, &action, &inject_handle, &mut ipc_tx, &mut active_listeners, &agent_ephemeral_ports)
                            .await?;

                    }
                }
            }
            Event::SocketInfo(address) => {
                if address.process_id() == 4 {
                    // We get some weird operating system events here, which are not useful.
                    debug!("Skipping PID 4");
                    continue;
                }

                let Ok(proto) = TransportProtocol::try_from(address.protocol()) else {
                    warn!("Unknown transport protocol: {}", address.protocol());
                    continue;
                };
                let connection_id: ConnectionId = ConnectionId {
                    proto,
                    src: SocketAddr::from((address.local_address(), address.local_port())),
                    dst: SocketAddr::from((address.remote_address(), address.remote_port())),
                };

                if connection_id.src.ip().is_multicast() || connection_id.dst.ip().is_multicast() {
                    info!("skipping multicast");
                    continue;
                }

                match address.event() {
                    WinDivertEvent::SocketConnect | WinDivertEvent::SocketAccept => {

                        // checks if the conenction is already saved or not
                        let make_entry: bool = match connections.get(&connection_id) {
                            None => true,
                            Some(e) => matches!(e, ConnectionState::Unknown(_)),
                        };

                        info!(
                            "{:<15?} make_entry={} pid={} {}",
                            address.event(),
                            make_entry,
                            address.process_id(),
                            connection_id
                        );

                        unsafe {
                            info!("here it is {} {}", address.remote_port(), APP_PORT);
                            if address.remote_port() == APP_PORT {
                                info!("dest");
                                continue;
                            }
                            if address.local_port() == APP_PORT {
                                info!("client");
                                continue;
                            }
                        };

                        if !make_entry {
                            info!("why will this invoke");
                            continue;
                        }

                        let proc_info = {
                            let pid: u32 = address.process_id();
                            ProcessInfo {
                                pid,
                                process_name: get_process_name(pid)
                                    .map(|x| x.to_string_lossy().into_owned())
                                    .ok(),
                            }
                        };

                        let action: ConnectionAction = if state.should_intercept(&proc_info) {
                            info!("didn't come here");
                            let addr: ipc::Address = ipc::Address {
                                host: address.remote_address().to_string(),
                                port: address.remote_port() as u32,
                                version: if address.ipv6() { "6".to_string() } else { "4".to_string() },
                                src_port: address.local_port() as u32,
                            };

                            let dst_info = ipc::TcpFlow {
                                remote_address: Some(addr), // Initialize with `None` as a placeholder
                            };

                            let _ = ipc_tx.send(ipc::Message {
                                message: Some(ipc::message::Message::Flow(ipc::NewFlow {
                                    message: Some(ipc::new_flow::Message::Tcp(dst_info)),
                                })),
                            });
                            ConnectionAction::InterceptOutgoing(proc_info)
                        } else {
                            ConnectionAction::None
                        };

                        info!("from here {} {}", address.local_port(), address.remote_port());
                        insert_into_connections(
                            connection_id,
                            &action,
                            &address.event(),
                            &mut connections,
                            &inject_handle,
                            &mut ipc_tx,
                            &mut active_listeners,
                            &agent_ephemeral_ports,
                        )
                        .await?;
                    }
                    WinDivertEvent::SocketListen => {
                        let pid = address.process_id();
                        let process_name: Option<String> = get_process_name(pid)
                            .map(|x: std::path::PathBuf| x.to_string_lossy().into_owned())
                            .ok();
                        debug!("Registering {:?} on {}.", process_name, connection_id.src);

                        let proc_info: ProcessInfo = {
                            let pid: u32 = address.process_id();
                            ProcessInfo {
                                pid,
                                process_name: process_name.clone()
                            }
                        };

                        if state.should_intercept(&proc_info) {
                            unsafe {
                                println!("Setting app port to {}", address.local_port());
                                APP_PORT = address.local_port();
                            }
                        }
                    }
                    WinDivertEvent::SocketBind => {
                        // Track ephemeral ports bound by the agent process
                        let pid = address.process_id();
                        if let Some(agent_pid) = state.agent_pid() {
                            if pid == agent_pid {
                                let port = address.local_port();
                                info!("Agent bound ephemeral port {} (pid={})", port, pid);
                                agent_ephemeral_ports.insert(port);
                            }
                        }
                    }
                    WinDivertEvent::SocketClose => {
                        // We cannot clean up here because there are still final packets on connections after this event,
                        // But at least we can release memory for unknown connections.
                        if let Some(ConnectionState::Unknown(packets)) =
                            connections.get_mut(&connection_id)
                        {
                            packets.clear();
                        }

                        // There might be listen sockets we can clean up.
                        // active_listeners.remove(connection_id.src, proto);
                        // If the agent closed a bound ephemeral port, remove it from the map.
                        let closed_port = address.local_port();
                        if agent_ephemeral_ports.remove(&closed_port) {
                            info!("Removed agent ephemeral port {} on close", closed_port);
                        }
                    }
                    _ => {}
                }
            }
            Event::Ipc(conf) => {
                state = conf.try_into()?;
                info!("{}", state.description());

                // Handle preexisting connections.
                connections.clear();
                active_listeners.clear();
            }
        }
    }
}

async fn handle_ipc(
    mut ipc_reader: UnixStream,
    ipc_writer: Arc<std::sync::Mutex<UnixStream>>,
    mut ipc_rx: UnboundedReceiver<ipc::Message>,
    tx: UnboundedSender<Event>,
) -> Result<()> {
    let mut buf = [0u8; IPC_BUF_SIZE];

    loop {
        tokio::select! {
            // Read from IPC in a blocking task
            result = tokio::task::spawn_blocking({
                let mut ipc_reader = ipc_reader.try_clone()?;
                let mut buf = buf.clone();
                move || {
                    ipc_reader.read(&mut buf).map(|len| (len, buf))
                }
            }) => {
                match result {
                    Ok(Ok((len, buf))) if len > 0 => {
                        let mut cursor = Cursor::new(&buf[..len]);
                        let intercept_conf = ipc::InterceptConf::decode(&mut cursor).map_err(|e| {
                            anyhow!("Received invalid IPC message: {:?}, Error: {:?}", &buf[..len], e)
                        })?;
                        assert_eq!(cursor.position(), len as u64);
                        tx.send(Event::Ipc(intercept_conf))?;
                    }
                    _ => {
                        info!("IPC read failed. Exiting.");
                        std::process::exit(0);
                    }
                }
            },
            Some(packet) = ipc_rx.recv() => {
                packet.encode(&mut buf.as_mut_slice())?;
                let len = packet.encoded_len();

                // Write to IPC in a blocking task
                let ipc_writer = ipc_writer.clone();
                let data = buf[..len].to_vec();
                info!("came till here");
                tokio::task::spawn_blocking(move || {
                    let mut ipc_writer = ipc_writer.lock().unwrap();
                    info!("well this did go");
                    ipc_writer.write_all(&data)
                }).await??;
            }
        }
    }
}

/// Repeatedly call WinDivertRecvEx to get socket info and feed them into the channel.
fn relay_socket_events(handle: WinDivert<SocketLayer>, tx: UnboundedSender<Event>) {
    loop {
        let packets = handle.recv_ex(1); // FIXME: more?
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

async fn insert_into_connections(
    connection_id: ConnectionId,
    action: &ConnectionAction,
    event: &WinDivertEvent,
    connections: &mut LruCache<ConnectionId, ConnectionState>,
    inject_handle: &WinDivert<NetworkLayer>,
    ipc_tx: &mut UnboundedSender<ipc::Message>,
    active_listeners: &mut ActiveListeners,
    agent_ephemeral_ports: &HashSet<u16>,
) -> Result<()> {
    debug!("Adding: {} with {:?} ({:?})", &connection_id, action, event);
    // no matter which action we do, the reverse direction is whitelisted.

    let mut new_connection_id = connection_id.reverse();
    match action { 
        ConnectionAction::InterceptOutgoing(ProcessInfo { pid, process_name }) => {
            if connection_id.src.is_ipv6() {
                info!("may be due to this");
                new_connection_id.src.set_ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
                new_connection_id.dst.set_ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
            } else {
                new_connection_id.src.set_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
                new_connection_id.dst.set_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
            }
            new_connection_id.src.set_port(16789);
        }
        ConnectionAction::InterceptIncoming => {
            // Redirect incoming connections to port 3000 on localhost
            if connection_id.src.is_ipv6() {
                new_connection_id.src.set_ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
                new_connection_id.dst.set_ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
            } else {
                new_connection_id.src.set_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
                new_connection_id.dst.set_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
            }
            new_connection_id.src.set_port(3000);
            info!("Setting up reverse connection for incoming intercept to port 3000");
        }
        ConnectionAction::None => {
            info!("expected");
        }
    }

    let existing1: Option<ConnectionState> = connections.insert(
        new_connection_id,
        ConnectionState::Known(action.clone()),
    );
    let existing2: Option<ConnectionState> = connections.insert(connection_id, ConnectionState::Known(action.clone()));

    if let Some(ConnectionState::Unknown(packets)) = existing1 {
        for (a, p) in packets {
            process_packet(a, p, action, inject_handle, ipc_tx, active_listeners, agent_ephemeral_ports).await?;
        }
    }
    if let Some(ConnectionState::Unknown(packets)) = existing2 {
        for (a, p) in packets {
            process_packet(a, p, action, inject_handle, ipc_tx, active_listeners, agent_ephemeral_ports).await?;
        }
    }
    Ok(())
}

async fn process_packet(
    address: WinDivertAddress<NetworkLayer>,
    mut packet: InternetPacket,
    action: &ConnectionAction,
    inject_handle: &WinDivert<NetworkLayer>,
    ipc_tx: &mut UnboundedSender<ipc::Message>,
    active_listeners: &mut ActiveListeners,
    agent_ephemeral_ports: &HashSet<u16>,
) -> Result<()> {
    match action {
        ConnectionAction::InterceptIncoming => {
            unsafe {
                println!("Handling InterceptIncoming for {} (dst_port={})", packet.connection_id(), packet.dst_port());
                
                info!(
                    "Intercepting incoming: {} {} protocol={} outbound={} loopback={}",
                    packet.connection_id(),
                    packet.tcp_flag_str(),
                    packet.protocol(),
                    address.outbound(),
                    address.loopback()
                );

                // If this packet is destined to the app port but its source port
                // is one of the agent's ephemeral ports, do not intercept it here.
                if packet.dst_port() == APP_PORT && agent_ephemeral_ports.contains(&packet.src_port()) {
                    debug!("Skipping intercept for packet from agent ephemeral port {}", packet.src_port());
                    inject_handle
                        .send(&WinDivertPacket::<NetworkLayer> {
                            address,
                            data: packet.inner().into(),
                        })
                        .context("failed to re-inject packet")?;
                    return Ok(());
                }

                if packet.dst_port() == APP_PORT {
                    // Store original packet info for reverse direction
                    let src_port = packet.src_port();
                    let packet_info = PacketInfo {
                        src_ip: packet.src_ip(),
                        dst_ip: packet.dst_ip(),
                        dst_port: packet.dst_port(),
                    };
                    
                    if let Some(ref packet_map) = PACKET_MAP {
                        let mut map = packet_map.lock().unwrap();
                        map.insert(src_port, packet_info);
                    }

                    // Redirect to port 3000 on localhost
                    match packet.src_ip() {
                        IpAddr::V4(_) => {
                            let ipv4_addr = Ipv4Addr::new(127, 0, 0, 1);
                            packet.set_dst_ip(IpAddr::V4(ipv4_addr));
                            packet.set_src_ip(IpAddr::V4(ipv4_addr));
                        }
                        IpAddr::V6(_) => {
                            let ipv6_addr = Ipv6Addr::LOCALHOST;
                            packet.set_dst_ip(IpAddr::V6(ipv6_addr));
                            packet.set_src_ip(IpAddr::V6(ipv6_addr));
                        }
                    }
                    packet.set_dst_port(3000);
                    packet.recalculate_tcp_checksum();

                    info!(
                        "Redirected incoming to port 3000: {} {} interface={} sub={}",
                        packet.connection_id(),
                        packet.tcp_flag_str(),
                        address.interface_index(),
                        address.subinterface_index()
                    );

                    let buff = packet.clone().inner();
                    let Ok(mut packet1) = SmolPacket::try_from(buff) else {
                        info!("Error converting to SmolPacket");
                        return Err(anyhow::anyhow!("Failed to convert to SmolPacket"));
                    };

                    packet1.fill_ip_checksum();
                    let buff1 = packet1.into_inner();

                    let packet2 = match InternetPacket::try_from(buff1) {
                        Ok(p) => p,
                        Err(e) => {
                            info!("Error parsing packet: {:?}", e);
                            return Err(anyhow::anyhow!("Failed to parse InternetPacket: {:?}", e));
                        }
                    };

                    let winpacket = WinDivertPacket::<NetworkLayer> {
                        address,
                        data: packet2.inner().into(),
                    };

                    if let Err(e) = inject_handle.send(&winpacket) {
                        eprintln!("Failed to send packet: {:?}", e);
                    } else {
                        println!("Packet sent successfully to port 3000!");
                    }
                } else if packet.src_port() == 3000 {
                    // Restore original addresses for response packets from port 3000
                    let dst_port = packet.dst_port();
                    let packet_info = if let Some(ref packet_map) = PACKET_MAP {
                        let map = packet_map.lock().unwrap();
                        if let Some(packet_info) = map.get(&dst_port) {
                            packet_info.clone()
                        } else {
                            return Err(anyhow::anyhow!("Failed to get packet info for port: {}", dst_port));
                        }
                    } else {
                        return Err(anyhow::anyhow!("Packet map not initialized."));
                    };

                    packet.set_src_ip(packet_info.dst_ip);
                    packet.set_dst_ip(packet_info.src_ip);
                    packet.set_src_port(packet_info.dst_port);
                    packet.recalculate_tcp_checksum();

                    info!(
                        "Restored response from port 3000: {} {} interface={} sub={}",
                        packet.connection_id(),
                        packet.tcp_flag_str(),
                        address.interface_index(),
                        address.subinterface_index()
                    );

                    let buff = packet.clone().inner();
                    let Ok(mut packet1) = SmolPacket::try_from(buff) else {
                        info!("Error converting to SmolPacket");
                        return Err(anyhow::anyhow!("Failed to convert to SmolPacket"));
                    };

                    packet1.fill_ip_checksum();
                    let buff1 = packet1.into_inner();

                    let packet2 = match InternetPacket::try_from(buff1) {
                        Ok(p) => p,
                        Err(e) => {
                            info!("Error parsing packet: {:?}", e);
                            return Err(anyhow::anyhow!("Failed to parse InternetPacket: {:?}", e));
                        }
                    };

                    let winpacket = WinDivertPacket::<NetworkLayer> {
                        address,
                        data: packet2.inner().into(),
                    };

                    if let Err(e) = inject_handle.send(&winpacket) {
                        eprintln!("Failed to send packet: {:?}", e);
                    } else {
                        println!("Response packet sent successfully!");
                    }
                } else {
                    // Forward other packets unchanged
                    debug!(
                        "Forwarding unchanged: {} {} outbound={} loopback={}",
                        packet.connection_id(),
                        packet.tcp_flag_str(),
                        address.outbound(),
                        address.loopback()
                    );
                    inject_handle
                        .send(&WinDivertPacket::<NetworkLayer> {
                            address,
                            data: packet.inner().into(),
                        })
                        .context("failed to re-inject packet")?;
                }
            }
        }
        ConnectionAction::None => {
            debug!(
                "Forwarding: {} {} outbound={} loopback={}",
                packet.connection_id(),
                packet.tcp_flag_str(),
                address.outbound(),
                address.loopback()
            );
            inject_handle
                .send(&WinDivertPacket::<NetworkLayer> {
                    address,
                    data: packet.inner().into(),
                })
                .context("failed to re-inject packet")?;
        }
        ConnectionAction::InterceptOutgoing(ProcessInfo { pid, process_name }) => {
            
            info!(
                "Intercepting: {} {} protocol={} outbound={} loopback={}",
                packet.connection_id(),
                packet.tcp_flag_str(),
                packet.protocol(),
                address.outbound(),
                address.loopback()
            );

            if packet.src_port() != 16789 {

                let src_port = packet.src_port();
                let packet_info: PacketInfo = PacketInfo {
                    src_ip: packet.src_ip(),
                    dst_ip: packet.dst_ip(),
                    dst_port: packet.dst_port(),
                };
                unsafe {
                    if let Some(ref packet_map) = PACKET_MAP {
                        let mut map = packet_map.lock().unwrap();
                        map.insert(src_port, packet_info);
                    }
                }


                match packet.src_ip() {
                    IpAddr::V4(_) => {
                        // Handle IPv4 packet
                        let ipv4_addr = Ipv4Addr::new(127, 0, 0, 1);
                        packet.set_dst_ip(IpAddr::V4(ipv4_addr));
                        packet.set_src_ip(IpAddr::V4(ipv4_addr));
                    }
                    IpAddr::V6(_) => {
                        // Handle IPv6 packet
                        let ipv6_addr = Ipv6Addr::LOCALHOST;
                        packet.set_dst_ip(IpAddr::V6(ipv6_addr));
                        packet.set_src_ip(IpAddr::V6(ipv6_addr));
                    }
                }
                packet.set_dst_port(16789);
                packet.recalculate_tcp_checksum();

                info!(
                    "Intercepting: {} {} protocol={} outbound={} loopback={} interface={} sub={}",
                    packet.connection_id(),
                    packet.tcp_flag_str(),
                    packet.protocol(),
                    address.outbound(),
                    address.loopback(),
                    address.interface_index(),
                    address.subinterface_index()
                );

                let buff = packet.clone().inner();
                let Ok(mut packet1) = SmolPacket::try_from(buff) else {
                    info!("Error converting to SmolPacket");
                    return Err(anyhow::anyhow!("Failed to convert to SmolPacket"));
                };

                packet1.fill_ip_checksum();

                let buff1 = packet1.into_inner();

                let packet2 = match InternetPacket::try_from(buff1) {
                    Ok(p) => p,
                    Err(e) => {
                        info!("Error parsing packet: {:?}", e);
                        return Err(anyhow::anyhow!("Failed to parse InternetPacket: {:?}", e));
                    }
                };

                let winpacket = WinDivertPacket::<NetworkLayer> {
                    address,
                    data: packet2.inner().into(),
                };

                if let Err(e) = inject_handle.send(&winpacket) {
                    eprintln!("Failed to send packet: {:?}", e);
                } else {
                    println!("Packet sent successfully!");
                }
            } else {
                let src_port = packet.dst_port();
                let packet_info: PacketInfo  = unsafe {
                    if let Some(ref packet_map) = PACKET_MAP {
                        let map = packet_map.lock().unwrap();
                        if let Some(packet_info) = map.get(&src_port) {
                            packet_info.clone()
                        } else {
                            return Err(anyhow::anyhow!("Failed to get info : {}", src_port));
                        }
                    } else {
                        return Err(anyhow::anyhow!("Packet map not initialized."));
                    }
                };

                packet.set_dst_ip(packet_info.src_ip);
                packet.set_src_ip(packet_info.dst_ip);
                packet.set_src_port(packet_info.dst_port);

                packet.recalculate_tcp_checksum();

                info!(
                    "Intercepting: {} {} protocol={} outbound={} loopback={} interface={} sub={}",
                    packet.connection_id(),
                    packet.tcp_flag_str(),
                    packet.protocol(),
                    address.outbound(),
                    address.loopback(),
                    address.interface_index(),
                    address.subinterface_index()
                );

                let mut buff = packet.clone().inner();
                
                // match packet.src_ip() {
                //     IpAddr::V4(_) => {
                //         let mut packet1;
                //         packet1 = Ipv4Packet::new_unchecked(&mut buff)
                //         packet1.fill_checksum();
                //         if packet1.verify_checksum() {
                //             println!("IPv4 checksum is valid.");
                //         } else {
                //             println!("IPv4 checksum is invalid.");
                //         }
                //     }
                //     IpAddr::V6(_) => {
                //         packet1 = Ipv6Packet::new_unchecked(&mut buff)
                //     }
                // }
              

                let Ok(mut packet1) = SmolPacket::try_from(buff) else {
                    info!("Error converting to SmolPacket");
                    return Err(anyhow::anyhow!("Failed to convert to SmolPacket"));
                };

                packet1.fill_ip_checksum();

                let buff1 = packet1.into_inner().clone();

                let packet2 = match InternetPacket::try_from(buff1) {
                    Ok(p) => p,
                    Err(e) => {
                        info!("Error parsing packet: {:?}", e);
                        return Err(anyhow::anyhow!("Failed to parse InternetPacket: {:?}", e));
                    }
                };

                let winpacket = WinDivertPacket::<NetworkLayer> {
                    address,
                    data: packet2.inner().into(),
                };

                if let Err(e) = inject_handle.send(&winpacket) {
                    eprintln!("Failed to send packet: {:?}", e);
                } else {
                    println!("Packet sent successfully!");
                }
            }
        }
    }
    Ok(())
}

fn extract_tcp_payload(packet: &InternetPacket, buff: &mut [u8]) -> Result<Option<Vec<u8>>> {
    let tcp_payload;

    match packet.src_ip() {
        IpAddr::V4(_) => {
            print!("came here in v4");
            // Handle IPv4 packets
            let mut ipv4_packet = Ipv4Packet::new_unchecked(buff);
            if ipv4_packet.next_header() == IpProtocol::Tcp {
                let payload = ipv4_packet.payload_mut();
                if let Ok(mut tcp_packet) = TcpPacket::new_checked(payload) {
                    tcp_payload = Some(tcp_packet.payload_mut().to_vec());
                } else {
                    return Ok(None);  // No valid TCP packet found in IPv4
                }
            } else {
                return Ok(None);  // Not a TCP packet
            }
        }
        IpAddr::V6(_) => {
            print!("came here in v6");
            // Handle IPv6 packets
            let mut ipv6_packet: Ipv6Packet<&mut [u8]> = Ipv6Packet::new_unchecked(buff);
            if ipv6_packet.next_header() == IpProtocol::Tcp {
                let payload = ipv6_packet.payload_mut();
                if let Ok(mut tcp_packet) = TcpPacket::new_checked(payload) {
                    tcp_payload = Some(tcp_packet.payload_mut().to_vec());
                } else {
                    return Ok(None);  // No valid TCP packet found in IPv6
                }
            } else {
                return Ok(None);  // Not a TCP packet
            }
        }
    }

    Ok(tcp_payload)
}