use libc::{c_char, c_int, c_uchar, c_uint, c_ulong, c_ushort, sockaddr_in, sockaddr_in6};
use std::ffi::CStr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr;

pub type WgKey = [u8; 32];
pub type WgKeyB64String = [u8; ((32 + 2) / 3) * 4 + 1]; // Base64 encoding for wg_key

// Cross-platform __kernel_timespec
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Timespec64 {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct WgAllowedIp {
    pub family: c_uint,
    pub ip4: sockaddr_in,
    pub ip6: sockaddr_in6,
    pub cidr: u8,
    pub next_allowedip: *mut WgAllowedIp,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct WgEndpoint {
    pub addr: sockaddr_in,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct WgPeer {
    pub flags: c_uint,
    pub public_key: WgKey,
    pub preshared_key: WgKey,
    pub endpoint: WgEndpoint,
    pub last_handshake_time: Timespec64,
    pub rx_bytes: c_ulong,
    pub tx_bytes: c_ulong,
    pub persistent_keepalive_interval: c_ushort,
    pub first_allowedip: *mut WgAllowedIp,
    pub last_allowedip: *mut WgAllowedIp,
    pub next_peer: *mut WgPeer,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct WgDevice {
    pub name: [c_uchar; 16], // IFNAMSIZ
    pub ifindex: c_uint,
    pub flags: c_uint,
    pub public_key: WgKey,
    pub private_key: WgKey,
    pub fwmark: c_uint,
    pub listen_port: c_ushort,
    pub first_peer: *mut WgPeer,
    pub last_peer: *mut WgPeer,
}

// Flags for WgPeer
pub const WGPEER_REMOVE_ME: c_uint = 1 << 0;
pub const WGPEER_REPLACE_ALLOWEDIPS: c_uint = 1 << 1;
pub const WGPEER_HAS_PUBLIC_KEY: c_uint = 1 << 2;
pub const WGPEER_HAS_PRESHARED_KEY: c_uint = 1 << 3;
pub const WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL: c_uint = 1 << 4;

// Flags for WgDevice
pub const WGDEVICE_REPLACE_PEERS: c_uint = 1 << 0;
pub const WGDEVICE_HAS_PRIVATE_KEY: c_uint = 1 << 1;
pub const WGDEVICE_HAS_PUBLIC_KEY: c_uint = 1 << 2;
pub const WGDEVICE_HAS_LISTEN_PORT: c_uint = 1 << 3;
pub const WGDEVICE_HAS_FWMARK: c_uint = 1 << 4;

// Functions that need to be linked with C code
extern "C" {
    pub fn wg_set_device(dev: *mut WgDevice) -> c_int;
    pub fn wg_get_device(dev: *mut *mut WgDevice, device_name: *const c_char) -> c_int;
    pub fn wg_add_device(device_name: *const c_char) -> c_int;
    pub fn wg_del_device(device_name: *const c_char) -> c_int;
    pub fn wg_free_device(dev: *mut WgDevice);
    pub fn wg_list_device_names() -> *mut c_char; // Returns a null-terminated string
    pub fn wg_key_to_base64(base64: *mut WgKeyB64String, key: *const WgKey);
    pub fn wg_key_from_base64(key: *mut WgKey, base64: *const WgKeyB64String) -> c_int;
    pub fn wg_key_is_zero(key: *const WgKey) -> bool;
    pub fn wg_generate_public_key(public_key: *mut WgKey, private_key: *const WgKey);
    pub fn wg_generate_private_key(private_key: *mut WgKey);
    pub fn wg_generate_preshared_key(preshared_key: *mut WgKey);
}

// For convenience, we define a macro for iterating over devices, peers, and allowed IPs.
#[macro_export]
macro_rules! wg_for_each_device_name {
    ($names: expr, $name: expr, $len: expr) => {
        let mut names = $names;
        let mut len: usize;
        while {
            len = names.len();
            len > 0
        } {
            $name = names;
            names = &names[len + 1..];
        }
    };
}

#[macro_export]
macro_rules! wg_for_each_peer {
    ($dev: expr, $peer: expr) => {
        let mut peer = $dev.first_peer;
        while !peer.is_null() {
            $peer = unsafe { &*peer };
            peer = peer.next_peer;
        }
    };
}

#[macro_export]
macro_rules! wg_for_each_allowedip {
    ($peer: expr, $allowedip: expr) => {
        let mut allowedip = $peer.first_allowedip;
        while !allowedip.is_null() {
            $allowedip = unsafe { &*allowedip };
            allowedip = allowedip.next_allowedip;
        }
    };
}
