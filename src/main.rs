use std::ffi::CStr;

use wireguard::wg_list_device_names;

mod wireguard;

pub fn main() {
    let device_names = unsafe { wg_list_device_names() };
    if device_names.is_null() {
        println!("No devices found.");
        return;
    }
    let device_names = unsafe { CStr::from_ptr(device_names) };
    let device_names = device_names.to_str().expect("CStr to_str failed");
    let device_names: Vec<&str> = device_names
        .split('\0')
        .filter(|&name| !name.is_empty()) // 过滤空字符串
        .collect();
    for name in device_names {
        println!("Device name: {}", name);
    }
}
