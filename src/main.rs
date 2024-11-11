use std::path::PathBuf;
use windows::{
    core::{GUID, PCSTR},
    Win32::{
        Devices::DeviceAndDriverInstallation::{
            SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsA,
            SetupDiGetDeviceRegistryPropertyA, DIGCF_PRESENT, SPDRP_SERVICE, SP_DEVINFO_DATA,
        },
        Foundation::{ERROR_SUCCESS, INVALID_HANDLE_VALUE},
        System::Registry::{
            RegCloseKey, RegOpenKeyExA, RegQueryValueExA, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
            KEY_WOW64_64KEY, REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE,
        },
        UI::Shell::{SHGetFolderPathA, CSIDL_SYSTEM, SHGFP_TYPE_CURRENT},
    },
};

fn get_system_dir() -> Option<PathBuf> {
    let mut sys_dir = [0u8; 260];
    unsafe {
        if SHGetFolderPathA(
            None,
            37, // CSIDL_SYSTEM = 37 (0x25)
            None,
            SHGFP_TYPE_CURRENT.0 as u32,
            &mut sys_dir,
        )
        .is_ok()
        {
            let path = std::str::from_utf8(&sys_dir)
                .ok()?
                .trim_matches(char::from(0));
            Some(PathBuf::from(path))
        } else {
            None
        }
    }
}

#[derive(Debug)]
struct GpuInfo {
    vendor: String,
    name: String,
    driver_path: String,
}

fn identify_gpu_vendor(driver_filename: &str) -> Option<String> {
    if driver_filename.to_lowercase().contains("amdkmdag") {
        Some("AMD".to_string())
    } else if driver_filename.to_lowercase().contains("nvlddmkm") {
        Some("NVIDIA".to_string())
    } else if driver_filename.to_lowercase().contains("igdkmd") {
        Some("Intel".to_string())
    } else {
        None
    }
}

fn get_gpu_name(driver_path: &str) -> String {
    PathBuf::from(driver_path)
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.trim_end_matches(".sys").to_string())
        .unwrap_or_else(|| "Unknown".to_string())
}

fn main() {
    let display_guid = GUID::from_values(
        0x4d36e968,
        0xe325,
        0x11ce,
        [0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18],
    );

    let device_info =
        unsafe { SetupDiGetClassDevsA(Some(&display_guid), PCSTR::null(), None, DIGCF_PRESENT) }
            .unwrap();

    if device_info.0 == INVALID_HANDLE_VALUE.0 {
        println!("Error: Failed to get device info");
        return;
    }

    let mut service_names = Vec::new();
    let mut device_index = 0;

    loop {
        let mut device_data = SP_DEVINFO_DATA {
            cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
            ..Default::default()
        };

        if unsafe { !SetupDiEnumDeviceInfo(device_info, device_index, &mut device_data).as_bool() }
        {
            break;
        }

        let mut buffer_size = 0u32;
        unsafe {
            SetupDiGetDeviceRegistryPropertyA(
                device_info,
                &device_data,
                SPDRP_SERVICE,
                None,
                None,
                Some(&mut buffer_size),
            );
        }

        if buffer_size > 0 {
            let mut buffer = vec![0u8; buffer_size as usize];
            let success = unsafe {
                SetupDiGetDeviceRegistryPropertyA(
                    device_info,
                    &device_data,
                    SPDRP_SERVICE,
                    None,
                    Some(buffer.as_mut_slice()),
                    Some(&mut buffer_size),
                )
            };

            if success.as_bool() {
                if let Ok(service_name) = String::from_utf8(buffer) {
                    service_names.push(service_name.trim_matches(char::from(0)).to_string());
                }
            }
        }

        device_index += 1;
    }

    unsafe { SetupDiDestroyDeviceInfoList(device_info) };

    if service_names.is_empty() {
        println!("Error: No display adapter found");
        return;
    }

    let services_key = "SYSTEM\\CurrentControlSet\\services\0";
    let mut driver_paths = Vec::new();

    for service_name in service_names {
        let reg_key_path = format!(
            "{}\\{}\0",
            services_key.trim_matches(char::from(0)),
            service_name
        );
        let mut reg_key = HKEY::default();

        let status = unsafe {
            RegOpenKeyExA(
                HKEY_LOCAL_MACHINE,
                PCSTR::from_raw(reg_key_path.as_ptr()),
                0,
                KEY_READ | KEY_WOW64_64KEY,
                &mut reg_key,
            )
        };

        if status != ERROR_SUCCESS {
            continue;
        }

        let mut value_type = REG_VALUE_TYPE::default();
        let mut value_size = 0u32;
        let image_path_key = "ImagePath\0";

        let status = unsafe {
            RegQueryValueExA(
                reg_key,
                PCSTR::from_raw(image_path_key.as_ptr()),
                None,
                Some(&mut value_type as *mut _),
                None,
                Some(&mut value_size),
            )
        };

        if status == ERROR_SUCCESS {
            let mut buffer = vec![0u8; value_size as usize];
            let status = unsafe {
                RegQueryValueExA(
                    reg_key,
                    PCSTR::from_raw(image_path_key.as_ptr()),
                    None,
                    Some(&mut value_type as *mut _),
                    Some(buffer.as_mut_ptr()),
                    Some(&mut value_size),
                )
            };

            if status == ERROR_SUCCESS
                && (value_type == REG_VALUE_TYPE(REG_SZ.0)
                    || value_type == REG_VALUE_TYPE(REG_EXPAND_SZ.0))
            {
                if let Ok(path) = String::from_utf8(buffer) {
                    driver_paths.push(path.trim_matches(char::from(0)).to_string());
                }
            }
        }

        unsafe { RegCloseKey(reg_key) };
    }

    if driver_paths.is_empty() {
        println!("Error: No GPU driver found");
        return;
    }

    let mut drivers_dir = match get_system_dir() {
        Some(path) => path,
        None => {
            println!("Error: Failed to get system directory");
            return;
        }
    };
    drivers_dir.push("drivers");

    let mut gpu_infos = Vec::new();

    for driver_path in driver_paths {
        if let Some(file_name) = PathBuf::from(&driver_path).file_name() {
            let file_name_str = file_name.to_string_lossy().to_string();
            if let Some(vendor) = identify_gpu_vendor(&file_name_str) {
                let mut full_path = drivers_dir.clone();
                full_path.push(&file_name);

                let gpu_info = GpuInfo {
                    vendor,
                    name: get_gpu_name(&file_name_str),
                    driver_path: full_path.display().to_string(),
                };
                gpu_infos.push(gpu_info);
            }
        }
    }

    if gpu_infos.is_empty() {
        println!("No recognized GPU found");
    } else {
        println!("\nGPU Information Summary:");
        println!("------------------------");
        for (index, gpu) in gpu_infos.iter().enumerate() {
            println!("GPU #{}", index + 1);
            println!("Vendor: {}", gpu.vendor);
            println!("Driver: {}", gpu.name);
            println!("Driver Path: {}", gpu.driver_path);
            println!("------------------------");
        }
    }
}
