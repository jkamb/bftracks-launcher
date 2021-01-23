use super::config;
use anyhow::{anyhow, Result};
use std::ffi::OsStr;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::slice;

mod native {
    use winapi::shared::minwindef::DWORD;
    use winapi::shared::ntdef::{HANDLE, LONG, NTSTATUS, PULONG, PVOID, ULONG};
    pub type FnNtQueryInformationProcess = unsafe extern "C" fn(
        ProcessHandle: HANDLE,
        ProcessInformationClass: DWORD,
        ProcessInformation: PVOID,
        ProcessInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;

    #[repr(C)]
    #[allow(non_snake_case)]
    pub struct PROCESS_BASIC_INFORMATION {
        pub ExitStatus: LONG,
        pub PebBaseAddress: PVOID, // Should be a PPEB but any pointer to get the correct size should work for now
        pub AffinityMask: PULONG,
        pub BasePriority: LONG,
        pub UniqueProcessId: PULONG,
        pub InheritedFromUniqueProcessId: PULONG,
    }
}

/*
[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\bftracks]
@="BFTracks Launcher"
"URL Protocol"=""

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\bftracks\shell]

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\bftracks\shell\open]

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\bftracks\shell\open\command]
@="\"D:\git\bftracks-launcher\target\release\bftracks-launcher.exe\"" \"%1\""
*/
fn setup_registry(launcher_path: &Path) -> Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let launcher_dir = launcher_path.parent().unwrap().to_str().unwrap();
    if let Some(launcher_path) = launcher_path.to_str() {
        // Setup custom scheme
        let (key, disp) =
            hklm.create_subkey("SOFTWARE\\Classes\\bftracks\\shell\\open\\command")?;
        match disp {
            REG_CREATED_NEW_KEY => {
                println!("A new key has been created, checking & fixing up parent");
                let (key, _) = hklm.create_subkey("SOFTWARE\\Classes\\bftracks")?;
                key.set_value("", &"BFTracks launcher")?;
                key.set_value("URL Protocol", &"")?;
            }
            REG_OPENED_EXISTING_KEY => println!("An existing key has been opened"),
        }
        key.set_value("", &format!("{} \"%1\"", launcher_path))?;

        /*
            Windows Registry Editor Version 5.00
            [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\BFTracks]
            "UninstallString"="C:\\Users\\jkamb\\AppData\\Local\\BFTracks\\bftracks-launcher.exe"
            "DisplayName"="BFTracks launcher"
            "URLInfoAbout"="http://bftracks.net"
            "NoModify"=dword:00000001
            "NoRepair"=dword:00000001
            "DisplayIcon"="C:\\Users\\jkamb\\AppData\\Local\\BFTracks\\bftracks-launcher.exe"
            "InstallLocation"="C:\\Users\\jkamb\\AppData\\Local\\BFTracks"
        */
        // Setup uninstall key
        let (key, _) = hklm
            .create_subkey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\BFTracks")?;
        key.set_value("UninstallString", &format!("{} uninstall", launcher_path))?;
        key.set_value("DisplayIcon", &launcher_path)?;
        key.set_value("DisplayName", &"BFTracks launcher")?;
        key.set_value("URLInfoAbout", &"http://bftracks.net")?;
        key.set_value("InstallLocation", &launcher_dir)?;
        key.set_value("NoModify", &1u32)?;
        key.set_value("NoRepair", &1u32)?;
        return Ok(());
    }
    Err(anyhow!("Failed to setup registry"))
}

fn get_app_data_directory() -> Result<PathBuf> {
    use std::os::windows::prelude::OsStringExt;
    use std::ptr;
    use winapi::shared::winerror;
    use winapi::um::combaseapi::CoTaskMemFree;
    use winapi::um::knownfolders::FOLDERID_LocalAppData;
    use winapi::um::shlobj::SHGetKnownFolderPath;
    use winapi::um::winbase::lstrlenW;
    use winapi::um::winnt::PWSTR;

    unsafe {
        let mut path_ptr: PWSTR = ptr::null_mut();
        let result =
            SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, ptr::null_mut(), &mut path_ptr);
        if result == winerror::S_OK {
            let len = lstrlenW(path_ptr) as usize;
            let path = slice::from_raw_parts(path_ptr, len);
            let ostr: OsString = OsStringExt::from_wide(path);
            CoTaskMemFree(path_ptr as *mut winapi::ctypes::c_void);
            Ok(PathBuf::from(ostr).join("BFTracks"))
        } else {
            Err(anyhow!("Failed to get app data directory"))
        }
    }
}

fn get_bf1942_path() -> Result<PathBuf> {
    /*
    Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Origin\Battlefield 1942
    */
    use wfd::{
        DialogError, DialogParams, FOS_DONTADDTORECENT, FOS_FILEMUSTEXIST, FOS_HIDEMRUPLACES,
        FOS_HIDEPINNEDPLACES,
    };
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    // Try to find Origin installation as a base for user to select the game exe, otherwise default to a known path
    let install_dir: String =
        match hklm.open_subkey("SOFTWARE\\WOW6432Node\\Origin\\Battlefield 1942") {
            Ok(key) => {
                if let Ok(dir) = key.get_value("InstallDir") {
                    dir
                } else {
                    "C:\\".to_string()
                }
            }
            Err(_) => "C:\\".to_string(),
        };

    let params = DialogParams {
        file_types: vec![("Executable Files", "BF1942.exe")],
        default_extension: "exe",
        default_folder: &install_dir,
        file_name: "BF1942.exe",
        ok_button_label: "Select",
        options: FOS_FILEMUSTEXIST | FOS_HIDEMRUPLACES | FOS_HIDEPINNEDPLACES | FOS_DONTADDTORECENT,
        title: "BFTracks launcher",
        ..Default::default()
    };

    match wfd::open_dialog(params) {
        Ok(r) => Ok(r.selected_file_path),
        Err(e) => match e {
            DialogError::UserCancelled => Err(anyhow!("Cancelled")),
            DialogError::HResultFailed {
                hresult,
                error_method,
            } => Err(anyhow!(
                "HResult Failed - HRESULT: {:X}, Method: {}",
                hresult,
                error_method
            )),
        },
    }
}

fn write_config(app_dir: &Path, executable: &Path) -> Result<()> {
    use config::Config;
    use std::fs;
    use std::io::Write;

    let cfg = Config {
        game_path: executable.to_string_lossy().to_string(),
    };
    let toml = toml::to_string(&cfg)?;
    let config_path = app_dir.join("config.toml");
    let mut config_file = fs::File::create(config_path)?;
    config_file.write_all(toml.as_bytes())?;
    Ok(())
}

fn copy_self(current_exe: &Path, app_dir: &Path) -> Result<()> {
    use std::fs;

    if !app_dir.exists() {
        fs::create_dir(app_dir)?;
    }
    let copy_location = app_dir.join(current_exe.file_name().unwrap());
    fs::copy(current_exe, copy_location)?;
    Ok(())
}

fn cleanup_registry() -> Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let _ = hklm.delete_subkey_all("SOFTWARE\\Classes\\bftracks");
    let _ =
        hklm.delete_subkey_all("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\BFTracks");
    Ok(())
}

pub fn self_delete() -> Result<()> {
    use native::{FnNtQueryInformationProcess, PROCESS_BASIC_INFORMATION};
    use std::fs;
    use std::mem;
    use std::os::windows::ffi::OsStrExt;
    use std::process::{Command, Stdio};
    use winapi::shared::minwindef::DWORD;
    use winapi::shared::ntdef::{PVOID, ULONG};
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::libloaderapi;
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcess};
    use winapi::um::synchapi::WaitForSingleObject;
    use winapi::um::winbase::{INFINITE, WAIT_OBJECT_0};
    use winapi::um::winnt::LPCSTR;
    use winapi::um::winnt::SYNCHRONIZE;

    unsafe {
        let own_handle = GetCurrentProcess();
        let mut process_basic_info: PROCESS_BASIC_INFORMATION = mem::zeroed();
        let process_basic_info_length = mem::size_of::<PROCESS_BASIC_INFORMATION>() as ULONG;
        let mut return_length: ULONG = 0;
        // Import NtQueryInformationProcess
        let filename: Vec<u16> = OsStr::new("ntdll").encode_wide().chain(Some(0)).collect();
        let handle = libloaderapi::LoadLibraryW(filename.as_ptr());
        if handle.is_null() {
            return Err(anyhow!("Failed to import ntdll"));
        }
        let fn_address =
            libloaderapi::GetProcAddress(handle, "NtQueryInformationProcess\0".as_ptr() as LPCSTR);
        #[allow(non_snake_case)]
        let NtQueryInformationProcess: FnNtQueryInformationProcess = mem::transmute(fn_address);

        let status = NtQueryInformationProcess(
            own_handle,
            0,
            &mut process_basic_info as *mut _ as PVOID,
            process_basic_info_length,
            &mut return_length,
        );
        if status >= 0 {
            let parent = OpenProcess(
                SYNCHRONIZE,
                0,
                process_basic_info.InheritedFromUniqueProcessId as DWORD,
            );
            if !parent.is_null() {
                let parent = scopeguard::guard(parent, |h| {
                    let _ = CloseHandle(h);
                });

                let res = WaitForSingleObject(*parent, INFINITE);
                if res != WAIT_OBJECT_0 {
                    return Err(anyhow!("Error waiting for parent to close"));
                }

                let app_dir = get_app_data_directory()?;
                fs::remove_dir_all(app_dir)?;

                // Have to exit quickly after this so the current exe is not mapped when net exits
                Command::new("net")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()?;
            } else {
                return Err(anyhow!("Failed to open parent process"));
            }
        }
    }
    Ok(())
}

fn delete_exe_and_app_dir(current_exe: &Path) -> Result<()> {
    use std::fs;
    use std::mem;
    use std::os::windows::ffi::OsStrExt;
    use std::process::Command;
    use std::ptr;
    use std::thread;
    use std::time::Duration;
    use winapi::shared::minwindef::DWORD;
    use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
    use winapi::um::winbase::FILE_FLAG_DELETE_ON_CLOSE;
    use winapi::um::winnt::{FILE_SHARE_DELETE, FILE_SHARE_READ, GENERIC_READ};

    // This is inspired by rustup's way of self-deleting
    let work_path = current_exe
        .parent()
        .unwrap()
        .parent()
        .ok_or_else(|| anyhow!("No parent found for app directory"))?;

    let self_delete_exe = work_path.join(&format!(
        "{}-self-delete.exe",
        current_exe.file_stem().unwrap().to_str().unwrap()
    ));
    let self_delete_exe_raw: Vec<u16> = self_delete_exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    fs::copy(&current_exe, &self_delete_exe)?;

    let mut security_attribute = SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as DWORD,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };

    let _guard = unsafe {
        let handle = CreateFileW(
            self_delete_exe_raw.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            &mut security_attribute,
            OPEN_EXISTING,
            FILE_FLAG_DELETE_ON_CLOSE,
            ptr::null_mut(),
        );

        if handle == INVALID_HANDLE_VALUE {
            return Err(anyhow!("Failed to get handle to current file"));
        }

        scopeguard::guard(handle, |h| {
            let _ = CloseHandle(h);
        })
    };

    Command::new(self_delete_exe).spawn()?;

    // Sleep for the new process to get created
    thread::sleep(Duration::from_millis(200));
    Ok(())
}

pub fn uninstall(current_exe: &Path) -> Result<()> {
    // Remove registry entries
    cleanup_registry()?;
    delete_exe_and_app_dir(current_exe)?;
    Ok(())
}

pub fn install(current_exe: &Path) -> Result<()> {
    let app_dir = get_app_data_directory()?;
    copy_self(&current_exe, &app_dir)?;

    let launcher_path = app_dir.join("bftracks-launcher.exe");
    setup_registry(&launcher_path)?;
    let game_path = get_bf1942_path()?;
    write_config(&app_dir, &game_path)?;
    Ok(())
}
