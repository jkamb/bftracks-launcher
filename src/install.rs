use std::path::{Path, PathBuf};
use std::ffi::OsString;
use std::slice;
use std::os::windows::prelude::OsStringExt;
use super::config;

mod native
{
    use winapi::shared::ntdef::{NTSTATUS, HANDLE, PVOID, ULONG, PULONG, LONG};
    use winapi::shared::minwindef::DWORD;
    extern "system" {
        pub fn NtQueryInformationProcess(
            ProcessHandle: HANDLE,
            ProcessInformationClass: DWORD,
            ProcessInformation: PVOID,
            ProcessInformationLength: ULONG,
            ReturnLength: PULONG,
        ) -> NTSTATUS;
    }

    pub struct PROCESS_BASIC_INFORMATION {
        pub ExitStatus : NTSTATUS,
        pub PebBaseAddress : PVOID, // Should be a PPEB but any pointer to get the correct size should work for now
        pub AffinityMask : PULONG,
        pub BasePriority : LONG,
        pub UniqueProcessId : ULONG,
        pub InheritedFromUniqueProcessId : ULONG,
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
fn setup_registry(launcher_path: &Path) -> Result<(), String>
{
    use winreg::RegKey;
    use winreg::enums::*;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let launcher_dir = launcher_path.parent().unwrap().to_str().unwrap();
    if let Some(launcher_path) = launcher_path.to_str()
    {
        // Setup custom scheme
        let (key, disp) = hklm.create_subkey("SOFTWARE\\Classes\\bftracks\\shell\\open\\command").map_err(|e| e.to_string())?;
        match disp
        {
            REG_CREATED_NEW_KEY => 
            {
                println!("A new key has been created, checking & fixing up keys parent");
                let (key, _) = hklm.create_subkey("SOFTWARE\\Classes\\bftracks").map_err(|e| e.to_string())?;
                key.set_value("", &"BFTracks launcher").map_err(|e| e.to_string())?;
                key.set_value("URL Protocol", &"").map_err(|e| e.to_string())?;
            },
            REG_OPENED_EXISTING_KEY => println!("An existing key has been opened"),
        }
        key.set_value("", &format!("{} \"%1\"", launcher_path)).map_err(|e| e.to_string())?;

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
        let (key, _) = hklm.create_subkey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\BFTracks").map_err(|e| e.to_string())?;
        key.set_value("UninstallString", &format!("{} uninstall", launcher_path)).map_err(|e| e.to_string())?;
        key.set_value("DisplayIcon", &launcher_path).map_err(|e| e.to_string())?;
        key.set_value("DisplayName", &"BFTracks launcher").map_err(|e| e.to_string())?;
        key.set_value("URLInfoAbout", &"http://bftracks.net").map_err(|e| e.to_string())?;
        key.set_value("InstallLocation", &launcher_dir).map_err(|e| e.to_string())?;
        key.set_value("NoModify", &1u32).map_err(|e| e.to_string())?;
        key.set_value("NoRepair", &1u32).map_err(|e| e.to_string())?;
        return Ok(());
    }
    Err("Failed to setup registry".to_owned())
}

fn get_app_data_directory() -> Result<PathBuf, String>
{
    use winapi::um::shlobj::SHGetKnownFolderPath;
    use winapi::um::knownfolders::FOLDERID_LocalAppData;
    use winapi::um::combaseapi::CoTaskMemFree;
    use winapi::um::winnt::PWSTR;
    use winapi::shared::winerror;
    use winapi::um::winbase::lstrlenW;
    use std::ptr;

    unsafe 
    {
        let mut path_ptr: PWSTR = ptr::null_mut();
        let result = SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, ptr::null_mut(), &mut path_ptr);
        if result == winerror::S_OK
        {
                let len = lstrlenW(path_ptr) as usize;
                let path = slice::from_raw_parts(path_ptr, len);
                let ostr: OsString = OsStringExt::from_wide(path);
                CoTaskMemFree(path_ptr as *mut winapi::ctypes::c_void);
                Ok(PathBuf::from(ostr).join("BFTracks"))
        }
        else {
            Err("Failed to get app data directory".to_string())
        }
    }
}

fn get_bf1942_path() -> Result<PathBuf, String>
{
/*
Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Origin\Battlefield 1942
*/
    use wfd::{DialogParams, DialogError, FOS_FILEMUSTEXIST, FOS_HIDEMRUPLACES, FOS_HIDEPINNEDPLACES, FOS_DONTADDTORECENT};
    use winreg::RegKey;
    use winreg::enums::*;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm.open_subkey("SOFTWARE\\WOW6432Node\\Origin\\Battlefield 1942").map_err(|e| e.to_string())?;

    // Try to find Origin installation as a base for user to select the game exe, otherwise default to a known path
    let install_dir: String = match key.get_value("InstallDir")
    {
        Ok(dir) => dir,
        Err(_) => "C:\\".to_string()
    };

    let params = DialogParams {
        file_types: vec![("Executable Files", "BF1942.exe")],
        default_extension: "exe",
        default_folder: &install_dir,
        file_name: "BF1942.exe",
        ok_button_label: "Select",
        options: FOS_FILEMUSTEXIST | FOS_HIDEMRUPLACES | FOS_HIDEPINNEDPLACES |FOS_DONTADDTORECENT,
        title: "BFTracks launcher",
        .. Default::default()
    };

    match wfd::open_dialog(params) {
        Ok(r) => {
            Ok(r.selected_file_path)
        }
        Err(e) => match e {
            DialogError::UserCancelled => {
                Err("Cancelled".to_string())
            }
            DialogError::HResultFailed { hresult, error_method } => {
                Err(format!("HResult Failed - HRESULT: {:X}, Method: {}", hresult, error_method))
            }
        },
    }
}

fn write_config(app_dir: &Path, executable: &Path) -> Result<(), String>
{
    use config::Config;
    use std::fs;
    use std::io::Write;

    let cfg = Config 
    {
        game_path: executable.to_string_lossy().to_string()
    };
    let toml = toml::to_string(&cfg).map_err(|e| e.to_string())?;
    let config_path = app_dir.join("config.toml");
    let mut config_file = fs::File::create(config_path).map_err(|e| e.to_string())?;
    config_file.write_all(toml.as_bytes()).map_err(|e| e.to_string())?;
    Ok(())
}

fn copy_self(current_exe: &Path, app_dir: &Path) -> Result<(), String>
{
    use std::fs;
    
    if !app_dir.exists()
    {
        fs::create_dir(app_dir).map_err(|e| e.to_string())?;
    }
    let copy_location = app_dir.join(current_exe.file_name().unwrap());
    fs::copy(current_exe, copy_location).map_err(|e| e.to_string())?;
    Ok(())
}

fn cleanup_registry() -> Result<(), String>
{
    use winreg::RegKey;
    use winreg::enums::*;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    hklm.delete_subkey_all("SOFTWARE\\Classes\\bftracks").map_err(|e| e.to_string())?;
    hklm.delete_subkey_all("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\BFTracks").map_err(|e| e.to_string())?;
    Ok(())
}

pub fn self_delete() -> Result<(), String>
{
    use std::fs;
    use std::process::{Command, Stdio};
    use native::{NtQueryInformationProcess, PROCESS_BASIC_INFORMATION};
    use winapi::um::synchapi::WaitForSingleObject;
    use winapi::shared::minwindef::DWORD;
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcess};
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use winapi::um::winnt::SYNCHRONIZE;
    use winapi::shared::ntdef::{ULONG, PVOID};
    use winapi::um::winbase::{INFINITE, WAIT_OBJECT_0};
    use std::mem;

    unsafe {
        let own_handle = GetCurrentProcess();
        if own_handle == INVALID_HANDLE_VALUE {
            return Err("Failed to get handle of current process".to_owned());
        }
        let mut process_basic_info : PROCESS_BASIC_INFORMATION = mem::zeroed();
        let process_basic_info_length = mem::size_of::<PROCESS_BASIC_INFORMATION>() as ULONG;
        let mut return_length : ULONG = 0;
        let status = NtQueryInformationProcess(own_handle, 0, &mut process_basic_info as *mut _  as PVOID, process_basic_info_length, &mut return_length);
        if status >= 0 {
            let parent = OpenProcess(SYNCHRONIZE, 0, process_basic_info.InheritedFromUniqueProcessId as DWORD);
            if !parent.is_null() {
                let parent = scopeguard::guard(parent, |h| {
                    let _ = CloseHandle(h);
                });

                let res = WaitForSingleObject(*parent, INFINITE);
                if res != WAIT_OBJECT_0 {
                    return Err("Error waiting for parent to close".to_owned());
                }

                let app_dir = get_app_data_directory()?;
                fs::remove_dir_all(app_dir).map_err(|e| e.to_string())?;

                Command::new("net")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| e.to_string())?;
            }
            else { 
                return Err("Failed to open parent process".to_owned());
            }
        }
    }
    Ok(())
}

fn delete_exe_and_app_dir(current_exe: &Path) -> Result<(), String>
{
    use std::fs;
    use std::mem;
    use std::ptr;
    use std::thread;
    use std::time::Duration;
    use std::process::Command;
    use winapi::shared::minwindef::DWORD;
    use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
    use winapi::um::winbase::FILE_FLAG_DELETE_ON_CLOSE;
    use winapi::um::winnt::{FILE_SHARE_DELETE, FILE_SHARE_READ, GENERIC_READ};
    use std::os::windows::ffi::OsStrExt;

    // This is inspired by rustup's way of self-deleting
    let work_path = current_exe.parent().expect("No parent found for app directory");
    let self_delete_exe = work_path.join(&format!("{}-self-delete.exe", current_exe.file_name().unwrap().to_str().unwrap()));
    let self_delete_exe_raw: Vec<u16> = self_delete_exe.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    fs::copy(&current_exe, &self_delete_exe).map_err(|e| e.to_string())?;

    let mut security_attribute = SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES> as DWORD,
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
            return Err("Failed to get handle to current file".to_owned());
        }

        scopeguard::guard(handle, |h| {
            let _ = CloseHandle(h);
        })
    };

    Command::new(self_delete_exe).spawn().map_err(|e| e.to_string())?;
    
    // Sleep for the new process to get created
    thread::sleep(Duration::from_millis(100));
    Ok(())
}

pub fn uninstall(current_exe: &Path) -> Result<(), String>
{
    // Remove registry entries
    cleanup_registry()?;
    delete_exe_and_app_dir(current_exe)?;
    Ok(())
}

pub fn install(current_exe: &Path) -> Result<(), String>
{
    let app_dir = get_app_data_directory()?;
    copy_self(&current_exe, &app_dir)?;

    let launcher_path = app_dir.join("bftracks-launcher.exe");
    setup_registry(&launcher_path)?;
    let game_path = get_bf1942_path()?;
    write_config(&app_dir, &game_path)?;
    Ok(())
}