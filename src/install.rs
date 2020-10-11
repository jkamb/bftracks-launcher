use std::path::{Path, PathBuf};
use std::ffi::OsString;
use std::slice;
use std::os::windows::prelude::OsStringExt;

use super::config;

/*
[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\bftracks]
@="BFTracks Launcher"
"URL Protocol"=""

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\bftracks\shell]

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\bftracks\shell\open]

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\bftracks\shell\open\command]
@="\"D:\git\bftracks-launcher\target\release\bftracks-launcher.exe\"" \"%1\""
*/
fn setup_registry(launcher_path: &str) -> Result<(), String>
{
    use winreg::RegKey;
    use winreg::enums::*;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
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
    Ok(())
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
        else
        {
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
            Ok(PathBuf::from(r.selected_file_path))
        }
        Err(e) => match e {
            DialogError::UserCancelled => {
                return Err("Cancelled".to_string())
            }
            DialogError::HResultFailed { hresult, error_method } => {
                return Err(format!("HResult Failed - HRESULT: {:X}, Method: {}", hresult, error_method))
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

pub fn install(current_exe: &Path) -> Result<(), String>
{
    let app_dir = get_app_data_directory().map_err(|_e| "Failed to get app data directory".to_string())?;
    copy_self(&current_exe, &app_dir)?;
    setup_registry(&format!("{}\\bftracks-launcher.exe", app_dir.to_str().unwrap()))?;
    let game_path = get_bf1942_path()?;
    write_config(&app_dir, &game_path)?;
    Ok(())
}