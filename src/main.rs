#![windows_subsystem = "windows"]
use std::env;
use std::process::{exit,Command};
use std::path::Path;
use std::fs;
use std::io;
use std::time::Duration;
use std::error;
use url::Url;

mod install;
mod config;

use wait_timeout::ChildExt;


fn parse_url(arg: &str) -> Result<String, String>
{
    let bftracks_url = Url::parse(arg).map_err(|e| e.to_string())?;
    if let false = bftracks_url.scheme().eq("bftracks")
    {
        return Err(format!("Invalid scheme {}",bftracks_url.scheme()))
    };

    let host = match bftracks_url.host_str()
    {
        Some(host) => host,
        None => return Err("Empty hostname".into())
    };
    let port = match bftracks_url.port()
    {
        Some(port) => port,
        None => return Err("Invalid port".into())
    };
    Ok(format!("{}:{}", host, port))
}

// From winapi example
fn to_wstring(value: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn show_message_box(message: &str, cancellable: bool) -> Result<i32, io::Error>
{
    use std::ptr::null_mut;
    use winapi::um::winuser::{MessageBoxW, MB_ICONINFORMATION, MB_OK, MB_OKCANCEL};

    let lp_text = to_wstring(message);
    let lp_caption = to_wstring("BFTracks launcher");
    let style = match cancellable
    {
        true => MB_OKCANCEL | MB_ICONINFORMATION,
        false => MB_OK | MB_ICONINFORMATION
    };
    let ret = unsafe {
        MessageBoxW(
            null_mut(),          // hWnd
            lp_text.as_ptr(),    // text
            lp_caption.as_ptr(), // caption (dialog box title)
            style,
        )
    };

    if ret == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn run(config_file: &Path, server_address: &str) -> Result<(), Box<dyn error::Error>>
{
    use config::Config;

    let config = fs::read_to_string(config_file.as_os_str())?;
    let config : Config = toml::from_str(&config)?;
    let game_path = Path::new(&config.game_path);
    let mut child = Command::new(game_path)
    .arg("+restart")
    .arg("1")
    .arg("+joinServer")
    .arg(server_address)
    .current_dir(game_path.parent().unwrap())
    .spawn()?;

    let timeout = Duration::from_secs(10);
    child.wait_timeout(timeout)?;
    Ok(())
}

fn restart_elevated(current_executable: &Path, args: Option<String>) -> Result<(), String>
{
    use winapi::um::shellapi::{ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use winapi::um::synchapi::WaitForSingleObject;
    use winapi::um::winbase::INFINITE;
    use std::mem;
    use std::ptr;

    println!("Restarting elevated! {}", current_executable.to_str().unwrap());
    let file = to_wstring(&current_executable.to_str().unwrap());
    let operation = to_wstring("runas");
    let parameters: Vec<u16> = match args {
        Some(arg) => to_wstring(&arg),
        None => std::iter::once(0u16).collect()
    };
    let n_show_cmd = 10;
    let mut info = SHELLEXECUTEINFOW {
        cbSize: 0,
        fMask: SEE_MASK_NOASYNC | SEE_MASK_NOCLOSEPROCESS,
        hwnd: ptr::null_mut(),
        lpVerb: operation.as_ptr(),
        lpFile: file.as_ptr(),
        lpParameters: parameters.as_ptr(),
        lpDirectory: ptr::null_mut(),
        nShow: n_show_cmd,
        hInstApp: ptr::null_mut(),
        lpIDList: ptr::null_mut(),
        lpClass: ptr::null_mut(),
        hkeyClass: ptr::null_mut(),
        dwHotKey: 0,
        hMonitor: ptr::null_mut(),
        hProcess: ptr::null_mut(),
    };
    info.cbSize = mem::size_of_val(&info) as u32;
    unsafe
    {
        let result = ShellExecuteExW(&mut info);
        if result == 0 {
            return Err("ShellExecute failed!".to_string());
        }
        else {
            WaitForSingleObject(info.hProcess, INFINITE);
        }
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let current_executable = Path::new(&args[0]);
    // TODO: Get app name from central location... maybe cargo file?!
    if current_executable.file_name().unwrap().to_str().unwrap().eq("bftracks-launcher.exe-self-delete.exe") { 
        match install::self_delete()
        {
            Ok(_) => show_message_box("Uninstall successful!", false).unwrap(),
            Err(err) =>
            {
                show_message_box(&format!("Uninstall error: {}", err), false).unwrap();
                exit(1);
            }
        };
        exit(0);
    }

    if args.len() < 2 { 
        if !is_elevated::is_elevated() {
            match restart_elevated(&current_executable, None)
            {
                Ok(_) => exit(0),
                Err(_) => exit(1)
            }
        }

        if let 2 = show_message_box("Starting first time install", true).unwrap()
        {
            // Cancelled
            exit(0);
        };

        match install::install(&current_executable)
        {
            Ok(_) => show_message_box("Install successful!", false).unwrap(),
            Err(err) =>
            {
                show_message_box(&format!("Install error: {}", err), false).unwrap();
                exit(1);
            }
        };
    }
    else if args[1].eq("uninstall") {
        if !is_elevated::is_elevated() {
            match restart_elevated(&current_executable, Some("uninstall".to_owned())) {
                Ok(_) => exit(0),
                Err(_) => exit(1)
            }
        }
        if let 2 = show_message_box("Do you want to uninstall BFTracks launcher?", true).unwrap()
        {
            // Cancelled
            exit(0);
        };

        if let Err(err) = install::uninstall(&current_executable)
        {
            show_message_box(&format!("Uninstall error: {}", err), false).unwrap();
        };
        exit(0);
    }
    else {
        let current_dir = current_executable.parent().unwrap();
        let config_file = current_dir.join("config.toml");
        let server = match parse_url(&args[1])
        {
            Ok(server) => server,
            Err(err) =>
            {
                show_message_box(&format!("Error parsing URL: {}", err), false).unwrap();
                exit(1);
            } 
        };
        match run(&config_file, &server)
        {
            Ok(_) => (),
            Err(err) =>
            {
                show_message_box(&(*err).to_string(), false).unwrap();
                exit(1);
            }
        }
    }
}