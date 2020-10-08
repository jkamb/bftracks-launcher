#![windows_subsystem = "windows"]
use std::env;
use std::process::{exit,Command};
use std::path::Path;
use std::fs;
use std::time::Duration;
use std::io::Error;
use url::{Url, ParseError};
use serde_derive::{Serialize, Deserialize};
use wfd::{DialogParams, DialogError, FOS_FILEMUSTEXIST, FOS_HIDEMRUPLACES, FOS_HIDEPINNEDPLACES, FOS_DONTADDTORECENT};

use wait_timeout::ChildExt;

/*
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\bftracks]
@="BFTracks Launcher"
"URL Protocol"=""

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\bftracks\shell]

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\bftracks\shell\open]

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\bftracks\shell\open\command]
@="\"C:\\Program Files (x86)\\Origin Games\\Battlefield 1942\\BF1942.exe\" \"+joinServer %1\""



Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Origin\Battlefield 1942
*/

#[derive(Serialize, Deserialize)]
struct Config
{
    #[serde(rename = "GamePath")]
    game_path: String
}

fn parse_url(arg: &str) -> Result<String, ParseError>
{
    let bftracks_url = Url::parse(arg)?;
    let host = match bftracks_url.host_str()
    {
        Some(host) => host,
        None => return Err(ParseError::EmptyHost)
    };
    let port = match bftracks_url.port()
    {
        Some(port) => port,
        None => return Err(ParseError::InvalidPort)
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

fn show_message_box(message: &str) -> Result<i32, Error>
{
    use std::ptr::null_mut;
    use winapi::um::winuser::{MessageBoxW, MB_ICONINFORMATION, MB_OK};

    let lp_text = to_wstring(message);
    let lp_caption = to_wstring("BFTracks launcher");
    let ret = unsafe {
        MessageBoxW(
            null_mut(),          // hWnd
            lp_text.as_ptr(),    // text
            lp_caption.as_ptr(), // caption (dialog box title)
            MB_OK | MB_ICONINFORMATION,
        )
    };
    if ret == 0 {
        Err(Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 
    { 
        let msg = format!("Do first time install?");
        show_message_box(&msg).unwrap();
        exit(1); 
    }
    let current_dir = Path::new(&args[0]).parent().unwrap();
    let server = match parse_url(&args[1])
    {
        Ok(server) => server,
        Err(err) =>
        {
            let msg = format!("Error parsing URL: {}", err);
            show_message_box(&msg).unwrap();
            exit(1);
        } 
    };

    let config_file = current_dir.join("config.toml");
    if !config_file.exists()
    {
        let params = DialogParams {
        file_types: vec![("Executable Files", "BF1942.exe")],
        default_extension: "exe",
        default_folder: r"C:\Program Files (x86)\Origin Games\Battlefield 1942",
        file_name: "BF1942.exe",
        //file_name_label: "Select BF1942 executable",
        ok_button_label: "Select",
        options: FOS_FILEMUSTEXIST | FOS_HIDEMRUPLACES | FOS_HIDEPINNEDPLACES |FOS_DONTADDTORECENT,
        title: "BFTracks launcher",
        .. Default::default()
    };

    match wfd::open_dialog(params) {
        Ok(r) => {
            for file in r.selected_file_paths {
                println!("{}", file.to_str().unwrap());
            }
        }
        Err(e) => match e {
            DialogError::UserCancelled => {
                println!("User cancelled dialog");
                exit(0);
            }
            DialogError::HResultFailed { hresult, error_method } => {
                println!("HResult Failed - HRESULT: {:X}, Method: {}", hresult, error_method);
                exit(1);
            }
        },
    }

    }
    let config : Config = match fs::read_to_string(config_file.as_os_str())
    {
        Ok(contents) => 
        {
            match toml::from_str(&contents)
            {
                Ok(config) => config,
                Err(err) => 
                {
                    let msg = format!("Error reading config: {}", err);
                    show_message_box(&msg).unwrap();
                    exit(1);
                }
            }
        },
        Err(err) => 
        {
            let msg = format!("Error reading config: {}", err);
            show_message_box(&msg).unwrap();
            exit(1);
        }
    };

    let game_path = Path::new(&config.game_path);
    let mut child = match Command::new(game_path)
    .arg("+restart")
    .arg("1")
    .arg("+joinServer")
    .arg(format!("{}", server))
    .current_dir(game_path.parent().unwrap())
    .spawn()
    {
        Ok(child) => child,
        Err(err) =>
        {
            let msg = format!("Error launching game: {}", err);
            show_message_box(&msg).unwrap();
            exit(1);
        }
    };
    let timeout = Duration::from_secs(10);
    match child.wait_timeout(timeout).unwrap() {
        Some(_) => (),
        None => ()
    };
}