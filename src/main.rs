#![windows_subsystem = "windows"]
use std::env;
use std::process::{exit,Command};
use std::path::Path;
use std::fs;
use std::io;
use std::time::Duration;
use std::error;
use url::{Url, ParseError};

mod install;
mod config;

use wait_timeout::ChildExt;


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

fn show_message_box(message: &str) -> Result<i32, io::Error>
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
    .arg(format!("{}", server_address))
    .current_dir(game_path.parent().unwrap())
    .spawn()?;

    let timeout = Duration::from_secs(10);
    child.wait_timeout(timeout)?;
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let current_executable = Path::new(&args[0]);
    if args.len() < 2 
    { 
        show_message_box(&format!("Starting first time install")).unwrap();
        match install::install(&current_executable)
        {
            Ok(_) => show_message_box("Install successful!").unwrap(),
            Err(err) =>
            {
                show_message_box(&format!("Install error: {}", err)).unwrap();
                exit(1);
            }
        };
        ()
    }
    else
    {
        let current_dir = current_executable.parent().unwrap();
        let config_file = current_dir.join("config.toml");
        let server = match parse_url(&args[1])
        {
            Ok(server) => server,
            Err(err) =>
            {
                show_message_box(&format!("Error parsing URL: {}", err)).unwrap();
                exit(1);
            } 
        };
        match run(&config_file, &server)
        {
            Ok(_) => (),
            Err(err) =>
            {
                show_message_box(&(*err).to_string()).unwrap();
            }
        }
    }
}