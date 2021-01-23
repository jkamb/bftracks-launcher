# BFTracks launcher
This is a very simple self-installing launcher for BFTracks.net. When run without arguments it will try to install itself by doing the following:
* Try to elevate privileges to be able to set registry keys
* Ask for the BF1942 executable path
* Copy itself to the AppData directory for the current user
* Write config in the AppData directory
* Register a custom URL scheme (bftracks://) in the registry
* Add an uinstall entry in the registry

After installation, clicking on a bftracks:// url will prompt to use the launcher.

Uninstallation is done via the standard "Programs & Features" panel in Windows.

This launcher has only been tested on Windows 10 64-bit. It might be broken on other Windows versions.

## Setup
* Install Visual C++ build tools
* Install Rust toolchain via https://rustup.rs/
* Rust or Rust Analyzer (recommended) extension for VS Code

## Build
Open command prompt in project folder and run: `cargo build` for debug build and `cargo build --release` for release (optimized)
Build for 32-bit by running `rustup target add i686-pc-windows-msvc` once and then build with cargo using `cargo build --target=i686-pc-windows-msvc`
