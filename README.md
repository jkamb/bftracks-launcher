# BFTracks launcher


## Setup
* Install Visual C++ build tools
* Install Rust toolchain via https://rustup.rs/
* Rust extension for VS Code

## Build
Open command prompt in project folder and run: `cargo build` for debug build and `cargo build --release` for release (optimized)
Build for 32-bit by running `target add i686-pc-windows-msvc` once and then build with cargo using `cargo build --target=i686-pc-windows-msvc`