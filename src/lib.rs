pub mod archive;
pub mod codec;
pub mod commands;
pub mod config;
pub mod crypto;
pub mod error;
pub mod protocol;
pub mod sha256;
pub mod ui_bridge;
pub mod util;

pub const ARCHIVE_EXTENSION: &str = ".qsrl";
pub const FORMAT_VERSION: u16 = 1;
