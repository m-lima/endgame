#![warn(clippy::pedantic)]

mod core;

pub mod ffi;
pub mod nginx;

#[cfg(feature = "base64")]
pub mod base64;
