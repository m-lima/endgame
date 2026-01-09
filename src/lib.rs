#![warn(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

macro_rules! log_err {
    ($msg: expr, $err: expr) => {
        eprintln!(
            concat!("[", env!("CARGO_CRATE_NAME"), "] ", $msg, ": {}"),
            $err
        )
    };
    ($msg: expr) => {
        eprintln!(concat!("[", env!("CARGO_CRATE_NAME"), "] ", $msg))
    };
}

pub mod dencrypt;
pub mod types;

mod ffi;

mod oidc;
