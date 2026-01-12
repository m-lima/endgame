#![warn(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

pub mod dencrypt;
pub mod types;

mod oidc;

#[cfg(test)]
mod tests {
    pub fn random_array<const L: usize>() -> [u8; L] {
        let mut value = [0; L];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut value);
        value
    }
}
