mod command;
mod interpreter;
mod merkle;

pub mod apdu;
pub mod client;
pub mod error;
pub mod psbt;
pub mod wallet;

#[cfg(feature = "async")]
pub mod async_client;

pub use client::{BitcoinClient, Transport};
pub use wallet::{WalletPolicy, WalletPubKey};
