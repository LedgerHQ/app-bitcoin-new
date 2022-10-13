mod command;
mod common;
mod interpreter;
mod merkle;
mod psbt;

pub mod apdu;
pub mod client;
pub mod error;
pub mod wallet;

#[cfg(feature = "async")]
pub mod async_client;

pub use client::{BitcoinClient, Transport};
pub use wallet::{WalletPolicy, WalletPubKey};
