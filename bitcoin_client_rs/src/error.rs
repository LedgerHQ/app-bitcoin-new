use crate::apdu::StatusWord;
use core::fmt::Debug;

#[derive(Debug)]
pub enum BitcoinClientError<T: Debug> {
    Transport(T),
    Device { command: u8, status: StatusWord },
    Unexpected { command: u8, error: String },
}
