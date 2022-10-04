use core::fmt::Debug;

use crate::{apdu::StatusWord, interpreter::InterpreterError};

#[derive(Debug)]
pub enum BitcoinClientError<T: Debug> {
    Transport(T),
    Interpreter(InterpreterError),
    Device { command: u8, status: StatusWord },
    Unexpected { command: u8, error: String },
}

impl<T: Debug> From<InterpreterError> for BitcoinClientError<T> {
    fn from(e: InterpreterError) -> BitcoinClientError<T> {
        BitcoinClientError::Interpreter(e)
    }
}
