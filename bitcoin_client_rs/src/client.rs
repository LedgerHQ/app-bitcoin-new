use bitcoin::util::bip32::{DerivationPath, ExtendedPubKey};
use core::fmt::Debug;
use core::str::FromStr;

use crate::{
    apdu::{APDUCommand, StatusWord},
    command,
    error::BitcoinClientError,
    interpreter::ClientCommandInterpreter,
};

/// BitcoinClient calls and interprets commands with the Ledger Device.
pub struct BitcoinClient<T: Transport> {
    transport: T,
}

impl<T: Transport> BitcoinClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    fn make_request(
        &self,
        req: &APDUCommand,
        interpreter: &mut ClientCommandInterpreter,
    ) -> Result<Vec<u8>, BitcoinClientError<T::Error>> {
        let (mut sw, mut data) = self
            .transport
            .exchange(req)
            .map_err(BitcoinClientError::Transport)?;

        while sw == StatusWord::InterruptedExecution {
            let response = interpreter.execute(data)?;
            let res = self
                .transport
                .exchange(&command::continue_interrupted(response))
                .map_err(BitcoinClientError::Transport)?;
            sw = res.0;
            data = res.1;
        }

        if sw != StatusWord::OK {
            Err(BitcoinClientError::Device {
                status: sw,
                command: req.ins,
            })
        } else {
            Ok(data)
        }
    }

    /// Retrieve the bip32 extended pubkey derived with the given path
    /// and optionally display it on screen
    pub fn get_extended_pubkey(
        &self,
        path: &DerivationPath,
        display: bool,
    ) -> Result<ExtendedPubKey, BitcoinClientError<T::Error>> {
        let cmd = command::get_extended_pubkey(path, display);
        let mut int = ClientCommandInterpreter::new();
        self.make_request(&cmd, &mut int).and_then(|data| {
            ExtendedPubKey::from_str(&String::from_utf8_lossy(&data)).map_err(|e| {
                BitcoinClientError::Unexpected {
                    command: cmd.ins,
                    error: e.to_string(),
                }
            })
        })
    }
}

/// Communication layer between the bitcoin client and the Ledger device.
pub trait Transport {
    type Error: Debug;
    fn exchange(&self, command: &APDUCommand) -> Result<(StatusWord, Vec<u8>), Self::Error>;
}
