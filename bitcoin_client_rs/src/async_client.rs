use async_trait::async_trait;
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
/// The methods can only be used by an asynchronous engine like tokio.
pub struct BitcoinClient<T: Transport> {
    transport: T,
}

impl<T: Transport> BitcoinClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    async fn make_request(
        &self,
        req: &APDUCommand,
        interpreter: &mut ClientCommandInterpreter,
    ) -> Result<Vec<u8>, BitcoinClientError<T::Error>> {
        let (mut sw, mut data) = self
            .transport
            .exchange(req)
            .await
            .map_err(BitcoinClientError::Transport)?;

        while sw == StatusWord::InterruptedExecution {
            let response = interpreter.execute(data)?;
            let res = self
                .transport
                .exchange(&command::continue_interrupted(response))
                .await
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
    pub async fn get_extended_pubkey(
        &self,
        path: &DerivationPath,
        display: bool,
    ) -> Result<ExtendedPubKey, BitcoinClientError<T::Error>> {
        let cmd = command::get_extended_pubkey(path, display);
        let mut int = ClientCommandInterpreter::new();
        self.make_request(&cmd, &mut int).await.and_then(|data| {
            ExtendedPubKey::from_str(&String::from_utf8_lossy(&data)).map_err(|e| {
                BitcoinClientError::Unexpected {
                    command: cmd.ins,
                    error: e.to_string(),
                }
            })
        })
    }
}

/// Asynchronous communication layer between the bitcoin client and the Ledger device.
#[async_trait]
pub trait Transport {
    type Error: Debug;
    async fn exchange(&self, command: &APDUCommand) -> Result<(StatusWord, Vec<u8>), Self::Error>;
}
