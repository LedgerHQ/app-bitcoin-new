use async_trait::async_trait;
use bitcoin::util::bip32::{DerivationPath, ExtendedPubKey, Fingerprint};
use core::fmt::Debug;
use core::str::FromStr;

use crate::{
    apdu::{APDUCommand, StatusWord},
    command,
    error::BitcoinClientError,
    interpreter::ClientCommandInterpreter,
    wallet::WalletPolicy,
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

    /// Retrieve the master fingerprint.
    pub async fn get_master_fingerprint(
        &self,
    ) -> Result<Fingerprint, BitcoinClientError<T::Error>> {
        let cmd = command::get_master_fingerprint();
        let mut int = ClientCommandInterpreter::new();
        self.make_request(&cmd, &mut int)
            .await
            .map(|data| Fingerprint::from(data.as_slice()))
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
            ExtendedPubKey::from_str(&String::from_utf8_lossy(&data)).map_err(|_| {
                BitcoinClientError::UnexpectedResult {
                    command: cmd.ins,
                    data,
                }
            })
        })
    }

    /// Registers the given wallet policy, returns the wallet ID and HMAC.
    pub async fn register_wallet(
        &self,
        wallet: &WalletPolicy,
    ) -> Result<([u8; 32], [u8; 32]), BitcoinClientError<T::Error>> {
        let cmd = command::register_wallet(wallet);
        let mut intpr = ClientCommandInterpreter::new();
        intpr.add_known_preimage(wallet.serialize());
        let keys: Vec<String> = wallet.keys.iter().map(|k| k.to_string()).collect();
        intpr.add_known_list(&keys);
        //necessary for version 1 of the protocol (introduced in version 2.1.0)
        intpr.add_known_preimage(wallet.descriptor_template.as_bytes().to_vec());
        self.make_request(&cmd, &mut intpr).await.and_then(|data| {
            if data.len() < 64 {
                Err(BitcoinClientError::UnexpectedResult {
                    command: cmd.ins,
                    data,
                })
            } else {
                let mut id = [0x00; 32];
                id.copy_from_slice(&data[0..32]);
                let mut hash = [0x00; 32];
                hash.copy_from_slice(&data[32..64]);
                Ok((id, hash))
            }
        })
    }

    /// For a given wallet that was already registered on the device (or a standard wallet that does not need registration),
    /// returns the address for a certain `change`/`address_index` combination.
    pub async fn get_wallet_address(
        &self,
        wallet: &WalletPolicy,
        wallet_hmac: Option<&[u8; 32]>,
        change: bool,
        address_index: u32,
        display: bool,
    ) -> Result<bitcoin::Address, BitcoinClientError<T::Error>> {
        let mut intpr = ClientCommandInterpreter::new();
        intpr.add_known_preimage(wallet.serialize());
        let keys: Vec<String> = wallet.keys.iter().map(|k| k.to_string()).collect();
        intpr.add_known_list(&keys);
        // necessary for version 1 of the protocol (introduced in version 2.1.0)
        intpr.add_known_preimage(wallet.descriptor_template.as_bytes().to_vec());
        let cmd = command::get_wallet_address(wallet, wallet_hmac, change, address_index, display);
        self.make_request(&cmd, &mut intpr).await.and_then(|data| {
            bitcoin::Address::from_str(&String::from_utf8_lossy(&data)).map_err(|_| {
                BitcoinClientError::UnexpectedResult {
                    command: cmd.ins,
                    data,
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
