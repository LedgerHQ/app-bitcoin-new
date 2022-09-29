use core::convert::TryFrom;
use std::collections::HashMap;

use async_trait::async_trait;
use bitcoin::hashes::hex::{FromHex, ToHex};

use ledger_bitcoin_client::{
    apdu::{APDUCommand, StatusWord},
    async_client, client,
};

#[derive(Default, Clone)]
pub struct RecordStore {
    pub queue: HashMap<Vec<u8>, Vec<u8>>,
}

impl RecordStore {
    pub fn new(exchanges: &Vec<String>) -> RecordStore {
        let mut store = RecordStore::default();
        let mut command: Vec<u8> = Vec::new();
        for exchange in exchanges {
            let exchange = exchange.replace(" ", "");
            if let Some(cmd) = exchange.strip_prefix("=>") {
                command = Vec::from_hex(cmd).expect("Wrong tests data");
            }
            if let Some(resp) = exchange.strip_prefix("<=") {
                let resp = Vec::from_hex(resp).expect("Wrong tests data");
                store.queue.insert(command.clone(), resp);
            }
        }

        store
    }
}

#[derive(Clone)]
pub struct TransportReplayer {
    store: RecordStore,
}

impl TransportReplayer {
    pub fn new(store: RecordStore) -> TransportReplayer {
        TransportReplayer { store }
    }

    fn replay(&self, command: &APDUCommand) -> Result<(StatusWord, Vec<u8>), MockError> {
        let payload = command.encode();
        if let Some(res) = self.store.queue.get(&payload) {
            let res = res.as_slice();
            let mut buff = [b'\0'; 2];
            buff.copy_from_slice(&res[res.len() - 2..res.len()]);
            let sw = u16::from_be_bytes(buff);
            let answer = &res[0..res.len() - 2];
            return Ok((
                StatusWord::try_from(sw).expect("Wrong tests data"),
                answer.to_vec(),
            ));
        }
        Err(MockError::ExchangeNotFound(payload.to_hex()))
    }
}

impl client::Transport for TransportReplayer {
    type Error = MockError;
    fn exchange(&self, command: &APDUCommand) -> Result<(StatusWord, Vec<u8>), Self::Error> {
        self.replay(command)
    }
}

#[async_trait]
impl async_client::Transport for TransportReplayer {
    type Error = MockError;
    async fn exchange(&self, command: &APDUCommand) -> Result<(StatusWord, Vec<u8>), Self::Error> {
        self.replay(command)
    }
}

#[derive(Debug)]
pub enum MockError {
    ExchangeNotFound(String),
}
