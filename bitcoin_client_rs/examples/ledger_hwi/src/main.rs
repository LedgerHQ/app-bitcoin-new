use std::convert::TryFrom;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use bitcoin::util::bip32;
use hidapi::HidApi;
use ledger_apdu::APDUAnswer;
use ledger_transport_hid::TransportNativeHID;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

use ledger_bitcoin_client::{
    apdu::{APDUCommand, StatusWord},
    async_client::{BitcoinClient, Transport},
};

const HELP: &'static str = "
Ledger Hardware Wallet Interface
--------------------------------
This tool first looks for a speculos simulator listening
at 127.0.0.1:40000, then looks for hid devices.

commands:
    get_extended_pubkey <bip32 derivation path> <display=true>
";

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("{}", HELP);
        std::process::exit(1);
    }

    let transport: Arc<dyn Transport<Error = Box<dyn Error>> + Send + Sync> =
        if let Ok(transport) = TransportTcp::new().await {
            Arc::new(transport)
        } else {
            Arc::new(TransportHID(
                TransportNativeHID::new(&HidApi::new().expect("unable to get HIDAPI")).unwrap(),
            ))
        };

    let client = BitcoinClient::new(TransportWrapper(transport));

    match args[1].as_str() {
        "get_extended_pubkey" => {
            get_extended_pubkey(&client, &args[2..]).await;
        }
        _ => {}
    }
}

async fn get_extended_pubkey<T: Transport>(client: &BitcoinClient<T>, args: &[String]) {
    if args.len() < 1 || args.len() > 2 {
        eprintln!("get_extended_pubkey <bip32 derivation path> <display=true>");
        std::process::exit(1);
    }
    let path = bip32::DerivationPath::from_str(&args[0]).unwrap();
    let display = if args.len() == 2 {
        bool::from_str(&args[1]).unwrap()
    } else {
        false
    };
    let xpk = client.get_extended_pubkey(&path, display).await.unwrap();
    println!("{}", xpk);
}

/// Transport with the Ledger device.
struct TransportHID(TransportNativeHID);

#[async_trait]
impl Transport for TransportHID {
    type Error = Box<dyn Error>;
    async fn exchange(&self, cmd: &APDUCommand) -> Result<(StatusWord, Vec<u8>), Self::Error> {
        self.0
            .exchange(&ledger_apdu::APDUCommand {
                ins: cmd.ins,
                cla: cmd.cla,
                p1: cmd.p1,
                p2: cmd.p2,
                data: cmd.data.clone(),
            })
            .map(|answer| {
                (
                    StatusWord::try_from(answer.retcode()).unwrap_or(StatusWord::Unknown),
                    answer.data().to_vec(),
                )
            })
            .map_err(|e| e.into())
    }
}

/// Transport to communicate with the Ledger Speculos simulator.
pub struct TransportTcp {
    connection: Mutex<TcpStream>,
}

impl TransportTcp {
    pub async fn new() -> Result<Self, Box<dyn Error>> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 40000);
        let stream = TcpStream::connect(addr).await?;
        Ok(Self {
            connection: Mutex::new(stream),
        })
    }
}

#[async_trait]
impl Transport for TransportTcp {
    type Error = Box<dyn Error>;
    async fn exchange(&self, command: &APDUCommand) -> Result<(StatusWord, Vec<u8>), Self::Error> {
        let mut stream = self.connection.lock().await;
        let command_bytes = command.encode();

        let mut req = vec![0u8; command_bytes.len() + 4];
        req[..4].copy_from_slice(&(command_bytes.len() as u32).to_be_bytes());
        req[4..].copy_from_slice(&command_bytes);
        stream.write(&req).await?;

        let mut buff = [0u8; 4];
        let len = match stream.read(&mut buff).await? {
            4 => u32::from_be_bytes(buff),
            _ => return Err("Invalid Length".into()),
        };

        let mut resp = vec![0u8; len as usize + 2];
        stream.read_exact(&mut resp).await?;
        let answer = APDUAnswer::from_answer(resp).map_err(|_| "Invalid Answer")?;
        Ok((
            StatusWord::try_from(answer.retcode()).unwrap_or(StatusWord::Unknown),
            answer.data().to_vec(),
        ))
    }
}

/// Wrapper to handle both hid and tcp transport.
struct TransportWrapper(Arc<dyn Transport<Error = Box<dyn Error>> + Sync + Send>);

#[async_trait]
impl Transport for TransportWrapper {
    type Error = Box<dyn Error>;
    async fn exchange(&self, command: &APDUCommand) -> Result<(StatusWord, Vec<u8>), Self::Error> {
        self.0.exchange(command).await
    }
}
