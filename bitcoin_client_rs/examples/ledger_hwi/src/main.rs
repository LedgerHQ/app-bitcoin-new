use std::error::Error;
use std::str::FromStr;
use std::sync::Arc;

use bitcoin::{
    consensus::encode::deserialize,
    hashes::hex::{FromHex, ToHex},
    util::{bip32, psbt::Psbt},
};

use hidapi::HidApi;
use ledger_transport_hid::TransportNativeHID;
use regex::Regex;

use ledger_bitcoin_client::{
    async_client::{BitcoinClient, Transport},
    wallet::{Version, WalletPolicy, WalletPubKey},
};

mod transport;
use transport::{TransportHID, TransportTcp, TransportWrapper};

use clap::{Parser, Subcommand};

/// Ledger Hardware Wallet Interface
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    GetFingerprint,
    GetExtendedPubkey {
        #[arg(long)]
        derivation_path: String,
        #[arg(short, long, default_value_t = false)]
        display: bool,
    },
    RegisterWallet {
        #[arg(long)]
        name: String,
        #[arg(long)]
        policy: String,
    },
    Sign {
        #[arg(long)]
        psbt: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        policy: String,
        #[arg(long)]
        hmac: String,
    },
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let transport: Arc<dyn Transport<Error = Box<dyn Error>> + Send + Sync> =
        if let Ok(transport) = TransportTcp::new().await {
            Arc::new(transport)
        } else {
            Arc::new(TransportHID::new(
                TransportNativeHID::new(&HidApi::new().expect("unable to get HIDAPI")).unwrap(),
            ))
        };

    let client = BitcoinClient::new(TransportWrapper::new(transport));

    match args.command {
        Some(Commands::GetFingerprint) => {
            let fg = client.get_master_fingerprint().await.unwrap();
            println!("{}", fg);
        }
        Some(Commands::GetExtendedPubkey {
            derivation_path,
            display,
        }) => {
            get_extended_pubkey(&client, &derivation_path, display)
                .await
                .unwrap();
        }
        Some(Commands::RegisterWallet { name, policy }) => {
            register_wallet(&client, &name, &policy).await.unwrap();
        }
        Some(Commands::Sign {
            psbt,
            name,
            policy,
            hmac,
        }) => {
            sign(&client, &psbt, &name, &policy, Some(&hmac))
                .await
                .unwrap();
        }
        _ => {}
    }
}

async fn get_extended_pubkey<T: Transport>(
    client: &BitcoinClient<T>,
    derivation_path: &str,
    display: bool,
) -> Result<(), Box<dyn Error>> {
    let path = bip32::DerivationPath::from_str(&derivation_path).map_err(|e| format!("{}", e))?;
    let xpk = client
        .get_extended_pubkey(&path, display)
        .await
        .map_err(|e| format!("{:#?}", e))?;
    println!("{}", xpk);
    Ok(())
}

async fn register_wallet<T: Transport>(
    client: &BitcoinClient<T>,
    name: &str,
    policy: &str,
) -> Result<(), Box<dyn Error>> {
    let (descriptor_template, keys) = extract_keys_and_template(policy)?;
    let wallet = WalletPolicy::new(name.to_string(), Version::V2, descriptor_template, keys);
    let (_id, hmac) = client
        .register_wallet(&wallet)
        .await
        .map_err(|e| format!("{:#?}", e))?;
    println!("{}", hmac.to_hex());
    Ok(())
}

async fn sign<T: Transport>(
    client: &BitcoinClient<T>,
    psbt: &str,
    name: &str,
    policy: &str,
    hmac: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let psbt: Psbt = deserialize(&base64::decode(&psbt)?).map_err(|e| format!("{:#?}", e))?;
    let (descriptor_template, keys) = extract_keys_and_template(policy)?;
    let wallet = WalletPolicy::new(name.to_string(), Version::V2, descriptor_template, keys);
    let hmac = if let Some(s) = hmac {
        let mut h = [b'\0'; 32];
        h.copy_from_slice(&Vec::from_hex(&s).map_err(|e| format!("{:#?}", e))?);
        Some(h)
    } else {
        None
    };

    let res = client
        .sign_psbt(&psbt, &wallet, hmac.as_ref())
        .await
        .map_err(|e| format!("{:#?}", e))?;

    for (index, key, sig) in res {
        println!("index: {}, key: {}, sig: {}", index, key, sig);
    }
    Ok(())
}

fn extract_keys_and_template(policy: &str) -> Result<(String, Vec<WalletPubKey>), Box<dyn Error>> {
    let re = Regex::new(r"((\[.+?\])?[xyYzZtuUvV]pub[1-9A-HJ-NP-Za-km-z]{79,108})").unwrap();
    let mut descriptor_template = policy.to_string();
    let mut pubkeys: Vec<WalletPubKey> = Vec::new();
    for (index, capture) in re.find_iter(policy).enumerate() {
        let pubkey = WalletPubKey::from_str(capture.as_str()).map_err(|e| format!("{}", e))?;
        pubkeys.push(pubkey);
        descriptor_template = descriptor_template.replace(capture.as_str(), &format!("@{}", index));
    }
    if let Some((descriptor_template, _hash)) = descriptor_template.rsplit_once("#") {
        Ok((descriptor_template.to_string(), pubkeys))
    } else {
        Ok((descriptor_template, pubkeys))
    }
}
