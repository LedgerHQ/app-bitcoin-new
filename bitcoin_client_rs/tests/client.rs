mod utils;
use std::str::FromStr;

use bitcoin::util::bip32::DerivationPath;
use ledger_bitcoin_client::{async_client, client};

fn test_cases(path: &str) -> Vec<serde_json::Value> {
    let data = std::fs::read_to_string(path).expect("Unable to read file");
    serde_json::from_str(&data).expect("Wrong tests data")
}

#[tokio::test]
async fn test_get_extended_pubkey() {
    for case in test_cases("./tests/data/get_extended_pubkey.json") {
        let exchanges: Vec<String> = case
            .get("exchanges")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let derivation_path: DerivationPath = case
            .get("derivation_path")
            .map(|v| v.as_str().unwrap())
            .map(|s| DerivationPath::from_str(&s).unwrap())
            .unwrap();

        let display: bool = case
            .get("display")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let xpk_str: String = case
            .get("result")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let transport = utils::TransportReplayer::new(utils::RecordStore::new(&exchanges));
        let key = client::BitcoinClient::new(transport.clone())
            .get_extended_pubkey(&derivation_path, display)
            .unwrap();

        assert_eq!(key.to_string(), xpk_str);

        let key = async_client::BitcoinClient::new(transport.clone())
            .get_extended_pubkey(&derivation_path, display)
            .await
            .unwrap();

        assert_eq!(key.to_string(), xpk_str);
    }
}
