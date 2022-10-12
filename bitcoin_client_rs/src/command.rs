/// APDU commands  for the Bitcoin application.
///
use bitcoin::util::bip32::{ChildNumber, DerivationPath};
use core::default::Default;

use super::{
    apdu::{self, APDUCommand},
    common::write_varint,
    wallet::WalletPolicy,
};

/// Creates the APDU Command to retrieve the master fingerprint.
pub fn get_master_fingerprint() -> APDUCommand {
    APDUCommand {
        cla: apdu::Cla::Bitcoin as u8,
        ins: apdu::BitcoinCommandCode::GetMasterFingerprint as u8,
        ..Default::default()
    }
}

/// Creates the APDU command required to get the extended pubkey with the given derivation path.
pub fn get_extended_pubkey(path: &DerivationPath, display: bool) -> APDUCommand {
    let child_numbers: &[ChildNumber] = path.as_ref();
    let data: Vec<u8> = child_numbers.iter().fold(
        vec![
            if display { 1_u8 } else { b'\0' },
            child_numbers.len() as u8,
        ],
        |mut acc, &x| {
            acc.extend_from_slice(&u32::from(x).to_be_bytes());
            acc
        },
    );

    APDUCommand {
        cla: apdu::Cla::Bitcoin as u8,
        ins: apdu::BitcoinCommandCode::GetExtendedPubkey as u8,
        data,
        ..Default::default()
    }
}

/// Creates the APDU command required to register the given wallet policy.
pub fn register_wallet(policy: &WalletPolicy) -> APDUCommand {
    let bytes = policy.serialize();
    let mut data = write_varint(bytes.len());
    data.extend(bytes);
    APDUCommand {
        cla: apdu::Cla::Bitcoin as u8,
        ins: apdu::BitcoinCommandCode::RegisterWallet as u8,
        data,
        ..Default::default()
    }
}

/// Creates the APDU command required to retrieve an address for the given wallet.
pub fn get_wallet_address(
    policy: &WalletPolicy,
    hmac: Option<&[u8; 32]>,
    change: bool,
    address_index: u32,
    display: bool,
) -> APDUCommand {
    let mut data: Vec<u8> = Vec::with_capacity(70);
    data.push(if display { 1_u8 } else { b'\0' });
    data.extend_from_slice(&policy.id());
    data.extend_from_slice(hmac.unwrap_or(&[b'\0'; 32]));
    data.push(if change { 1_u8 } else { b'\0' });
    data.extend_from_slice(&address_index.to_be_bytes());
    APDUCommand {
        cla: apdu::Cla::Bitcoin as u8,
        ins: apdu::BitcoinCommandCode::GetWalletAddress as u8,
        data,
        ..Default::default()
    }
}

/// Creates the APDU command to CONTINUE.
pub fn continue_interrupted(data: Vec<u8>) -> APDUCommand {
    APDUCommand {
        cla: apdu::Cla::Framework as u8,
        ins: apdu::FrameworkCommandCode::ContinueInterrupted as u8,
        data,
        ..Default::default()
    }
}
