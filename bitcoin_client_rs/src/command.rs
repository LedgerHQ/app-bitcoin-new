/// APDU commands  for the Bitcoin application.
///
use bitcoin::util::bip32::{ChildNumber, DerivationPath};
use core::default::Default;

use super::{
    apdu::{self, APDUCommand},
    common::write_varint,
    wallet::WalletPolicy,
};

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

/// Creates the APDU command to CONTINUE.
pub fn continue_interrupted(data: Vec<u8>) -> APDUCommand {
    APDUCommand {
        cla: apdu::Cla::Framework as u8,
        ins: apdu::FrameworkCommandCode::ContinueInterrupted as u8,
        data,
        ..Default::default()
    }
}
