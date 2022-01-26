#include <string.h>

#include "os.h"

#include "handle_check_address.h"
#include "bip32_path.h"

#include "../common/segwit_addr.h"
#include "../crypto.h"

#ifndef DISABLE_LEGACY_SUPPORT
#include "../legacy/cashaddr.h"
#endif

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

// constants previously defined in btchip_apdu_get_wallet_public_key.h
#define P1_NO_DISPLAY    0x00
#define P1_DISPLAY       0x01
#define P1_REQUEST_TOKEN 0x02

#define P2_LEGACY        0x00
#define P2_SEGWIT        0x01
#define P2_NATIVE_SEGWIT 0x02
#define P2_CASHADDR      0x03

bool get_address_from_compressed_public_key(unsigned char format,
                                            unsigned char* compressed_pub_key,
                                            unsigned short payToAddressVersion,
                                            unsigned short payToScriptHashVersion,
                                            const char* native_segwit_prefix,
                                            char* address,
                                            unsigned char max_address_length) {
    bool segwit = (format == P2_SEGWIT);
    bool nativeSegwit = (format == P2_NATIVE_SEGWIT);
    int address_length;

    // clang-format off
#ifndef DISABLE_LEGACY_SUPPORT
    bool cashAddr = (format == P2_CASHADDR);
    if (cashAddr) {
        uint8_t tmp[20];
        crypto_hash160(compressed_pub_key,  // IN
                         33,                  // INLEN
                         tmp);
        if (!cashaddr_encode(tmp, 20, (uint8_t*) address, max_address_length, CASHADDR_P2PKH))
            return false;
    } else
#endif
    if (!(segwit || nativeSegwit)) {
        // clang-format on
        uint8_t tmp[20];
        crypto_hash160(compressed_pub_key, 33, tmp);
        address_length =
            base58_encode_address(tmp, payToAddressVersion, address, max_address_length - 1);
        if (address_length < 0) {
            return false;
        }
        address[address_length] = 0;
    } else {
        uint8_t script[22];
        script[0] = 0x00;
        script[1] = 0x14;
        crypto_hash160(compressed_pub_key,  // IN
                       33,                  // INLEN
                       script + 2           // OUT
        );
        if (!nativeSegwit) {
            uint8_t tmp[20];
            crypto_hash160(script, 22, tmp);
            // wrapped segwit
            address_length =
                base58_encode_address(tmp, payToScriptHashVersion, address, max_address_length - 1);
            if (address_length < 0) {
                return false;
            }
            address[address_length] = 0;
        } else {
            if (!native_segwit_prefix) return false;
            if (!segwit_addr_encode(address, native_segwit_prefix, 0, script + 2, 20)) {
                return false;
            }
        }
    }
    return true;
}

static int os_strcmp(const char* s1, const char* s2) {
    size_t size = strlen(s1) + 1;
    return memcmp(s1, s2, size);
}

int handle_check_address(check_address_parameters_t* params, btchip_altcoin_config_t* coin_config) {
    unsigned char compressed_public_key[33];
    PRINTF("Params on the address %d\n", (unsigned int) params);
    PRINTF("Address to check %s\n", params->address_to_check);
    PRINTF("Inside handle_check_address\n");
    if (params->address_to_check == 0) {
        PRINTF("Address to check == 0\n");
        return 0;
    }
    bip32_path_t path;
    if (!parse_serialized_path(&path,
                               params->address_parameters + 1,
                               params->address_parameters_length - 1)) {
        PRINTF("Can't parse path\n");
        return false;
    }

    if (!crypto_get_compressed_pubkey_at_path(path.path,
                                              path.length,
                                              compressed_public_key,
                                              NULL)) {
        return 0;
    }
    char address[51];
    if (!get_address_from_compressed_public_key(params->address_parameters[0],
                                                compressed_public_key,
                                                coin_config->p2pkh_version,
                                                coin_config->p2sh_version,
                                                coin_config->native_segwit_prefix,
                                                address,
                                                sizeof(address))) {
        PRINTF("Can't create address from given public key\n");
        return 0;
    }
    if (os_strcmp(address, params->address_to_check) != 0) {
        PRINTF("Addresses don't match\n");
        return 0;
    }
    PRINTF("Addresses match\n");
    return 1;
}