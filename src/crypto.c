/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2021 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>   // uint*_t
#include <string.h>   // memset, explicit_bzero
#include <stdbool.h>  // bool

#include "os.h"
#include "cx.h"


#include "common/base58.h"
#include "common/segwit_addr.h"
#include "common/read.h"
#include "common/write.h"

#include "crypto.h"

// TODO: missing unit tests
int crypto_derive_private_key(cx_ecfp_private_key_t *private_key,
                              uint8_t chain_code[static 32],
                              const uint32_t *bip32_path,
                              uint8_t bip32_path_len) {
    uint8_t raw_private_key[32] = {0};

    // TODO: disabled exception handling, as it breaks with CMocha. Once the sdk is updated,
    //       there will be versions of the cx.h functions that do not throw exceptions.
    //       NOTE: the current version is insecure as it might not wipe the private key after usage!

    // BEGIN_TRY {
    //     TRY {
            // derive the seed with bip32_path
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       bip32_path,
                                       bip32_path_len,
                                       raw_private_key,
                                       chain_code);
            // new private_key from raw
            cx_ecfp_init_private_key(CX_CURVE_256K1,
                                     raw_private_key,
                                     sizeof(raw_private_key),
                                     private_key);
        // }
        // CATCH_OTHER(e) {
        //     THROW(e);
        // }
        // FINALLY {
            explicit_bzero(&raw_private_key, sizeof(raw_private_key));
    //     }
    // }
    // END_TRY;

    return 0;
}


// TODO: missing unit tests
int crypto_init_public_key(cx_ecfp_private_key_t *private_key,
                           cx_ecfp_public_key_t *public_key,
                           uint8_t raw_public_key[static 64]) {
    // generate corresponding public key
    cx_ecfp_generate_pair(CX_CURVE_256K1, public_key, private_key, 1);

    memmove(raw_public_key, public_key->W + 1, 64);

    return 0;
}


int crypto_sign_sha256_hash(const uint8_t in[static 32], uint8_t out[static MAX_DER_SIG_LEN]) {
    cx_ecfp_private_key_t private_key = {0};
    uint8_t chain_code[32] = {0};
    uint32_t info = 0; // TODO: wat?

    // derive private key according to BIP32 path
    // TODO: should we sign with a specific path? e.g. reserve m/0xLED'/... for all internal keys.
    const uint32_t root_path[] = {};
    crypto_derive_private_key(&private_key, chain_code, root_path, 0);

    int sig_len = 0;
    BEGIN_TRY {
        TRY {
            sig_len = cx_ecdsa_sign(&private_key,
                                    CX_RND_RFC6979,
                                    CX_SHA256,
                                    in,
                                    32,
                                    out,
                                    MAX_DER_SIG_LEN,
                                    &info);
        }
        CATCH_OTHER(e) {
            return -1;
        }
        FINALLY {
            explicit_bzero(&private_key, sizeof(private_key));
        }
    }
    END_TRY;

    return sig_len;
}


int crypto_hash_update(cx_hash_t *hash_context, void *in, size_t in_len) {
    return cx_hash(hash_context, 0, in, in_len, NULL, 0);
}


int crypto_hash_digest(cx_hash_t *hash_context, uint8_t *out, size_t out_len) {
    return cx_hash(hash_context, CX_LAST, NULL, 0, out, out_len);
}


// TODO: missing unit tests
void crypto_hash160(uint8_t *in, uint16_t inlen, uint8_t out[static 20]) {
    cx_ripemd160_t riprip;
    uint8_t buffer[32];
    cx_hash_sha256(in, inlen, buffer, 32);
    cx_ripemd160_init(&riprip);
    cx_hash(&riprip.header, CX_LAST, buffer, 32, out, 20);
}


int crypto_get_compressed_pubkey(uint8_t uncompressed_key[static 65], uint8_t out[static 33]) {
    if (uncompressed_key[0] != 0x04) {
        return -1;
    }
    out[0] = (uncompressed_key[64] % 2 == 1) ? 0x03 : 0x02;
    memmove(out + 1, uncompressed_key + 1, 32);
    return 0;
}


// TODO: missing unit tests
void crypto_get_checksum(const uint8_t *in, uint16_t in_len, uint8_t out[static 4]) {
    uint8_t buffer[32];
    cx_hash_sha256(in, in_len, buffer, 32);
    cx_hash_sha256(buffer, 32, buffer, 32);
    os_memmove(out, buffer, 4);
}

/**
 * Gets the compressed pubkey and (optionally) the chain code at the given derivation path. 
 *
 * @param[in]  bip32_path
 *   Pointer to 32-bit integer input buffer.
 * @param[in]  bip32_path_len
 *   Maximum number of BIP32 paths in the input buffer.
 * @param[out]  pubkey
 *   A pointer to a 33-bytes buffer that will receive the compressed public key.
 * @param[out]  chaincode
 *   Either NULL, or a pointer to a 32-bytes buffer that will receive the chain code.
 */
static void crypto_get_compressed_pubkey_at_path(
    const uint32_t bip32_path[],
    uint8_t bip32_path_len,
    uint8_t pubkey[static 33],
    uint8_t chain_code[]
) {
    struct {
        uint8_t prefix;
        uint8_t raw_public_key[64];
        uint8_t chain_code[32];
    } keydata;

    cx_ecfp_private_key_t private_key = {0};
    cx_ecfp_public_key_t public_key;

    keydata.prefix  = 0x04; // uncompressed public keys always start with 04
    // derive private key according to BIP32 path
    crypto_derive_private_key(&private_key, keydata.chain_code, bip32_path, bip32_path_len);

    if (chain_code != NULL) {
        memmove(chain_code, keydata.chain_code, 32);
        explicit_bzero(keydata.chain_code, 32); // delete sensitive data
    }

    // generate corresponding public key
    crypto_init_public_key(&private_key, &public_key, keydata.raw_public_key);
    // reset private key
    explicit_bzero(&private_key, sizeof(private_key)); // delete sensitive data
    // compute compressed public key
    crypto_get_compressed_pubkey((uint8_t *)&keydata, pubkey);
}

size_t get_serialized_extended_pubkey(
    const uint32_t bip32_path[],
    uint8_t bip32_path_len,
    char out[static MAX_SERIALIZED_PUBKEY_LENGTH + 1]
) {
    // find parent key's fingerprint and child number
    uint32_t parent_fingerprint = 0;
    uint32_t child_number = 0;
    if (bip32_path_len > 0) {
        // here we reuse the storage for the parent keys that we will later use
        // for the response, in order to save memory

        uint8_t parent_pubkey[33];
        crypto_get_compressed_pubkey_at_path(bip32_path, bip32_path_len - 1, parent_pubkey, NULL);

        uint8_t parent_key_hash[20];
        crypto_hash160(parent_pubkey, 33, parent_key_hash);

        parent_fingerprint = read_u32_be(parent_key_hash, 0);
        child_number = bip32_path[bip32_path_len - 1];
    }

    // all fields are serialized in big-endian
    static struct {
        uint8_t version[4];
        uint8_t depth;
        uint8_t parent_fingerprint[4];
        uint8_t child_number[4];
        uint8_t chain_code[32];
        uint8_t compressed_pubkey[33];
        uint8_t checksum[4];
    } ext_pubkey;

    write_u32_be(ext_pubkey.version, 0, 0x0488B21E); // TODO: generalize to all networks
    ext_pubkey.depth = bip32_path_len;
    write_u32_be(ext_pubkey.parent_fingerprint, 0, parent_fingerprint);
    write_u32_be(ext_pubkey.child_number, 0, child_number);

    // extkey = version + depth + fpr + child + chainCode + publicKey

    crypto_get_compressed_pubkey_at_path(bip32_path, bip32_path_len, ext_pubkey.compressed_pubkey, ext_pubkey.chain_code);
    crypto_get_checksum((uint8_t *)&ext_pubkey, 78, ext_pubkey.checksum);

    size_t serialized_pubkey_len = base58_encode((uint8_t *)&ext_pubkey, 78 + 4, out, MAX_SERIALIZED_PUBKEY_LENGTH);

    out[serialized_pubkey_len] = '\0';
    return serialized_pubkey_len;
}


int base58_encode_address(const uint8_t in[20], uint32_t version, char *out, size_t out_len) {
    uint8_t tmp[4+20+4]; //version + max_in_len + checksum

    uint8_t version_len;
    if (version < 256) {
        tmp[0] = (uint8_t)version;
        version_len = 1;
    } else if (version < 65536) {
        write_u16_be(tmp, 0, (uint16_t)version);
        version_len = 2;
    } else {
        write_u32_be(tmp, 0, version);
        version_len = 4;
    }

    memcpy(tmp + version_len, in, 20);
    crypto_get_checksum(tmp, version_len + 20, tmp + version_len + 20);
    return base58_encode(tmp, version_len + 20 + 4, out, out_len);
}


int get_address_at_path(
    const uint32_t bip32_path[],
    uint8_t bip32_path_len,
    uint8_t address_type,
    char out[static MAX_ADDRESS_LENGTH_STR + 1]
){
    cx_ecfp_private_key_t private_key = {0};
    cx_ecfp_public_key_t public_key;

    struct {
        uint8_t prefix;
        uint8_t raw_public_key[64];
        uint8_t chain_code[32];
    } keydata;

    keydata.prefix = 0x04;
    // derive private key according to BIP32 path
    crypto_derive_private_key(&private_key, keydata.chain_code, bip32_path, bip32_path_len);
    // generate corresponding public key
    crypto_init_public_key(&private_key, &public_key, keydata.raw_public_key);
    // reset private key
    explicit_bzero(&private_key, sizeof(private_key));
    // compute compressed public key (in-place)
    crypto_get_compressed_pubkey((uint8_t *)&keydata, (uint8_t *)&keydata);

    uint8_t pubkey_hash[20];
    size_t address_len;

    switch(address_type) {
        case ADDRESS_TYPE_PKH:
            crypto_hash160((uint8_t *)&keydata, 33, pubkey_hash);
            address_len = base58_encode_address(pubkey_hash, 0x00, out, MAX_ADDRESS_LENGTH_STR);
            break;
        case ADDRESS_TYPE_SH_WPKH: // wrapped segwit
        case ADDRESS_TYPE_WPKH:    // native segwit
            {
                uint8_t script[22];
                script[0] = 0x00;
                script[1] = 0x14;
                crypto_hash160((uint8_t *)&keydata, 33, script+2);

                uint8_t script_rip[20];
                crypto_hash160((uint8_t *)&script, 22, script_rip);

                if (address_type == ADDRESS_TYPE_SH_WPKH) {
                    address_len = base58_encode_address(script_rip, 0x05, out, MAX_ADDRESS_LENGTH_STR); // TODO: support for altcoins
                } else { // ADDRESS_TYPE_WPKH

                    int ret = segwit_addr_encode(
                        out,
                        (char *)PIC("bc"), // TODO: generalize for other networks
                        0, script + 2, 20
                    );

                    if (ret != 1) {
                        return -1; // should never happen
                    }

                    address_len = strlen(out);
                }
            }
            break;
        default:
            return -1; // this can never happen
    }

    out[address_len] = '\0';
    return address_len;
}
