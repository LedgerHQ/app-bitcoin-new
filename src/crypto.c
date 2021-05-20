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
#include "common/bip32.h"
#include "common/format.h"
#include "common/read.h"
#include "common/write.h"

#include "crypto.h"


/**
 * Generator for secp256k1, value 'g' defined in "Standards for Efficient Cryptography" (SEC2) 2.7.1.
 */
static const uint8_t secp256k1_generator[] = {
    0x04,
    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
    0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
    0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
    0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8
};

/**
 * Modulo for secp256k1
 */
static const uint8_t secp256k1_p[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f
};


/**
 * (p + 1)/4, used to calculate square roots in secp256k1
 */
static const uint8_t secp256k1_sqr_exponent[] = {
    0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbf, 0xff, 0xff, 0x0c
};


//// TODO: remove development code only relevant for speculos
//// BEGIN

//       This replaces the library implementation with our own, as the syscall is not implemented in speculos.
#define cx_ecfp_add_point my_cx_ecfp_add_point

// Temporary replacement for cx_ecfp_add_point that is missing in speculos.
// Does not handle any special case, but it works for most random points.
int my_cx_ecfp_add_point(cx_curve_t curve, unsigned char *R, const unsigned char *P, const unsigned char *Q, unsigned int X_len) {
    if (curve != CX_CURVE_SECP256K1 || X_len != 65) {
        THROW(INVALID_PARAMETER);
    }

    const uint8_t *P_x = P + 1;
    const uint8_t *P_y = P + 1 + 32;
    const uint8_t *Q_x = Q + 1;
    const uint8_t *Q_y = Q + 1 + 32;

    uint8_t lam[32];

    // TODO: missing some special cases, do not use in production!

    if (memcmp(P, Q, 65) == 0) {
        // this branch is not tested, but it shouldn't really happen anyway for random points and this
        // is going to be removed

        // lam = (3 * P.x * P.x * pow(2 * Q.y, p - 2, p)) % p
        uint8_t tmp[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3};
        cx_math_multm(tmp, tmp, P_x, secp256k1_p, 32);       // tmp = 3 * P.x
        cx_math_multm(tmp, tmp, P_x, secp256k1_p, 32);       // tmp = 3 * P.x * P.x

        uint8_t tmp2[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2};
        cx_math_sub(tmp2, secp256k1_p, tmp2, 32);            // tmp2 = p - 2

        uint8_t tmp3[32];
        cx_math_addm(tmp3, Q_y, Q_y, secp256k1_p, 32);       // tmp3 = 2 * Q.y
        cx_math_powm(tmp2, tmp3, tmp2, 32, secp256k1_p, 32); // tmp2 = pow(2 * Q.y, p - 2, p)

        cx_math_multm(lam, tmp, tmp2, secp256k1_p, 32);      // lam
    } else {
        // lam = ((Q.y - P.y) * pow(Q.x - P.x, p - 2, p)) % p
        uint8_t dy[32], dx[32];
        cx_math_subm(dy, Q_y, P_y, secp256k1_p, 32);         //dy = Q.y - P.y
        cx_math_subm(dx, Q_x, P_x, secp256k1_p, 32);         //dx = Q.x - P.x
        uint8_t tmp[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2};
        cx_math_sub(tmp, secp256k1_p, tmp, 32);              // tmp = p - 2
        cx_math_powm(tmp, dx, tmp, 32, secp256k1_p, 32);     // tmp = pow(Q.x - P.x, p - 2, p))

        cx_math_multm(lam, dy, tmp, secp256k1_p, 32);        // lam
    }

    //R.x = (lam * lam - P.x - Q.x) % p
    //R.y = (lam * (P.x - R.x) - P.y) % p

    uint8_t tmp4[32];
    cx_math_multm(tmp4, lam, lam, secp256k1_p, 32);   // tmp4 = lam * lam
    cx_math_subm(tmp4, tmp4, P_x, secp256k1_p, 32);   // tmp4 = lam * lam - P.x
    cx_math_subm(R + 1, tmp4, Q_x, secp256k1_p, 32);  // R.x = lam * lam - P.x - Q.xp

    cx_math_subm(tmp4, P_x, R + 1, secp256k1_p, 32);  // tmp4 = P.x - R.x
    cx_math_multm(tmp4, lam, tmp4, secp256k1_p, 32);  // tmp4 = lam * (P.x - R.x)
    cx_math_subm(R + 33, tmp4, P_y, secp256k1_p, 32); // R.y = lam * (P.x - R.x) - P.y

    R[0] = 0x04;
    return 32;
}
//// END


static int secp256k1_point(const uint8_t scalar[static 32], uint8_t out[static 65]);


/**
 * Gets the point on the SECP256K1 that corresponds to kG, where G is the curve's generator point.
 */
static int secp256k1_point(const uint8_t k[static 32], uint8_t out[static 65]) {
    memcpy(out, secp256k1_generator, 65);
    return cx_ecfp_scalar_mult(CX_CURVE_SECP256K1, out, 65, k, 32);
}


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


int bip32_CKDpub(const serialized_extended_pubkey_t *parent, uint32_t index, serialized_extended_pubkey_t *child) {
    if (index >= BIP32_FIRST_HARDENED_CHILD) {
        return -1; // can only derive unhardened children
    }

    if (parent->depth == 255) {
        return -2; // maximum derivation depth reached
    }

    cx_hmac_t hmac_context;
    uint8_t I[64];

    cx_hmac_sha512_init(&hmac_context, parent->chain_code, 32);
    cx_hmac(&hmac_context, 0, parent->compressed_pubkey, 33, NULL, 0);

    uint8_t index_be[4];
    write_u32_be(index_be, 0, index);
    cx_hmac(&hmac_context, CX_LAST, index_be, 4, I, 64);

    uint8_t *I_L = &I[0];
    uint8_t *I_R = &I[32];

    // TODO: should fail if I_L is not smaller than the group order n, but the probability is < 1/2^128

    // compute point(I_L)
    uint8_t P[65];
    secp256k1_point(I_L, P);

    uint8_t K_par[65];
    crypto_get_uncompressed_pubkey(parent->compressed_pubkey, K_par);

    // add K_par
    uint8_t child_uncompressed_pubkey[65];

    if (cx_ecfp_add_point(CX_CURVE_SECP256K1, child_uncompressed_pubkey, P, K_par, sizeof(child_uncompressed_pubkey)) == 0) {
        return -3; // the point at infinity is not a valid child pubkey (should never happen in practice)
    }

    memmove(child->version, parent->version, 4);
    child->depth = parent->depth + 1;

    uint32_t parent_fingerprint = crypto_get_key_fingerprint(parent->compressed_pubkey);

    write_u32_be(child->parent_fingerprint, 0, parent_fingerprint);
    write_u32_be(child->child_number, 0, index);

    memcpy(child->chain_code, I_R, 32);

    crypto_get_compressed_pubkey(child_uncompressed_pubkey, child->compressed_pubkey);

    return 0;
}


int crypto_sign_sha256_hash(const uint8_t in[static 32], uint8_t out[static MAX_DER_SIG_LEN]) {
    cx_ecfp_private_key_t private_key = {0};
    uint8_t chain_code[32] = {0};
    uint32_t info = 0;

    // derive private key according to BIP32 path
    // TODO: should we sign with a specific path? e.g. reserve m/0xC0FF33'/... for all internal keys.
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


bool crypto_verify_sha256_hash(const uint8_t hash[static 32], uint8_t sig[], size_t sig_len) {
    uint8_t raw_public_key[65];
    cx_ecfp_public_key_t public_key;

    crypto_get_compressed_pubkey_at_path(NULL, 0, raw_public_key, NULL);
    crypto_get_uncompressed_pubkey(raw_public_key, raw_public_key);
    cx_ecfp_init_public_key(CX_CURVE_SECP256K1, raw_public_key, 65, &public_key);

    return cx_ecdsa_verify(&public_key, 0, CX_SHA256, hash, 32, sig, sig_len) == 1;
}


void crypto_ripemd160(const uint8_t *in, uint16_t inlen, uint8_t out[static 20]) {
    cx_ripemd160_t rip_context;
    cx_ripemd160_init(&rip_context);
    cx_hash(&rip_context.header, CX_LAST, in, inlen, out, 20);
}


void crypto_hash160(const uint8_t *in, uint16_t inlen, uint8_t out[static 20]) {
    uint8_t buffer[32];
    cx_hash_sha256(in, inlen, buffer, 32);
    crypto_ripemd160(buffer, 32, out);
}


int crypto_get_compressed_pubkey(const uint8_t uncompressed_key[static 65], uint8_t out[static 33]) {
    if (uncompressed_key[0] != 0x04) {
        return -1;
    }
    out[0] = (uncompressed_key[64] % 2 == 1) ? 0x03 : 0x02;
    memmove(out + 1, uncompressed_key + 1, 32); // copy x
    return 0;
}


int crypto_get_uncompressed_pubkey(const uint8_t compressed_key[static 33], uint8_t out[static 65]) {
    uint8_t prefix = compressed_key[0];
    if (prefix != 0x02 && prefix != 0x03) {
        return -1;
    }

    uint8_t *x = &out[1], *y = &out[1 + 32];

    memmove(x, compressed_key + 1, 32); // copy x

    uint8_t scalar[32] = {0};
    uint8_t tmp1[32], tmp2[32]; // buffers for intermediate results

    scalar[31] = 3;
    cx_math_powm(tmp1, x, scalar, 32, secp256k1_p, 32);                    // tmp1 = x^3 (mod p)
    scalar[31] = 7;
    cx_math_addm(tmp2, tmp1, scalar, secp256k1_p, 32);                     // tmp2 = x^3 + 7 (mod p)
    cx_math_powm(tmp1, tmp2, secp256k1_sqr_exponent, 32, secp256k1_p, 32); // tmp1 = sqrt(x^3 + 7) (mod p)

    // if the prefix and y don't have the same parity, take the opposite root (mod p)
    if (((prefix ^ tmp1[31]) & 1) != 0) {
        cx_math_sub(y, secp256k1_p, tmp1, 32);
    } else {
        memcpy(y, tmp1, 32);
    }

    out[0] = 0x04;
    return 0;
}


// TODO: missing unit tests
void crypto_get_checksum(const uint8_t *in, uint16_t in_len, uint8_t out[static 4]) {
    uint8_t buffer[32];
    cx_hash_sha256(in, in_len, buffer, 32);
    cx_hash_sha256(buffer, 32, buffer, 32);
    os_memmove(out, buffer, 4);
}


void crypto_get_compressed_pubkey_at_path(
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


uint32_t crypto_get_key_fingerprint(const uint8_t pub_key[static 33]) {
    uint8_t key_rip[20];
    crypto_hash160(pub_key, 33, key_rip);

    return read_u32_be(key_rip, 0);
}


// TODO: Split serialization from key derivation?
//       It might be difficult to have a clean API without wasting memory, as the checksum
//       needs to be concatenated to the data before base58 serialization.
size_t get_serialized_extended_pubkey_at_path(
    const uint32_t bip32_path[],
    uint8_t bip32_path_len,
    uint32_t bip32_pubkey_version,
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

        parent_fingerprint = crypto_get_key_fingerprint(parent_pubkey);
        child_number = bip32_path[bip32_path_len - 1];
    }

    struct {
        serialized_extended_pubkey_t ext_pubkey;
        uint8_t checksum[4];
    } ext_pubkey_check; // extended pubkey and checksum

    serialized_extended_pubkey_t *ext_pubkey = &ext_pubkey_check.ext_pubkey;

    write_u32_be(ext_pubkey->version, 0, bip32_pubkey_version);
    ext_pubkey->depth = bip32_path_len;
    write_u32_be(ext_pubkey->parent_fingerprint, 0, parent_fingerprint);
    write_u32_be(ext_pubkey->child_number, 0, child_number);

    crypto_get_compressed_pubkey_at_path(bip32_path, bip32_path_len, ext_pubkey->compressed_pubkey, ext_pubkey->chain_code);
    crypto_get_checksum((uint8_t *)ext_pubkey, 78, ext_pubkey_check.checksum);

    size_t serialized_pubkey_len = base58_encode((uint8_t *)&ext_pubkey_check, 78 + 4, out, MAX_SERIALIZED_PUBKEY_LENGTH);

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
