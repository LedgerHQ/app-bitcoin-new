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
 * (p + 1)/4, used to calculate square roots in secp256k1_p
 */
static const uint8_t secp256k1_sqr_exponent[] = {
    0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbf, 0xff, 0xff, 0x0c
};


//// TODO: remove development code only relevant for speculos
//// BEGIN
void debug_write(const char *buf)
{
  asm volatile (
     "movs r0, #0x04\n"
     "movs r1, %0\n"
     "svc      0xab\n"
     :: "r"(buf) : "r0", "r1"
  );
}

static unsigned char nib_to_hex(unsigned char nib) {
    return nib < 10 ? '0' + nib : 'a' + (nib - 10);
}

void debug_write_hex(const void *buf, size_t len) {
    for (unsigned int i = 0; i < len; i++) {
        char str[3];
        uint8_t c = ((char *)buf)[i];
        str[0] = nib_to_hex(c >> 4);
        str[1] = nib_to_hex(c & 0b1111);
        str[2] = 0;
        debug_write(str);
    }
    debug_write("\n");
}

// replacement for cx_ecfp_add_point that is missing in speculos; only replies correctly for a 
int my_cx_ecfp_add_point(cx_curve_t curve, unsigned char *R, const unsigned char *P, const unsigned char *Q, unsigned int X_len) {
    static const char precomputed_sums[][3][131] = {
        {
            "044104b51c57a880c6e52457daa0b596dc6cada22eaed15243e958354433ed748b463bc4299fc0c2c3034d20e1bc0dfaab2c2e306811881731b048fec5d1c41cfd",
            "040b2f1c533fe7bb1160292c6ebccc426cde21ff02bf455ce0e369a1ca0f563c0d1219a37f340667e0088f3619ac1822856792e1ff6abf5579d6eee5a8728975b8",
            "044251358da206b3d549f5c538a7bc466427ee81099aa8b40dd0f5d4bfac5f5f152ea7968164873f9f7a9430d3eab432ae8d2484b513e5b3bd2d0b8d6a0251314b"
        },
        {
            "049d0e32cd161b550deb6be3fba6a235f648b1f7faa56ba8abb475607844b555545893822837c131a6ec191764a4427c0089f438ddf69071006129f49b80b91ea6",
            "044251358da206b3d549f5c538a7bc466427ee81099aa8b40dd0f5d4bfac5f5f152ea7968164873f9f7a9430d3eab432ae8d2484b513e5b3bd2d0b8d6a0251314b",
            "048df72565b96f522251967d1301891ad98f142b0ffb7f05251e1742413cad1d7df12b327f319d2c86e819510b6867c66edcce8c110dcfe01c6946d9a34cb77f8a",
        },
        {
            "043709ec56327cd741253c20d806942768e83ea067717935af2ad74b81dd6a6bb04beaf7e46491ce88fa02e1212d3d61b41519706e6c1d510b60f493a6ff233549",
            "04f6bcdc56e76edfe07bbac5f4471e38cb2225cce50810808e5e35a76d4ba63b2e6e9e464e0f101177adcefdc5760dc51a75f9c2fb51b84d32ddb2ccebf3fd873a",
            "042f211e7b6360f0d3deb14b7f1813b97331c7a2b9db2030f5c396805883ae34d4b9530177c424dc9ad7dfe8ee8fcb02533f49f61da8788e693a183f80ee72323d",
        },
        {
            "04a4154949d9df47dd65c7dce1323f7f4a4ab789edd7817802ae1ce2a258dd6bdd0a2e5b935c12bd284411c9777a50b67e2cce9b8c50e88ab550ba13a401741c59",
            "042f211e7b6360f0d3deb14b7f1813b97331c7a2b9db2030f5c396805883ae34d4b9530177c424dc9ad7dfe8ee8fcb02533f49f61da8788e693a183f80ee72323d",
            "04cc50c5c1c1d74db5c578507cd94164425860c08e81ffb87e8ff85f9a8e58ac84e6cd2be60486106082c6eee08a098839c1d64357aae0017ea6ad3d18e4f0eee8",
        },
        {
            "04cb9579c43b24fd851ac0fa834bc992c020c37eb1ce9a4031b11aef3c5b1a51273a4ad28da0662fe5311ef691cf0e4cead3923846fa3cd8e74b920a319370d093",
            "047024763c1ca429eaaa3aaf096c24328155ea8414bf47428dfa97d57f6c535b1a5a2a51f70ea81fd464c1878cc048b3e8c552b18e85e9af3e29a142b6fd86ee93",
            "04eb1bffe2f24ee47ded2e7a028e90814562a5f767ece3503fe4537ca5f59f4bac1f3196726bd462f5ed167b8bfd4fe20c4e9dd0be7fa4fcd3344d4a06a0f9d170",
        },
        {
            "044e78a6c190ec3fc4f716e1ccbe84d10fa2724af1827beae3c9b47ffc5f7c6b6f00119f6ac4eb847efd8d7d02bf1eb52508deba30cfd5cba2c4c8fab48da301d3",
            "04eb1bffe2f24ee47ded2e7a028e90814562a5f767ece3503fe4537ca5f59f4bac1f3196726bd462f5ed167b8bfd4fe20c4e9dd0be7fa4fcd3344d4a06a0f9d170",
            "0403cae65c0f7df1cc1447bb9c85b189dc0d82a4b7a15b790f99b591fb3c32ab5a1a65cee8767c1bdea4684862e7d54071c430924a1ebf2653a4c150f0b1d98e7d",
        },
        {
            "040d45f564edbd98e4f4631fc0c8ae3674c8bf226e2fce3a8e12ce08b4cf4f44ca037ffd7cbfa76a2dbe283d2e6b5a2f6a290b5d69a4fbf5dfdd26e7da31195afb",
            "044251358da206b3d549f5c538a7bc466427ee81099aa8b40dd0f5d4bfac5f5f152ea7968164873f9f7a9430d3eab432ae8d2484b513e5b3bd2d0b8d6a0251314b",
            "041cd16f06cb22c35b8c5f53b6c91e1e09f9898acf3e3fe401d0152f9b6f435a7f0ed861e0c75682b6e501375330070c52f7f84796a5e32074504a24b4e0f8d05f",
        },
        {
            "04705184e8bb0be65b34ed65ded3bccdcb816fdb70faa35c15fe2f5e0a30f2bb7b8da2cc9a875ac2dd2dd5bcc7b033460ff87e6cbaf2b912234b99255870a8ec2f",
            "04eb1bffe2f24ee47ded2e7a028e90814562a5f767ece3503fe4537ca5f59f4bac1f3196726bd462f5ed167b8bfd4fe20c4e9dd0be7fa4fcd3344d4a06a0f9d170",
            "0403ccd2edbab718ed0268ed1cbfe0ef9247bf023495bfd9fba39b035f6e42c2e864dde4451aa5c2daa232ce8469d0c4c3089e084891b8d82dedafd8ef5f3927c9",
        },
        {
            "04c1b99173eab91b249a878431b456e00e0a0ccb26d584ed7815e945cef1217340d955e34b49b86b6da3f659ba6bf7ab84ae53e9f2c1fa29d7bc750b1923b010e6",
            "042f211e7b6360f0d3deb14b7f1813b97331c7a2b9db2030f5c396805883ae34d4b9530177c424dc9ad7dfe8ee8fcb02533f49f61da8788e693a183f80ee72323d",
            "04d911b19671d5d9216124dddfec08f1925f6257f8a396a001ceb7a151edf921c3237768efbfeeb1c9e31a6c84674df8cebf49e683c2209fbdbfa35f97342d0ad3",
        },
        {
            "04c56e7c0317c993d1bedc7271225a750fa60671fcd2484867156e12d369b7d014f73aecf58e947d06c91e88b689fdaab24c2677a95c65adf3a17be45cf69fa24e",
            "04eb1bffe2f24ee47ded2e7a028e90814562a5f767ece3503fe4537ca5f59f4bac1f3196726bd462f5ed167b8bfd4fe20c4e9dd0be7fa4fcd3344d4a06a0f9d170",
            "04c1dfb283ee3e0a3c0fce7abf86011e1d45a6efb16f8ac55f9f508e02d547ec20bb317682cb0096d12a15445893d51c600b6ce92e92001c622d0735d6378f18fe",
        }
    };

    if (curve == CX_CURVE_SECP256K1 && X_len == 65) {
        for (unsigned int i = 0; i < sizeof(precomputed_sums)/sizeof(precomputed_sums[0]); i++) {
            char P_str[131], Q_str[131];
            format_hex(P, 65, P_str, sizeof(P_str));
            format_hex(Q, 65, Q_str, sizeof(Q_str));

            if (strcmp(P_str, (char *)PIC(precomputed_sums[i][0])) != 0) continue;
            if (strcmp(Q_str, (char *)PIC(precomputed_sums[i][1])) != 0) continue;

            // both matched; convert result
            const char *R_str = (const char *)PIC(precomputed_sums[i][2]);
            for (int j = 0; j < 65; j++) {
                uint8_t nib1, nib2;
                nib1 = R_str[2 * j] <= '9' ? R_str[2 * j] - '0' : R_str[2 * j] - 'a' + 10;
                nib2 = R_str[2 * j + 1] <= '9' ? R_str[2 * j + 1] - '0' : R_str[2 * j + 1] - 'a' + 10;
                R[j] = (char)(nib1 * 16 + nib2);
            }
            return 32;
        }

        debug_write("Unknown point sum.\n");
        debug_write_hex(P, 65);
        debug_write(" ");
        debug_write_hex(Q, 65);
        debug_write("\n");
    }

    THROW(INVALID_PARAMETER);
}
//// END


static uint32_t crypto_get_key_fingerprint(const uint8_t key[static 33]);

static void crypto_get_compressed_pubkey_at_path(
    const uint32_t bip32_path[],
    uint8_t bip32_path_len,
    uint8_t pubkey[static 33],
    uint8_t chain_code[]
);
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

    memcpy(child->version, parent->version, 4);
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


bool crypto_verify_sha256_hash(const uint8_t hash[static 32], uint8_t sig[], size_t sig_len) {
    uint8_t raw_public_key[65];
    cx_ecfp_public_key_t public_key;

    crypto_get_compressed_pubkey_at_path(NULL, 0, raw_public_key, NULL);
    crypto_get_uncompressed_pubkey(raw_public_key, raw_public_key);
    cx_ecfp_init_public_key(CX_CURVE_SECP256K1, raw_public_key, 65, &public_key);

    return cx_ecdsa_verify(&public_key, 0, CX_SHA256, hash, 32, sig, sig_len) == 1;
}


int crypto_hash_update(cx_hash_t *hash_context, void *in, size_t in_len) {
    return cx_hash(hash_context, 0, in, in_len, NULL, 0);
}


int crypto_hash_digest(cx_hash_t *hash_context, uint8_t *out, size_t out_len) {
    return cx_hash(hash_context, CX_LAST, NULL, 0, out, out_len);
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

    uint8_t uncompressed_pubkey[65];
    crypto_get_uncompressed_pubkey(pubkey, uncompressed_pubkey);
}


/**
 * Computes the fingerprint of a compressed key.
 */
static uint32_t crypto_get_key_fingerprint(const uint8_t key[static 33]) {
    uint8_t key_rip[20];
    crypto_hash160(key, 33, key_rip);

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
