#include <stdbool.h>

#include "musig.h"

#include "../crypto.h"
#include "../secp256k1.h"

static const uint8_t BIP0327_keyagg_coeff_tag[] =
    {'K', 'e', 'y', 'A', 'g', 'g', ' ', 'c', 'o', 'e', 'f', 'f', 'i', 'c', 'i', 'e', 'n', 't'};
static const uint8_t BIP0327_keyagg_list_tag[] =
    {'K', 'e', 'y', 'A', 'g', 'g', ' ', 'l', 'i', 's', 't'};

static inline bool is_point_infinite(const point_t *P) {
    return P->prefix == 0;
}

static inline void set_point_infinite(point_t *P) {
    memset(P->raw, 0, sizeof(point_t));
}

static int point_add(const point_t *P1, const point_t *P2, point_t *out) {
    if (is_point_infinite(P1)) {
        memmove(out->raw, P2->raw, sizeof(point_t));
        return CX_OK;
    }
    if (is_point_infinite(P2)) {
        memmove(out->raw, P1->raw, sizeof(point_t));
        return CX_OK;
    }
    if (memcmp(P1->x, P2->x, 32) == 0 && memcmp(P1->y, P2->y, 32) != 0) {
        memset(out->raw, 0, sizeof(point_t));
        return CX_OK;
    }
    return cx_ecfp_add_point_no_throw(CX_CURVE_SECP256K1, out->raw, P1->raw, P2->raw);
}

// out can be equal to P
static int point_negate(const point_t *P, point_t *out) {
    if (is_point_infinite(P)) {
        set_point_infinite(out);
        return 0;
    }
    memmove(out->x, P->x, 32);

    if (CX_OK != cx_math_sub_no_throw(out->y, secp256k1_p, P->y, 32)) return -1;

    out->prefix = 4;
    return 0;
}

static int cpoint(const uint8_t x[33], point_t *out) {
    crypto_tr_lift_x(&x[1], out->raw);
    if (is_point_infinite(out)) {
        PRINTF("Invalid compressed point\n");
        return -1;
    }
    if (x[0] == 2) {
        return 0;
    } else if (x[0] == 3) {
        if (0 > point_negate(out, out)) {
            return -1;
        }
        return 0;
    } else {
        PRINTF("Invalid compressed point: invalid prefix\n");
        return -1;
    }
}

static void musig_get_second_key(const plain_pk_t pubkeys[], size_t n_keys, plain_pk_t out) {
    for (size_t i = 0; i < n_keys; i++) {
        if (memcmp(pubkeys[0], pubkeys[i], sizeof(plain_pk_t)) != 0) {
            memcpy(out, pubkeys[i], sizeof(plain_pk_t));
            return;
        }
    }
    memset(out, 0, sizeof(plain_pk_t));
}

static void musig_hash_keys(const plain_pk_t pubkeys[], size_t n_keys, uint8_t out[static 32]) {
    cx_sha256_t hash_context;
    crypto_tr_tagged_hash_init(&hash_context,
                               BIP0327_keyagg_list_tag,
                               sizeof(BIP0327_keyagg_list_tag));
    for (size_t i = 0; i < n_keys; i++) {
        crypto_hash_update(&hash_context.header, pubkeys[i], sizeof(plain_pk_t));
    }
    crypto_hash_digest(&hash_context.header, out, 32);
}

static void musig_key_agg_coeff_internal(const plain_pk_t pubkeys[],
                                         size_t n_keys,
                                         const plain_pk_t pk_,
                                         const plain_pk_t pk2,
                                         uint8_t out[static CX_SHA256_SIZE]) {
    uint8_t L[CX_SHA256_SIZE];
    musig_hash_keys(pubkeys, n_keys, L);
    if (memcmp(pk_, pk2, sizeof(plain_pk_t)) == 0) {
        memset(out, 0, CX_SHA256_SIZE);
        out[31] = 1;
    } else {
        crypto_tr_tagged_hash(BIP0327_keyagg_coeff_tag,
                              sizeof(BIP0327_keyagg_coeff_tag),
                              L,
                              sizeof(L),
                              pk_,
                              sizeof(plain_pk_t),
                              out);

        // result modulo secp256k1_n
        int res = cx_math_modm_no_throw(out, CX_SHA256_SIZE, secp256k1_n, sizeof(secp256k1_n));

        LEDGER_ASSERT(res == CX_OK, "Modular reduction failed");
    }
}

int musig_key_agg(const plain_pk_t pubkeys[], size_t n_keys, musig_keyagg_context_t *ctx) {
    plain_pk_t pk2;
    musig_get_second_key(pubkeys, n_keys, pk2);

    set_point_infinite(&ctx->Q);
    for (size_t i = 0; i < n_keys; i++) {
        point_t P;

        // set P := P_i
        if (0 > cpoint(pubkeys[i], &P)) {
            PRINTF("Invalid pubkey in musig_key_agg\n");
            return -1;
        }

        uint8_t a_i[32];
        musig_key_agg_coeff_internal(pubkeys, n_keys, pubkeys[i], pk2, a_i);

        // set P := a_i * P_i
        if (CX_OK != cx_ecfp_scalar_mult_no_throw(CX_CURVE_SECP256K1, P.raw, a_i, 32)) {
            PRINTF("Scalar multiplication failed in musig_key_agg\n");
            return -1;
        }

        point_add(&ctx->Q, &P, &ctx->Q);
    }
    memset(ctx->tacc, 0, sizeof(ctx->tacc));
    memset(ctx->gacc, 0, sizeof(ctx->gacc));
    ctx->gacc[31] = 1;
    return 0;
}
