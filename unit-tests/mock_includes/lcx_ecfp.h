
/*******************************************************************************
*   Ledger Nano S - Secure firmware
*   (c) 2019 Ledger
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
********************************************************************************/

#ifndef LCX_ECFP_H
#define LCX_ECFP_H

/**
 *
 */
#define CX_ECCINFO_PARITY_ODD 1
#define CX_ECCINFO_xGTn 2

/** List of supported elliptic curves */
enum cx_curve_e {
  CX_CURVE_NONE,
  /* ------------------------ */
  /* --- Type Weierstrass --- */
  /* ------------------------ */
  /** Low limit (not included) of Weierstrass curve ID */
  CX_CURVE_WEIERSTRASS_START = 0x20,

  /** Secp.org */
  CX_CURVE_SECP256K1,
  CX_CURVE_SECP256R1,
#define CX_CURVE_256K1 CX_CURVE_SECP256K1
#define CX_CURVE_256R1 CX_CURVE_SECP256R1
  CX_CURVE_SECP384R1,
  CX_CURVE_SECP521R1,

  /** BrainPool */
  CX_CURVE_BrainPoolP256T1,
  CX_CURVE_BrainPoolP256R1,
  CX_CURVE_BrainPoolP320T1,
  CX_CURVE_BrainPoolP320R1,
  CX_CURVE_BrainPoolP384T1,
  CX_CURVE_BrainPoolP384R1,
  CX_CURVE_BrainPoolP512T1,
  CX_CURVE_BrainPoolP512R1,

/* NIST P256 curve*/
#define CX_CURVE_NISTP256 CX_CURVE_SECP256R1
#define CX_CURVE_NISTP384 CX_CURVE_SECP384R1
#define CX_CURVE_NISTP521 CX_CURVE_SECP521R1

  /* ANSSI P256 */
  CX_CURVE_FRP256V1,

  /* STARK */
  CX_CURVE_Stark256,

  /* BLS */
  CX_CURVE_BLS12_381_G1,

  /** High limit (not included) of Weierstrass curve ID */
  CX_CURVE_WEIERSTRASS_END,

  /* --------------------------- */
  /* --- Type Twister Edward --- */
  /* --------------------------- */
  /** Low limit (not included) of  Twister Edward curve ID */
  CX_CURVE_TWISTED_EDWARD_START = 0x40,

  /** Ed25519 curve */
  CX_CURVE_Ed25519,
  CX_CURVE_Ed448,

  CX_CURVE_TWISTED_EDWARD_END,
  /** High limit (not included) of Twister Edward  curve ID */

  /* ----------------------- */
  /* --- Type Montgomery --- */
  /* ----------------------- */
  /** Low limit (not included) of Montgomery curve ID */
  CX_CURVE_MONTGOMERY_START = 0x60,

  /** Curve25519 curve */
  CX_CURVE_Curve25519,
  CX_CURVE_Curve448,

  CX_CURVE_MONTGOMERY_END
  /** High limit (not included) of Montgomery curve ID */
};
/** Convenience type. See #cx_curve_e. */
typedef enum cx_curve_e cx_curve_t;

/** Return true if curve type is short weierstrass curve */
#define CX_CURVE_IS_WEIRSTRASS(c)                                              \
  (((c) > CX_CURVE_WEIERSTRASS_START) && ((c) < CX_CURVE_WEIERSTRASS_END))

/** Return true if curve type is short weierstrass curve */
#define CX_CURVE_IS_TWISTED_EDWARD(c)                                          \
  (((c) > CX_CURVE_TWISTED_EDWARD_START) && ((c) < CX_CURVE_TWISTED_EDWARD_END))

/** Return true if curve type is short weierstrass curve */
#define CX_CURVE_IS_MONTGOMERY(c)                                              \
  (((c) > CX_CURVE_MONTGOMERY_START) && ((c) < CX_CURVE_MONTGOMERY_END))

#define CX_CURVE_HEADER                                                        \
  /** Curve Identifier. See #cx_curve_e */                                     \
  cx_curve_t curve;                                                            \
  /** Curve size in bits */                                                    \
  unsigned int bit_size;                                                       \
  /** component lenth in bytes */                                              \
  unsigned int length;                                                         \
  /** Curve field */                                                           \
  unsigned char WIDE *p;                                                       \
  /** @internal 2nd Mongtomery constant for Field */                           \
  unsigned char WIDE *Hp;                                                      \
  /** Point Generator x coordinate*/                                           \
  unsigned char WIDE *Gx;                                                      \
  /** Point Generator y coordinate*/                                           \
  unsigned char WIDE *Gy;                                                      \
  /** Curve order*/                                                            \
  unsigned char WIDE *n;                                                       \
  /** @internal 2nd Mongtomery constant for Curve order*/                      \
  unsigned char WIDE *Hn;                                                      \
  /**  cofactor */                                                             \
  int h

/**
 * Weirstrass curve :     y^3=x^2+a*x+b        over F(p)
 *
 */
struct cx_curve_weierstrass_s {
  CX_CURVE_HEADER;
  /**  a coef */
  unsigned char WIDE *a;
  /**  b coef */
  unsigned char WIDE *b;
};
/** Convenience type. See #cx_curve_weierstrass_s. */
typedef struct cx_curve_weierstrass_s cx_curve_weierstrass_t;

/*
 * Twisted Edward curve : a*x^2+y^2=1+d*x2*y2  over F(q)
 */
struct cx_curve_twisted_edward_s {
  CX_CURVE_HEADER;
  /**  a coef */
  unsigned char WIDE *a;
  /**  d coef */
  unsigned char WIDE *d;
  /** @internal Square root of -1 or zero */
  unsigned char WIDE *I;
  /** @internal  (q+3)/8 or (q+1)/4*/
  unsigned char WIDE *Qq;
};
/** Convenience type. See #cx_curve_twisted_edward_s. */
typedef struct cx_curve_twisted_edward_s cx_curve_twisted_edward_t;

/*
 * Twisted Edward curve : a*x??+y??=1+d*x??*y??  over F(q)
 */
struct cx_curve_montgomery_s {
  CX_CURVE_HEADER;
  /**  a coef */
  unsigned char WIDE *a;
  /**  b coef */
  unsigned char WIDE *b;
  /** @internal (a + 2) / 4*/
  unsigned char WIDE *A24;
  /** @internal  (p-1)/2 */
  unsigned char WIDE *P1;
};
/** Convenience type. See #cx_curve_montgomery_s. */
typedef struct cx_curve_montgomery_s cx_curve_montgomery_t;

/** Abstract type for elliptic curve domain */
struct cx_curve_domain_s {
  CX_CURVE_HEADER;
};
/** Convenience type. See #cx_curve_domain_s. */
typedef struct cx_curve_domain_s cx_curve_domain_t;

/** Retrieve domain parameters
 *
 * @param curve curve ID #cx_curve_e
 *
 * @return curve parameters
 */
const cx_curve_domain_t WIDE *cx_ecfp_get_domain(cx_curve_t curve);

/** Public Elliptic Curve key */
struct cx_ecfp_public_key_s {
  /** curve ID #cx_curve_e */
  cx_curve_t curve;
  /** Public key length in bytes */
  unsigned int W_len;
  /** Public key value starting at offset 0 */
  unsigned char W[1];
};
/** Private Elliptic Curve key */
struct cx_ecfp_private_key_s {
  /** curve ID #cx_curve_e */
  cx_curve_t curve;
  /** Public key length in bytes */
  unsigned int d_len;
  /** Public key value starting at offset 0 */
  unsigned char d[1];
};
// temporary typedef for scc check
typedef struct cx_ecfp_private_key_s __cx_ecfp_private_key_t;
typedef struct cx_ecfp_public_key_s __cx_ecfp_public_key_t;

/** Up to 256 bits Public Elliptic Curve key */
struct cx_ecfp_256_public_key_s {
  /** curve ID #cx_curve_e */
  cx_curve_t curve;
  /** Public key length in bytes */
  unsigned int W_len;
  /** Public key value starting at offset 0 */
  unsigned char W[65];
};
/** Up to 256 bits Private Elliptic Curve key */
struct cx_ecfp_256_private_key_s {
  /** curve ID #cx_curve_e */
  cx_curve_t curve;
  /** Public key length in bytes */
  unsigned int d_len;
  /** Public key value starting at offset 0 */
  unsigned char d[32];
};
/** Up to 256 bits Extended Private Elliptic Curve key */
struct cx_ecfp_256_extended_private_key_s {
  /** curve ID #cx_curve_e */
  cx_curve_t curve;
  /** Public key length in bytes */
  unsigned int d_len;
  /** Public key value starting at offset 0 */
  unsigned char d[64];
};
/** Convenience type. See #cx_ecfp_256_public_key_s. */
typedef struct cx_ecfp_256_public_key_s cx_ecfp_256_public_key_t;
/** temporary def type. See #cx_ecfp_256_private_key_s. */
typedef struct cx_ecfp_256_private_key_s cx_ecfp_256_private_key_t;
/** Convenience type. See #cx_ecfp_256_extended_private_key_s. */
typedef struct cx_ecfp_256_extended_private_key_s
    cx_ecfp_256_extended_private_key_t;

/* Do not use those types anymore for declaration, they will become abstract */
typedef struct cx_ecfp_256_public_key_s cx_ecfp_public_key_t;
typedef struct cx_ecfp_256_private_key_s cx_ecfp_private_key_t;

/** Up to 384 bits Public Elliptic Curve key */
struct cx_ecfp_384_public_key_s {
  /** curve ID #cx_curve_e */
  cx_curve_t curve;
  /** Public key length in bytes */
  unsigned int W_len;
  /** Public key value starting at offset 0 */
  unsigned char W[97];
};
/** Up to 384 bits Private Elliptic Curve key */
struct cx_ecfp_384_private_key_s {
  /** curve ID #cx_curve_e */
  cx_curve_t curve;
  /** Public key length in bytes */
  unsigned int d_len;
  /** Public key value starting at offset 0 */
  unsigned char d[48];
};
/** Convenience type. See #cx_ecfp_384_public_key_s. */
typedef struct cx_ecfp_384_private_key_s cx_ecfp_384_private_key_t;
/** Convenience type. See #cx_ecfp_384_private_key_s. */
typedef struct cx_ecfp_384_public_key_s cx_ecfp_384_public_key_t;

/** Up to 512 bits Public Elliptic Curve key */
struct cx_ecfp_512_public_key_s {
  /** curve ID #cx_curve_e */
  cx_curve_t curve;
  /** Public key length in bytes */
  unsigned int W_len;
  /** Public key value starting at offset 0 */
  unsigned char W[129];
};
/** Up to 512 bits Private Elliptic Curve key */
struct cx_ecfp_512_private_key_s {
  /** curve ID #cx_curve_e */
  cx_curve_t curve;
  /** Public key length in bytes */
  unsigned int d_len;
  /** Public key value starting at offset 0 */
  unsigned char d[64];
};
/** Up to 512 bits Extended Private Elliptic Curve key */
struct cx_ecfp_512_extented_private_key_s {
  /** curve ID #cx_curve_e */
  cx_curve_t curve;
  /** Public key length in bytes */
  unsigned int d_len;
  /** Public key value starting at offset 0 */
  unsigned char d[128];
};
/** Convenience type. See #cx_ecfp_512_public_key_s. */
typedef struct cx_ecfp_512_public_key_s cx_ecfp_512_public_key_t;
/** Convenience type. See #cx_ecfp_512_private_key_s. */
typedef struct cx_ecfp_512_private_key_s cx_ecfp_512_private_key_t;
/** Convenience type. See #cx_ecfp_512_extented_private_key_s. */
typedef struct cx_ecfp_512_extented_private_key_s
    cx_ecfp_512_extented_private_key_t;

/** Up to 640 bits Public Elliptic Curve key */
struct cx_ecfp_640_public_key_s {
  /** curve ID #cx_curve_e */
  cx_curve_t curve;
  /** Public key length in bytes */
  unsigned int W_len;
  /** Public key value starting at offset 0 */
  unsigned char W[161];
};
/** Up to 640 bits Private Elliptic Curve key */
struct cx_ecfp_640_private_key_s {
  /** curve ID #cx_curve_e */
  cx_curve_t curve;
  /** Public key length in bytes */
  unsigned int d_len;
  /** Public key value starting at offset 0 */
  unsigned char d[80];
};
/** Convenience type. See #cx_ecfp_640_public_key_s. */
typedef struct cx_ecfp_640_public_key_s cx_ecfp_640_public_key_t;
/** Convenience type. See #cx_ecfp_640_private_key_s. */
typedef struct cx_ecfp_640_private_key_s cx_ecfp_640_private_key_t;

/**
 * Verify that a given point is really on the specified curve.
 *
 * @param [in] domain
 *   The curve domain parameters to work with.
 *
 * @param [in]  P
 *   The point to test  encoded as: 04 x y
 *
 * @return
 *    1 if point is on the curve
 *    0 if point is not on the curve
 *   -1 if undefined (function not impl)
 *
 * @throws INVALID_PARAMETER
 */
CXCALL int cx_ecfp_is_valid_point(cx_curve_t curve,
                                  const unsigned char WIDE *P PLENGTH(P_len),
                                  unsigned int P_len);

/**
 * Verify that a given point is really on the specified curve and its order
 * is the curve order
 *
 * @param [in] domain
 *   The curve domain parameters to work with.
 *
 * @param [in]  public_point
 *   The point to test  encoded as: 04 x y
 *
 * @return
 *    1 if point is on the curve
 *    0 if point is not on the curve
 *   -1 if undefined (function not impl)
 *
 * @throws INVALID_PARAMETER
 */
CXCALL int
cx_ecfp_is_cryptographic_point(cx_curve_t curve,
                               const unsigned char WIDE *P PLENGTH(P_len),
                               unsigned int P_len);

/**
 * Add two affine point
 *
 * This routine only support Weierstrass and Twisted edward curve.
 *
 * @param [in] domain
 *   The curve domain parameters to work with.
 *
 * @param [out] R
 *   P+Q encoded as: 04 x y, where x and y are
 *   encoded as  big endian raw value and have bits length equals to
 *   the curve size.
 *
 * @param [in] P
 *   First point to add *
 *   The value shall be a point encoded as: 04 x y, where x and y are
 *   encoded as  big endian raw value and have bits length equals to
 *   the curve size.
 *
 * @param [in] Q
 *   Second point to add
 *
 * @param [in]  public_point
 *   The point to test  encoded as: 04 x y
 *
 * @return
 *   R encoding length, if add success
 *   0 if result is infinity
 *
 * @throws INVALID_PARAMETER
 */
CXCALL int cx_ecfp_add_point(cx_curve_t curve, unsigned char *R PLENGTH(X_len),
                             const unsigned char WIDE *P PLENGTH(X_len),
                             const unsigned char WIDE *Q PLENGTH(X_len),
                             unsigned int X_len);

/**
 * Multiply an affine point
 *
 * @param [in] domain
 *   The curve domain parameters to work with.
 *
 * @param [out] R
 *   R = k.P encoded as: 04 x y, where x and y are
 *   encoded as  big endian raw value and have bits length equals to
 *   the curve size.
 *
 * @param [in] P
 *   Point to multiply *
 *   The value shall be a point encoded as: 04 x y, where x and y are
 *   encoded as  big endian raw value and have bits length equals to
 *   the curve size.
 *
 * @param [in] k
 *   scalar to multiply, encoded as big endian integer
 *
 * @param [in] k_len
 *   byte length of scalar to multiply
 *
 * @return
 *   R encoding length, if mult success
 *   0 if result is infinity
 *
 * @throws INVALID_PARAMETER
 */
CXCALL int cx_ecfp_scalar_mult(cx_curve_t curve,
                               unsigned char *P PLENGTH(P_len),
                               unsigned int P_len,
                               const unsigned char WIDE *k PLENGTH(k_len),
                               unsigned int k_len);

/**
 * Initialize a public ECFP Key.
 * Once initialized, the key may be stored in non-volatile memory
 * an reused 'as-is' for any ECDSA/25519 processing
 * Passing NULL as raw key initializes the key without value. The key may be
 used
 * as parameter for cx_ecfp_generate_pair.

 * @param [in] curve
 *   The curve domain parameters to work with.
 *
 * @param [in] rawkey
 *   Raw key value or NULL.
 *   The value shall be the public point encoded as:
 *     - '04 x y' for Weiertrass curve
 *     - '04 x y'  or '02 y' (plus sign) for twisted Edward curves
 *     - '04 x y'  or '02 x' for Montgomery curves
 *    where x and y are encoded as big endian raw value and have bits length
 *    equals to the curve size. Any specific integer decoding from binary,
 *    such as specified in RFC7748 and RFC eddsa-draft, is up to caller.
 *
 * @param [in] key_len
 *   Key bytes lenght
 *
 * @param [out] key
 *   Public ecfp key to init.
 *
 * @param key
 *   Ready to use key to init
 *
 * @return something
 *
 * @throws INVALID_PARAMETER
 */

CXCALL int cx_ecfp_init_public_key(
    cx_curve_t curve, const unsigned char WIDE *rawkey PLENGTH(key_len),
    unsigned int key_len,
    cx_ecfp_public_key_t *key
        PLENGTH(scc__cx_scc_struct_size_ecfp_pubkey_from_curve__curve));

/**
 * Initialize a private ECFP Key.
 * Once initialized, the key may be  stored in non-volatile memory
 * and reused 'as-is' for any ECDSA/EC25519 processing
 * Passing NULL as raw key initializes the key without value. The key may be
 * used as parameter for cx_ecfp_generate_pair.
 *
 * @param [in] curve
 *   The curve domain parameters to work with.
 *
 * @param [in] rawkey
 *   Raw key value or NULL.
 *   The value shall be the private key big endian raw value.
 *
 * @param [in] key_len
 *   Key bytes lenght
 *
 * @param [out] pvkey
 *   Private ecfp key to init.
 *
 * @param key
 *   Ready to use key to init
 *
 * @return something
 *
 * @throws INVALID_PARAMETER
 */
CXCALL int cx_ecfp_init_private_key(
    cx_curve_t curve, const unsigned char WIDE *rawkey PLENGTH(key_len),
    unsigned int key_len,
    cx_ecfp_private_key_t *pvkey
        PLENGTH(scc__cx_scc_struct_size_ecfp_privkey_from_curve__curve));

/**
 * Generate a ecfp key pair.
 * This function call cx_ecfp_generate_pair2 with hashID equals to CX_SHA512.
 *
 * @param [in] curve
 *   The curve domain parameters to work with.
 *
 * @param [out] pubkey
 *   A public ecfp public key to generate.
 *
 * @param [in,out] privkey
 *   A private ecfp private key to generate.
 *   Either:
 *     - if the private ecfp key is fully inited, i.e  parameter 'rawkey' of
 *       'cx_ecfp_init_private_key' is NOT null, the private key value is kept
 *       if the 'keep_private' parameter is non zero
 *     - else a new private key is generated.
 *
 * @param [in] keepprivate if set to non zero, keep the private key value if
 * set. Else generate a new random one
 *
 * @return zero
 *
 * @throws INVALID_PARAMETER
 */
CXCALL int cx_ecfp_generate_pair(
    cx_curve_t curve,
    cx_ecfp_public_key_t *pubkey
        PLENGTH(scc__cx_scc_struct_size_ecfp_pubkey_from_curve__curve),
    cx_ecfp_private_key_t *privkey
        PLENGTH(scc__cx_scc_struct_size_ecfp_privkey_from_curve__curve),
    int keepprivate);

/**
 * Generate a ecfp key pair
 *
 * @param [in] curve
 *   The curve domain parameters to work with.
 *
 * @param [out] pubkey
 *   A public ecfp public key to generate.
 *
 * @param [in,out] privkey
 *   A private ecfp private key to generate.
 *   Either:
 *     - if the private ecfp key is fully inited, i.e  parameter 'rawkey' of
 *       'cx_ecfp_init_private_key' is NOT null, the private key value is kept
 *       if the 'keep_private' parameter is non zero
 *     - else a new private key is generated.
 *
 * @param [in] keepprivate if set to non zero, keep the private key value if
 * set. Else generate a new random one
 *
 *  @param [in] hashID Hash to use for eddsa (SHA512, SHA3 and Keccak are
 * supported)
 *
 * @return zero
 *
 * @throws INVALID_PARAMETER
 */
CXCALL int cx_ecfp_generate_pair2(
    cx_curve_t curve,
    cx_ecfp_public_key_t *pubkey
        PLENGTH(scc__cx_scc_struct_size_ecfp_pubkey_from_curve__curve),
    cx_ecfp_private_key_t *privkey
        PLENGTH(scc__cx_scc_struct_size_ecfp_privkey_from_curve__curve),
    int keepprivate, cx_md_t hashID);

#endif
