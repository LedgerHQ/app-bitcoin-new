
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

#ifndef LCX_COMMON_H
#define LCX_COMMON_H

#include <stdint.h>

#ifndef NATIVE_64BITS // NO 64BITS
/** 64bits types, native or by-hands, depending on target and/or compiler
 * support.
 * This type is defined here only because sha-3 struct used it INTENALLY.
 * It should never be directly used by other modules.
 */
struct uint64_s {
#ifdef OS_LITTLE_ENDIAN
  unsigned long int l;
  unsigned long int h;
#else
  unsigned long int h;
  unsigned long int l;
#endif
};
typedef struct uint64_s uint64bits_t;
#else
typedef uint64_t uint64bits_t;
#endif

/**
 * Some function take logical or of various flags. The follwing flags are
 * globally defined:
 * @rststar
 *
 *  +------------+----------------------------+------------------------------------------------------------------+
 *  | bit pos    |  H constant                |   meanings |
 *  +============+============================+==================================================================+
 *  |  0         | - CX_LAST                  | last block |
 *  +------------+----------------------------+------------------------------------------------------------------+
 *  |  2:1       | - CX_ENCRYPT               | | |            | - CX_DECRYPT |
 * | |            | - CX_SIGN                  | | |            | - CX_VERIFY |
 * |
 *  +------------+----------------------------+------------------------------------------------------------------+
 *  |  5:3       | - CX_PAD_NONE              | | |            | -
 * CX_PAD_ISO9797M1         | | |            | - CX_PAD_ISO9797M2         | | |
 * | - CX_PAD_PKCS1_1o5         | | |            | - CX_PAD_PKCS1_PSS         |
 * | |            | - CX_PAD_PKCS1_OAEP        | |
 *  +------------+----------------------------+------------------------------------------------------------------+
 *  |  8:6       | - CX_CHAIN_ECB             | | |            | - CX_CHAIN_CBC
 * |                                                                  | |  -DES
 * | - CX_CHAIN_CTR             | | |  -AES      | - CX_CHAIN_CFB             |
 * | |            | - CX_CHAIN_OFB             | |
 *  +------------+----------------------------+------------------------------------------------------------------+
 *  |  8:6       | - CX_NO_CANONICAL          | do not perform canonical sig |
 *  |            |                            | | | -ECDSA     | | | | -EDDSA |
 * |                                                                  | |
 * -ECSCHNORR |                            | |
 *  +------------+----------------------------+------------------------------------------------------------------+
 *  |  11:9      | - CX_RND_TRNG              | | |            | - CX_RND_PRNG
 * |                                                                  | | | -
 * CX_RND_RFC6979           | | |            | - CX_RND_PROVIDED          | |
 *  +------------+----------------------------+------------------------------------------------------------------+
 *  |  14:12     | - CX_ECDH_POINT            | share full point | | | -
 * CX_ECDH_X                | share only x coordinate | |            | -
 * CX_ECSCHNORR_BSI03111    | | |            | - CX_ECSCHNORR_ISO14888_XY | | |
 * | - CX_ECSCHNORR_ISO14888_X  | | |            |  -CX_ECSCHNORR_LIBSECP     |
 * | |            |  -CX_ECSCHNORR_Zfrai de port           | Zilliqa scheme |
 *  +------------+----------------------------+------------------------------------------------------------------+
 *  |  15        | CX_NO_REINIT               | do not reinitialize context on
 * CX_LAST when supported            |
 *  +------------+----------------------------+------------------------------------------------------------------+
 *
 * @endrststar
 */
#define CX_FLAG

/*
 * Bit 0
 */
#define CX_LAST (1 << 0)

/*
 * Bit 1
 */
#define CX_SIG_MODE (1 << 1)

/*
 * Bit 2:1
 */
#define CX_MASK_SIGCRYPT (3 << 1)
#define CX_ENCRYPT (2 << 1)
#define CX_DECRYPT (0 << 1)
#define CX_SIGN (CX_SIG_MODE | CX_ENCRYPT)
#define CX_VERIFY (CX_SIG_MODE | CX_DECRYPT)

/*
 * Bit 5:3: padding
 */
#define CX_MASK_PAD (7 << 3)
#define CX_PAD_NONE (0 << 3)
#define CX_PAD_ISO9797M1 (1 << 3)
#define CX_PAD_ISO9797M2 (2 << 3)
#define CX_PAD_PKCS1_1o5 (3 << 3)
#define CX_PAD_PKCS1_PSS (4 << 3)
#define CX_PAD_PKCS1_OAEP (5 << 3)

/*
 * Bit 8:6 DES/AES chaining
 */
#define CX_MASK_CHAIN (7 << 6)
#define CX_CHAIN_ECB (0 << 6)
#define CX_CHAIN_CBC (1 << 6)
#define CX_CHAIN_CTR (2 << 6)
#define CX_CHAIN_CFB (3 << 6)
#define CX_CHAIN_OFB (4 << 6)

/*
 * Bit 8:6 ECC variant
 */
#define CX_MASK_ECC_VARIANT (7 << 6)
#define CX_NO_CANONICAL (1 << 6)

/*
 * Bit 11:9
 */
#define CX_MASK_RND (7 << 9)
#define CX_RND_PRNG (1 << 9)
#define CX_RND_TRNG (2 << 9)
#define CX_RND_RFC6979 (3 << 9)
#define CX_RND_PROVIDED (4 << 9)

/*
 * Bit 14:12
 */
#define CX_MASK_EC (7 << 12)
#define CX_ECDH_POINT (1 << 12)
#define CX_ECDH_X (2 << 12)
#define CX_ECSCHNORR_ISO14888_XY (3 << 12)
#define CX_ECSCHNORR_ISO14888_X (4 << 12)
#define CX_ECSCHNORR_BSI03111 (5 << 12)
#define CX_ECSCHNORR_LIBSECP (6 << 12)
#define CX_ECSCHNORR_Z (7 << 12)
/*
 * Bit 15
 */
#define CX_NO_REINIT (1 << 15)

#endif
