
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

#ifndef LCX_RIPEMD160_H
#define LCX_RIPEMD160_H

/** RIPEMD160 message digest size */
#define CX_RIPEMD160_SIZE 20

/**
 * RIPEMD-160 context
 */
struct cx_ripemd160_s {
  /** See #cx_hash_header_s */
  struct cx_hash_header_s header;
  /** @internal
   * pending partial block length
   */
  unsigned int blen;
  /** @internal
   * pending partial block
   */
  unsigned char block[64];
  /** Current digest state.
   * After finishing the digest, contains the digest if correct parameters are
   * passed.
   */
  unsigned char acc[5 * 4];
};
/** Convenience type. See #cx_ripemd160_s. */
typedef struct cx_ripemd160_s cx_ripemd160_t;

/**
 * Initialize a RIPEMD-160 context.
 *
 * @param [out] hash the context to init.
 *    The context shall be in RAM
 *
 * @return algorithm identifier
 */
CXCALL int
cx_ripemd160_init(cx_ripemd160_t *hash PLENGTH(sizeof(cx_ripemd160_t)));

#endif
