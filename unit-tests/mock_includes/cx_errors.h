#pragma once

/**
 * Mock cx_errors.h for unit tests.
 *
 * Provides CX error codes and _no_throw function declarations
 * used by musig.c and other crypto code.
 */

#include <stddef.h>
#include <stdint.h>

#include "lcx_common.h"
#include "ledger_assert.h"

/* Ensure CXCALL is defined before including headers that use it */
#ifndef CXCALL
#define CXCALL
#endif

#include "lcx_hash.h"
#include "lcx_sha256.h"
#include "lcx_ecfp.h"

/* CX error codes */
#define CX_OK                0x00000000u
#define CX_INTERNAL_ERROR    0xFFFFFF85u
#define CX_INVALID_PARAMETER 0xFFFFFF84u
#define CX_EC_INFINITE_POINT 0xFFFFFF41u

/* _no_throw variants of SDK crypto functions */

cx_err_t cx_hash_no_throw(cx_hash_t *hash,
                          int mode,
                          const unsigned char *in,
                          unsigned int len,
                          unsigned char *out,
                          unsigned int out_len);

cx_err_t cx_sha256_init_no_throw(cx_sha256_t *hash);

cx_err_t cx_math_modm_no_throw(unsigned char *v,
                               unsigned int len_v,
                               const unsigned char *m,
                               unsigned int len_m);

cx_err_t cx_math_cmp_no_throw(const unsigned char *a,
                              const unsigned char *b,
                              unsigned int len,
                              int *diff);

cx_err_t cx_math_sub_no_throw(unsigned char *r,
                              const unsigned char *a,
                              const unsigned char *b,
                              unsigned int len);

cx_err_t cx_math_multm_no_throw(unsigned char *r,
                                const unsigned char *a,
                                const unsigned char *b,
                                const unsigned char *m,
                                unsigned int len);

cx_err_t cx_math_addm_no_throw(unsigned char *r,
                               const unsigned char *a,
                               const unsigned char *b,
                               const unsigned char *m,
                               unsigned int len);

cx_err_t cx_ecfp_scalar_mult_no_throw(cx_curve_t curve,
                                      unsigned char *P,
                                      const unsigned char *k,
                                      unsigned int k_len);

cx_err_t cx_ecfp_add_point_no_throw(cx_curve_t curve,
                                    unsigned char *R,
                                    const unsigned char *P,
                                    const unsigned char *Q);
