#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>

#include <cmocka.h>

#include "common/bip32.h"

#define H 0x80000000u

static void test_bip32_format(void **state) {
    (void) state;

    char output[30];
    bool b = false;

    b = bip32_path_format((const uint32_t[5]){0x8000002C, 0x80000000, 0x80000000, 0, 0},
                          5,
                          output,
                          sizeof(output));
    assert_true(b);
    assert_string_equal(output, "44'/0'/0'/0/0");

    b = bip32_path_format((const uint32_t[5]){0x8000002C, 0x80000001, 0x80000000, 0, 0},
                          5,
                          output,
                          sizeof(output));
    assert_true(b);
    assert_string_equal(output, "44'/1'/0'/0/0");

    // No BIP32 path (=0)
    b = bip32_path_format(NULL, 0, output, sizeof(output));
    assert_true(b);
    assert_string_equal(output, "");
}

static void test_bad_bip32_format(void **state) {
    (void) state;

    char output[30];
    bool b = true;

    // More than MAX_BIP32_PATH_STEPS (=10)
    b = bip32_path_format(
        (const uint32_t[11]){0x8000002C, 0x80000000, 0x80000000, 0, 0, 0, 0, 0, 0, 0, 0},
        11,
        output,
        sizeof(output));
    assert_false(b);
}

static void test_bip32_read(void **state) {
    (void) state;

    // clang-format off
    uint8_t input[20] = {
        0x80, 0x00, 0x00, 0x2C,
        0x80, 0x00, 0x00, 0x01,
        0x80, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    uint32_t expected[5] = {0x8000002C, 0x80000001, 0x80000000, 0, 0};
    uint32_t output[5] = {0};
    bool b = false;

    b = bip32_path_read(input, sizeof(input), output, 5);
    assert_true(b);
    assert_memory_equal(output, expected, 5);

    // No BIP32 path
    assert_true(bip32_path_read(input, sizeof(input), output, 0));
}

static void test_bad_bip32_read(void **state) {
    (void) state;

    // clang-format off
    uint8_t input[20] = {
        0x80, 0x00, 0x00, 0x2C,
        0x80, 0x00, 0x00, 0x01,
        0x80, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    uint32_t output[10] = {0};

    // buffer too small (5 BIP32 paths instead of 10)
    assert_false(bip32_path_read(input, sizeof(input), output, 10));

    // More than MAX_BIP32_PATH_STEPS (=10)
    assert_false(bip32_path_read(input, sizeof(input), output, 20));
}


static void test_is_pubkey_path_standard_true(void **state) {
    (void) state;

    const uint32_t valid_purposes[] = {44, 49, 84};
    const uint32_t coin_types[] = {0, 8};

    for (int i_p = 0; i_p < sizeof(valid_purposes)/sizeof(valid_purposes[0]); i_p++) {
        uint32_t purpose = valid_purposes[i_p];

        // any coin type will do, if coin_types is not given
        assert_true(is_pubkey_path_standard((const uint32_t[]){purpose^H, 12345^H}, 2, purpose, NULL, 0));
        assert_true(is_pubkey_path_standard((const uint32_t[]){purpose^H, 12345^H, 0^H}, 3, purpose, NULL, 0));

        for (int i_c = 0; i_c < sizeof(coin_types)/sizeof(coin_types[0]); i_c++) {
            uint32_t coin_type = coin_types[i_c];

            assert_true(is_pubkey_path_standard((const uint32_t[]){purpose^H, coin_type^H, 0^H}, 3, purpose, coin_types, 2));
        }
    }
}

static void test_is_pubkey_path_standard_false(void **state) {
    (void) state;

    const uint32_t coin_types[] = {0, 8};

    // path too short
    assert_false(is_pubkey_path_standard(NULL, 0, 44, coin_types, 2));
    assert_false(is_pubkey_path_standard(NULL, 0, 44, NULL, 0));
    assert_false(is_pubkey_path_standard((const uint32_t[]){44^H}, 1, 44, coin_types, 2));
    assert_false(is_pubkey_path_standard((const uint32_t[]){44^H}, 1, 44, NULL, 0));

    // wrong purpose
    assert_false(is_pubkey_path_standard((const uint32_t[]){45^H, 0^H}, 2, 44, coin_types, 2));
    // non-hardened purpose
    assert_false(is_pubkey_path_standard((const uint32_t[]){44, 0^H}, 2, 44, coin_types, 2));

    // invalid coin type
    assert_false(is_pubkey_path_standard((const uint32_t[]){44^H, 100^H, 0^H}, 3, 44, coin_types, 2));
    // non-hardened coin type (but otherwise in coin_types)
    assert_false(is_pubkey_path_standard((const uint32_t[]){44^H, 8, 0^H}, 3, 44, coin_types, 2));
    // should still check that coin type is hardened, even if coin_types is not given
    assert_false(is_pubkey_path_standard((const uint32_t[]){44^H, 0, 0^H}, 3, 44, NULL, 0));

    // account too big
    assert_false(is_pubkey_path_standard((const uint32_t[]){44^H, 0^H, (1 + MAX_BIP44_ACCOUNT_RECOMMENDED)^H}, 3, 44, coin_types, 2));
    // account not hardened
    assert_false(is_pubkey_path_standard((const uint32_t[]){44^H, 0^H, 0}, 3, 44, coin_types, 2));
}


int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_bip32_format),
        cmocka_unit_test(test_bad_bip32_format),
        cmocka_unit_test(test_bip32_read),
        cmocka_unit_test(test_bad_bip32_read),
        cmocka_unit_test(test_is_pubkey_path_standard_true),
        cmocka_unit_test(test_is_pubkey_path_standard_false)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
