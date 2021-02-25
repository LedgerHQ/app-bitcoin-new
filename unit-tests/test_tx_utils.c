#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "transaction/utils.h"
#include "transaction/types.h"

static void test_tx_utils(void **state) {
    (void) state;

    const uint8_t good_ascii[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21};  // Hello!
    const uint8_t bad_ascii[] = {0x32, 0xc3, 0x97, 0x32, 0x3d, 0x34};   // 2×2=4

    assert_true(transaction_utils_check_encoding(good_ascii, sizeof(good_ascii)));
    assert_false(transaction_utils_check_encoding(bad_ascii, sizeof(bad_ascii)));

    char output[MAX_MEMO_LEN] = {0};
    assert_true(transaction_utils_format_memo(good_ascii,          //
                                              sizeof(good_ascii),  //
                                              output,              //
                                              sizeof(output)));
    assert_string_equal(output, "Hello!");
    assert_false(transaction_utils_format_memo(good_ascii,            //
                                               sizeof(good_ascii),    //
                                               output,                //
                                               sizeof(good_ascii)));  // dst_len too small
}

int main() {
    const struct CMUnitTest tests[] = {cmocka_unit_test(test_tx_utils)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
