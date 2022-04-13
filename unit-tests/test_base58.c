#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "common/base58.h"

static void test_base58(void **state) {
    (void) state;

    const char in[] = "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z";
    const char expected_out[] = "The quick brown fox jumps over the lazy dog.";
    uint8_t out[100] = {0};
    int out_len = base58_decode(in, sizeof(in) - 1, out, sizeof(out));
    assert_int_equal(out_len, strlen(expected_out));
    assert_string_equal((char *) out, expected_out);

    const char in2[] = "The quick brown fox jumps over the lazy dog.";
    const char expected_out2[] = "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z";
    char out2[100] = {0};
    int out_len2 = base58_encode((uint8_t *) in2, sizeof(in2) - 1, out2, sizeof(out2));
    assert_int_equal(out_len2, strlen(expected_out2));
    assert_string_equal((char *) out2, expected_out2);
}

int main() {
    const struct CMUnitTest tests[] = {cmocka_unit_test(test_base58)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
