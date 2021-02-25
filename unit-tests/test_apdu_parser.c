#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "types.h"
#include "apdu/parser.h"

static void test_apdu_parser(void **state) {
    (void) state;
    uint8_t apdu_bad_min_len[] = {0xE0, 0x03, 0x00, 0x00};   // less than 5 bytes
    uint8_t apdu_bad_lc[] = {0xE0, 0x03, 0x00, 0x00, 0x01};  // Lc = 1 but no data
    uint8_t apdu[] = {0xE0, 0x03, 0x01, 0x02, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04};

    command_t cmd;

    memset(&cmd, 0, sizeof(cmd));
    assert_false(apdu_parser(&cmd, apdu_bad_min_len, sizeof(apdu_bad_min_len)));

    memset(&cmd, 0, sizeof(cmd));
    assert_false(apdu_parser(&cmd, apdu_bad_lc, sizeof(apdu_bad_min_len)));

    memset(&cmd, 0, sizeof(cmd));
    assert_true(apdu_parser(&cmd, apdu, sizeof(apdu)));
    assert_int_equal(cmd.cla, 0xE0);
    assert_int_equal(cmd.ins, 0x03);
    assert_int_equal(cmd.p1, 0x01);
    assert_int_equal(cmd.p2, 0x02);
    assert_int_equal(cmd.lc, 5);
    assert_memory_equal(cmd.data, ((uint8_t[]){0x00, 0x01, 0x02, 0x03, 0x04}), cmd.lc);
}

int main() {
    const struct CMUnitTest tests[] = {cmocka_unit_test(test_apdu_parser)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
