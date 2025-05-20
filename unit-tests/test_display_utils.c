#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "ui/display_utils.h"

static const struct {
    const char *coin;
    uint64_t amount;
    const char *expected;
} sats_testcases[] = {
    {.coin = "BTC", .amount = 0LLU, .expected = "0 BTC"},
    {.coin = "BTC", .amount = 1LLU, .expected = "0.00000001 BTC"},
    {.coin = "BTC", .amount = 10LLU, .expected = "0.0000001 BTC"},
    {.coin = "BTC", .amount = 100LLU, .expected = "0.000001 BTC"},
    {.coin = "BTC", .amount = 1000LLU, .expected = "0.00001 BTC"},
    {.coin = "BTC", .amount = 10000LLU, .expected = "0.0001 BTC"},
    {.coin = "BTC", .amount = 100000LLU, .expected = "0.001 BTC"},
    {.coin = "BTC", .amount = 1000000LLU, .expected = "0.01 BTC"},
    {.coin = "BTC", .amount = 10000000LLU, .expected = "0.1 BTC"},
    {.coin = "BTC", .amount = 100000000LLU, .expected = "1 BTC"},
    {.coin = "TEST", .amount = 234560000LLU, .expected = "2.3456 TEST"},
    {.coin = "TEST", .amount = 21000000LLU * 100000000LLU, .expected = "21000000 TEST"},
    {.coin = "TICKR",  // ticker supported up to 5 characters
     .amount = 18446744073709551615LLU,
     .expected = "184467440737.09551615 TICKR"},  // largest possible uint64_t
};

static void test_format_sats_amount(void **state) {
    (void) state;

    for (unsigned int i = 0; i < sizeof(sats_testcases) / sizeof(sats_testcases[0]); i++) {
        char out[MAX_AMOUNT_LENGTH + 1] = {0};
        format_sats_amount(sats_testcases[i].coin, sats_testcases[i].amount, out);

        assert_string_equal((char *) out, sats_testcases[i].expected);
    }
}

int main() {
    const struct CMUnitTest tests[] = {cmocka_unit_test(test_format_sats_amount)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
