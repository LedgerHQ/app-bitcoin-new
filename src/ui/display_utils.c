#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "./display_utils.h"

static size_t n_digits(uint64_t number) {
    size_t count = 0;
    do {
        count++;

        number /= 10;
    } while (number != 0);
    return count;
}

void format_sats_amount(const char *coin_name,
                        uint64_t amount,
                        char out[static MAX_AMOUNT_LENGTH + 1]) {
    uint64_t integral_part = amount / 100000000;
    uint32_t fractional_part = (uint32_t) (amount % 100000000);

    // Compute the fractional part string (exactly 8 digits, possibly with trailing zeros)
    char fractional_str[9];
    snprintf(fractional_str, 9, "%08u", fractional_part);
    // Drop trailing zeros
    for (int i = 7; i > 0 && fractional_str[i] == '0'; i--) {
        fractional_str[i] = '\0';
    }

    // the integral part is at most 2^64 / 10^8 = 184467440737
    char integral_str[12 + 1];
    size_t integral_part_digit_count = n_digits(integral_part);
    for (unsigned int i = 0; i < integral_part_digit_count; i++) {
        integral_str[integral_part_digit_count - 1 - i] = '0' + (integral_part % 10);
        integral_part /= 10;
    }
    integral_str[integral_part_digit_count] = '\0';

#ifdef SCREEN_SIZE_WALLET
    // on large screens, format as "<amount> TICKER"
    snprintf(out,
             MAX_AMOUNT_LENGTH + 1,
             "%s%s%s %s",
             integral_str,
             fractional_part ? "." : "",
             fractional_part ? fractional_str : "",
             coin_name);

#else
    // on nanos, format as "TICKER <amount>"
    snprintf(out,
             MAX_AMOUNT_LENGTH + 1,
             "%s %s%s%s",
             coin_name,
             integral_str,
             fractional_part ? "." : "",
             fractional_part ? fractional_str : "");
#endif
}
