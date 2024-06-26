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
    size_t coin_name_len = strlen(coin_name);
    strncpy(out, coin_name, MAX_AMOUNT_LENGTH + 1);
    out[coin_name_len] = ' ';

    char *amount_str = out + coin_name_len + 1;

    uint64_t integral_part = amount / 100000000;
    uint32_t fractional_part = (uint32_t) (amount % 100000000);

    // format the integral part, starting from the least significant digit
    size_t integral_part_digit_count = n_digits(integral_part);
    for (unsigned int i = 0; i < integral_part_digit_count; i++) {
        amount_str[integral_part_digit_count - 1 - i] = '0' + (integral_part % 10);
        integral_part /= 10;
    }

    if (fractional_part == 0) {
        amount_str[integral_part_digit_count] = '\0';
    } else {
        // format the fractional part (exactly 8 digits, possibly with trailing zeros)
        amount_str[integral_part_digit_count] = '.';
        char *fract_part_str = amount_str + integral_part_digit_count + 1;
        snprintf(fract_part_str, 8 + 1, "%08u", fractional_part);

        // drop trailing zeros
        for (int i = 7; i > 0 && fract_part_str[i] == '0'; i--) {
            fract_part_str[i] = '\0';
        }
    }
}
