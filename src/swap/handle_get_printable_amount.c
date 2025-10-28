#include <string.h>
#include <stdint.h>

#include "handle_get_printable_amount.h"

#include "btchip_bcd.h"

#define MAX_NON_PRINTABLE_AMOUNT_LEN 8

int handle_get_printable_amount(get_printable_amount_parameters_t *params) {
    params->printable_amount[0] = 0;
    if (params->amount_length > MAX_NON_PRINTABLE_AMOUNT_LEN) {
        PRINTF("Amount is too big");
        return 0;
    }
    unsigned char amount[MAX_NON_PRINTABLE_AMOUNT_LEN] = {0};
    /* Amount + ' ' + ticker */
    memcpy(amount + (MAX_NON_PRINTABLE_AMOUNT_LEN - params->amount_length),
           params->amount,
           params->amount_length);
    int res_length =
        btchip_convert_hex_amount_to_displayable_no_globals(amount,
                                                            (uint8_t *) params->printable_amount);
    params->printable_amount[res_length] = ' ';
    size_t coin_name_length = strlen(COIN_COINID_SHORT);
    memmove(&params->printable_amount[res_length + 1], COIN_COINID_SHORT, coin_name_length);
    params->printable_amount[res_length + coin_name_length + 1] = '\0';

    return 1;
}
