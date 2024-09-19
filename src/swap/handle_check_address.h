#pragma once

#include "swap_lib_calls.h"

int handle_check_address(check_address_parameters_t* check_address_params);

bool get_address_from_compressed_public_key(unsigned char format,
                                            unsigned char* compressed_pub_key,
                                            unsigned short payToAddressVersion,
                                            unsigned short payToScriptHashVersion,
                                            const char* native_segwit_prefix,
                                            char* address,
                                            unsigned char max_address_length);

int os_strcmp(const char* s1, const char* s2);