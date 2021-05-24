#include "stdlib.h"
#include "string.h"

#include "psbt_parse_rawtx.h"

#include "../../boilerplate/dispatcher.h"
#include "../../boilerplate/sw.h"

#include "../../common/buffer.h"
#include "../../common/read.h"
#include "../../common/varint.h"
#include "../../crypto.h"
#include "../../constants.h"

static void start_parsing(dispatcher_context_t *dc);

/*   PARSER FOR A RAWTX INPUT */

// parses the 32-bytes txid of an input in a rawtx
static int parse_rawtxinput_txid(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove

    uint8_t txid[32];
    bool result = dbuffer_read_bytes(buffers, txid, 32);
    if (result) {
        bool must_add_to_hash = true;
        ParseMode_t parse_mode = state->parent_state->parse_mode;
        if (parse_mode == PARSEMODE_TXID) {
            // if this is the input index requested in the parameter, store its prevout hash

            int relevant_input_index = state->parent_state->program_state->compute_txid.input_index;
            if (state->parent_state->in_counter == relevant_input_index) {
                // copy the txid
                memcpy(state->parent_state->program_state->compute_txid.prevout_hash, txid, 32);
            }
        } else if (parse_mode == PARSEMODE_LEGACY_PASS1) {
            uint32_t sighash_type = state->parent_state->program_state->compute_sighash_legacy.sighash_type;
            int input_index = (int)state->parent_state->program_state->compute_sighash_legacy.input_index;

            if (sighash_type & SIGHASH_ANYONECANPAY) {
                // must not add for inputs different than the current transaction (which becomes the only one)
                if (state->parent_state->in_counter != input_index) {
                    must_add_to_hash = false;
                }
            } else {
                // only add for inputs up to and including the current transactions (the others are in pass 2)
                if (state->parent_state->in_counter > input_index) {
                    must_add_to_hash = false;
                }
            }
        } else if (parse_mode == PARSEMODE_LEGACY_PASS2) {
            uint32_t sighash_type = state->parent_state->program_state->compute_sighash_legacy.sighash_type;
            int input_index = (int)state->parent_state->program_state->compute_sighash_legacy.input_index;
            // only add for inputs up to the current transactions (the other are in pass 2)
            if (sighash_type & SIGHASH_ANYONECANPAY) {
                must_add_to_hash = false; // always done in pass 1, for the only input where it matters
            } else {
                // only add for inputs strictly after the current transactions (the other are in pass 1)
                if (state->parent_state->in_counter <= input_index) {
                    must_add_to_hash = false;
                }                
            }
        } else if (parse_mode == PARSEMODE_SEGWIT_V0) {
            crypto_hash_update(&state->parent_state->program_state->compute_sighash_segwit_v0.hashPrevouts_context.header, txid, 32);
        } else {
            PRINTF("NOT IMPLEMENTED (%d)\n", __LINE__);
            return -1;
        }

        if (must_add_to_hash) {
            crypto_hash_update(&state->parent_state->hash_context->header, txid, 32);
        }
    }
    return result;
}

// parses the 4-bytes vout of an input in a rawtx
// TODO: shares logic with the previous method; try to factor out the shared code
static int parse_rawtxinput_vout(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    uint8_t vout_bytes[4];
    bool result = dbuffer_read_bytes(buffers, vout_bytes, 4);
    if (result) {
        bool must_add_to_hash = true;
        ParseMode_t parse_mode = state->parent_state->parse_mode;
        if (parse_mode == PARSEMODE_TXID) {
            // if this is the input index requested in the parameters, store its prevout.n

            int relevant_input_index = state->parent_state->program_state->compute_txid.input_index;
            if (state->parent_state->in_counter == relevant_input_index) {
                state->parent_state->program_state->compute_txid.prevout_n = read_u32_le(vout_bytes, 0);
            }
        } else if (parse_mode == PARSEMODE_LEGACY_PASS1) {
            uint32_t sighash_type = state->parent_state->program_state->compute_sighash_legacy.sighash_type;
            int input_index = (int)state->parent_state->program_state->compute_sighash_legacy.input_index;

            if (sighash_type & SIGHASH_ANYONECANPAY) {
                // must not add for inputs different than the current transaction (which becomes the only one)
                if (state->parent_state->in_counter != input_index) {
                    must_add_to_hash = false;
                }
            } else {
                // only add for inputs up to and including the current transactions (the others are in pass 2)
                if (state->parent_state->in_counter > input_index) {
                    must_add_to_hash = false;
                }
            }
        } else if (parse_mode == PARSEMODE_LEGACY_PASS2) {
            uint32_t sighash_type = state->parent_state->program_state->compute_sighash_legacy.sighash_type;
            int input_index = (int)state->parent_state->program_state->compute_sighash_legacy.input_index;
            // only add for inputs up to the current transactions (the other are in pass 2)
            if (sighash_type & SIGHASH_ANYONECANPAY) {
                must_add_to_hash = false; // always done in pass 1, for the only input where it matters
            } else {
                // only add for inputs strictly after the current transactions (the other are in pass 1)
                if (state->parent_state->in_counter <= input_index) {
                    must_add_to_hash = false;
                }                
            }
        } else if (parse_mode == PARSEMODE_SEGWIT_V0) {
            crypto_hash_update(&state->parent_state->program_state->compute_sighash_segwit_v0.hashPrevouts_context.header, vout_bytes, 4);
        } else {
            PRINTF("NOT IMPLEMENTED (%d)\n", __LINE__);
            return -1;
        }

        if (must_add_to_hash) {
            crypto_hash_update(&state->parent_state->hash_context->header, vout_bytes, 4);
        }
    }
    return result;
}

static int parse_rawtxinput_scriptsig_size(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    uint64_t scriptsig_size;
    bool result = dbuffer_read_varint(buffers, &scriptsig_size);

    if (result) {
        state->scriptsig_size = (int)scriptsig_size;

        ParseMode_t parse_mode = state->parent_state->parse_mode;
        if (parse_mode == PARSEMODE_TXID) {
            crypto_hash_update_varint(&state->parent_state->hash_context->header, scriptsig_size);
        } else if (parse_mode == PARSEMODE_LEGACY_PASS1) {
            uint32_t sighash_type = state->parent_state->program_state->compute_sighash_legacy.sighash_type;
            int input_index = (int)state->parent_state->program_state->compute_sighash_legacy.input_index;
            // nothing to do if ANYONECANPAY
            // otherwise, scriptsigs prior strictly before the current inputs are changed to 0x00 (length 1),
            // and the others others done in pass 2
            if (!(sighash_type & SIGHASH_ANYONECANPAY) && state->parent_state->in_counter < input_index) {
                crypto_hash_update_u8(&state->parent_state->hash_context->header, 1);    // script length
                crypto_hash_update_u8(&state->parent_state->hash_context->header, 0x00); // empty script (0x00)
            }
        } else if (parse_mode == PARSEMODE_LEGACY_PASS2) {
            uint32_t sighash_type = state->parent_state->program_state->compute_sighash_legacy.sighash_type;
            int input_index = (int)state->parent_state->program_state->compute_sighash_legacy.input_index;
            // nothing to do if ANYONECANPAY
            // otherwise, scriptsigs prior strictly before the current inputs are changed to 0x00 (length 1),
            // and the others others done in pass 2
            if (!(sighash_type & SIGHASH_ANYONECANPAY) && state->parent_state->in_counter > input_index) {
                crypto_hash_update_u8(&state->parent_state->hash_context->header, 1);    // script length
                crypto_hash_update_u8(&state->parent_state->hash_context->header, 0x00); // empty script (0x00)
            }
        } else if (parse_mode == PARSEMODE_SEGWIT_V0) {
            // nothing to do
        } else {
            PRINTF("NOT IMPLEMENTED (%d)\n", __LINE__);
            return -1;
        }
    }
    return result;
}

// Does not read any bytes; only initializing the state before the next step
static int parse_rawtxinput_scriptsig_init(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove

    state->scriptsig_counter = 0;

    // When parse_mode == PARSEMODE_LEGACY, parse_rawtxinput_scriptsig_size already took care of adding
    // the scriptsig (replaced with 0x00) when needed. So nothing to do here and in the next function.

    return 1;
}

static int parse_rawtxinput_scriptsig(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    uint8_t data[32];

    while (true) {
        int remaining_len = state->scriptsig_size - state->scriptsig_counter;

        // We read in chunks of at most 32 bytes, so that we can always interrupt with less than 32 unparsed bytes
        int data_len = MIN(32, remaining_len);

        bool read_result = dbuffer_read_bytes(buffers, data, data_len);
        if (!read_result) {
            return 0; // could not read enough data
        }

        ParseMode_t parse_mode = state->parent_state->parse_mode;
        if (parse_mode == PARSEMODE_TXID) {
            crypto_hash_update(&state->parent_state->hash_context->header, data, data_len);
        } else if (parse_mode == PARSEMODE_LEGACY_PASS1 || parse_mode == PARSEMODE_LEGACY_PASS2) {
            // nothing to do here, already handled in parse_rawtxinput_scriptsig_size
        } else if (parse_mode == PARSEMODE_SEGWIT_V0) {
            // nothing to do
        } else {
            PRINTF("NOT IMPLEMENTED (%d)\n", __LINE__);
            return -1;
        }

        state->scriptsig_counter += data_len;

        if (state->scriptsig_counter == state->scriptsig_size) {
            return 1; // done
        }
    }
}

static int parse_rawtxinput_sequence(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    uint8_t sequence_bytes[4];

    bool result = dbuffer_read_bytes(buffers, sequence_bytes, 4);
    if (result) {
        bool must_add_to_hash = true;
        bool must_replace_with_zeros = false; // used for SIGHASH_NONE and SIGHASH_SINGLE

        ParseMode_t parse_mode = state->parent_state->parse_mode;
        if (parse_mode == PARSEMODE_TXID) {
            // nothing to do
        } else if (parse_mode == PARSEMODE_LEGACY_PASS1) {
            uint32_t sighash_type = state->parent_state->program_state->compute_sighash_legacy.sighash_type;
            int input_index = (int)state->parent_state->program_state->compute_sighash_legacy.input_index;
            if (sighash_type & SIGHASH_ANYONECANPAY) {
                // nothing to do, only add in pass 2
                must_add_to_hash = false;
            } else {
                if (state->parent_state->in_counter != input_index) {
                    // replace with zeros if SIGHASH_NONE or SIGHASH_SINGLE
                    must_replace_with_zeros = (sighash_type & 31) == SIGHASH_NONE || (sighash_type & 31) == SIGHASH_SINGLE;
                }
                // add for inputs strictly less than the current input
                must_add_to_hash = state->parent_state->in_counter < input_index;
            }
        } else if (parse_mode == PARSEMODE_LEGACY_PASS2) {
            uint32_t sighash_type = state->parent_state->program_state->compute_sighash_legacy.sighash_type;
            int input_index = (int)state->parent_state->program_state->compute_sighash_legacy.input_index;
            if (sighash_type & SIGHASH_ANYONECANPAY) {
                // only add for the current input
                must_add_to_hash = state->parent_state->in_counter == input_index;
            } else {
                if (state->parent_state->in_counter != input_index) {
                    // replace with zeros if SIGHASH_NONE or SIGHASH_SINGLE
                    must_replace_with_zeros = (sighash_type & 31) == SIGHASH_NONE || (sighash_type & 31) == SIGHASH_SINGLE;
                }
                // add for inputs greater than or equal to the current input
                must_add_to_hash = state->parent_state->in_counter >= input_index;
            }
        } else if (parse_mode == PARSEMODE_SEGWIT_V0) {
            crypto_hash_update(&state->parent_state->hash_context->header, sequence_bytes, 4);
        } else {
            PRINTF("NOT IMPLEMENTED (%d)\n", __LINE__);
            return -1;
        }

        if (must_add_to_hash) {
            if (!must_replace_with_zeros) {
                crypto_hash_update(&state->parent_state->hash_context->header, sequence_bytes, 4);
            } else {
                crypto_hash_update_u32(&state->parent_state->hash_context->header, 0x00000000);
            }
        }
    }
    return result;
}


static const parsing_step_t parse_rawtxinput_steps[] = {
    (parsing_step_t)parse_rawtxinput_txid,
    (parsing_step_t)parse_rawtxinput_vout,
    (parsing_step_t)parse_rawtxinput_scriptsig_size,
    (parsing_step_t)parse_rawtxinput_scriptsig_init, (parsing_step_t)parse_rawtxinput_scriptsig,
    (parsing_step_t)parse_rawtxinput_sequence,
};

const int n_parse_rawtxinput_steps = sizeof(parse_rawtxinput_steps)/sizeof(parse_rawtxinput_steps[0]);


/*   PARSER FOR A RAWTX OUTPUT */

static int parse_rawtxoutput_value(parse_rawtxoutput_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    uint8_t value_bytes[8];
    bool result = dbuffer_read_bytes(buffers, value_bytes, 8);
    if (result) {
        ParseMode_t parse_mode = state->parent_state->parse_mode;
        if (parse_mode == PARSEMODE_TXID) {
            crypto_hash_update(&state->parent_state->hash_context->header, value_bytes, 8);

            int relevant_output_index = state->parent_state->program_state->compute_txid.output_index;
            if (state->parent_state->out_counter == relevant_output_index) {
                state->parent_state->program_state->compute_txid.prevout_value = read_u64_le(value_bytes, 0);
            }
        } else if (parse_mode == PARSEMODE_LEGACY_PASS1) {
            // nothing to do, all outputs are past the script_code, therefore handled in pass 2
        } else if (parse_mode == PARSEMODE_LEGACY_PASS2) {
            uint32_t sighash_type = state->parent_state->program_state->compute_sighash_legacy.sighash_type;
            int input_index = (int)state->parent_state->program_state->compute_sighash_legacy.input_index;
            if ((sighash_type & 31) == SIGHASH_NONE) {
                // nothing to do, there are no outputs in SIGHASH_NONE
            } else if ((sighash_type & 31) == SIGHASH_SINGLE) {
                if (state->parent_state->out_counter < input_index) {
                    // outputs with index less than the current input have value with -1 (8 bytes 0xFF)
                    int64_t minus_one = -1LL;
                    crypto_hash_update(&state->parent_state->hash_context->header, &minus_one, 8);
                } else if (state->parent_state->out_counter == input_index) {
                    // output with index equal to the current input is unchanged
                    crypto_hash_update(&state->parent_state->hash_context->header, value_bytes, 8);
                } else {
                    // outputs with index above the current input were removed, so nothing to do here
                }
            } else {
                // SIGHASH_ALL
                crypto_hash_update(&state->parent_state->hash_context->header, value_bytes, 8);
            }
        } else if (parse_mode == PARSEMODE_SEGWIT_V0) {
            uint32_t sighash_type = state->parent_state->program_state->compute_sighash_legacy.sighash_type;
            int input_index = (int)state->parent_state->program_state->compute_sighash_legacy.input_index;

            if ((sighash_type & 0x1f) != SIGHASH_SINGLE || state->parent_state->out_counter == input_index) {
                crypto_hash_update(&state->parent_state->program_state->compute_sighash_segwit_v0.hashOutputs_context.header, value_bytes, 8);
            }
        } else {
            PRINTF("NOT IMPLEMENTED (%d)\n", __LINE__);
            return -1;
        }
    }
    return result;
}

static int parse_rawtxoutput_scriptpubkey_size(parse_rawtxoutput_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    uint64_t scriptpubkey_size;
    bool result = dbuffer_read_varint(buffers, &scriptpubkey_size);
    if (result) {
        state->scriptpubkey_size = (int)scriptpubkey_size;

        ParseMode_t parse_mode = state->parent_state->parse_mode;
        if (parse_mode == PARSEMODE_TXID) {
            crypto_hash_update_varint(&state->parent_state->hash_context->header, scriptpubkey_size);

            int relevant_output_index = state->parent_state->program_state->compute_txid.output_index;
            if (state->parent_state->out_counter == relevant_output_index) {
                state->parent_state->program_state->compute_txid.vout_scriptpubkey_len = (int)scriptpubkey_size;
            }
        } else if (parse_mode == PARSEMODE_LEGACY_PASS1) {
            // nothing to do, all outputs are past the script_code, therefore handled in pass 2
        } else if (parse_mode == PARSEMODE_LEGACY_PASS2) {
            uint32_t sighash_type = state->parent_state->program_state->compute_sighash_legacy.sighash_type;
            int input_index = (int)state->parent_state->program_state->compute_sighash_legacy.input_index;
            if ((sighash_type & 31) == SIGHASH_NONE) {
                // nothing to do, there are no outputs in SIGHASH_NONE
            } else if ((sighash_type & 31) == SIGHASH_SINGLE) {
                if (state->parent_state->out_counter < input_index) {
                    // outputs with index less than the current input have script replaced with empty script (length 1)
                    crypto_hash_update_u8(&state->parent_state->hash_context->header, 1);
                    // we also add the actual script now, so we do not repleat that below
                    crypto_hash_update_u8(&state->parent_state->hash_context->header, 0x00);
                } else if (state->parent_state->out_counter == input_index) {
                    // output with index equal to the current input is unchanged
                    crypto_hash_update_varint(&state->parent_state->hash_context->header, scriptpubkey_size);
                } else {
                    // outputs with index above the current input were removed, so nothing to do here
                }
            } else {
                // SIGHASH_ALL
                crypto_hash_update_varint(&state->parent_state->hash_context->header, scriptpubkey_size);
            }
        } else if (parse_mode == PARSEMODE_SEGWIT_V0) {
            uint32_t sighash_type = state->parent_state->program_state->compute_sighash_legacy.sighash_type;
            int input_index = (int)state->parent_state->program_state->compute_sighash_legacy.input_index;

            if ((sighash_type & 0x1f) != SIGHASH_SINGLE || state->parent_state->out_counter == input_index) {
                crypto_hash_update_varint(&state->parent_state->program_state->compute_sighash_segwit_v0.hashOutputs_context.header, scriptpubkey_size);
            }
        } else {
            PRINTF("NOT IMPLEMENTED (%d)\n", __LINE__);
            return -1;
        }
    }
    return result;
}

// Does not read any bytes; only initializing the state before the next step
static int parse_rawtxoutput_scriptpubkey_init(parse_rawtxoutput_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    state->scriptpubkey_counter = 0;
    return 1;
}

static int parse_rawtxoutput_scriptpubkey(parse_rawtxoutput_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    uint8_t data[32];

    while (true) {
        int remaining_len = state->scriptpubkey_size - state->scriptpubkey_counter;

        // We read in chunks of at most 32 bytes, so that we can always interrupt with less than 32 unparsed bytes
        int data_len = MIN(32, remaining_len);

        bool read_result = dbuffer_read_bytes(buffers, data, data_len);
        if (!read_result) {
            return 0; // could not read enough data
        }

        ParseMode_t parse_mode = state->parent_state->parse_mode;
        if (parse_mode == PARSEMODE_TXID) {
            crypto_hash_update(&state->parent_state->hash_context->header, data, data_len);

            int relevant_output_index = state->parent_state->program_state->compute_txid.output_index;
            int scriptpubkey_len = state->parent_state->program_state->compute_txid.vout_scriptpubkey_len;
            if (state->parent_state->out_counter == relevant_output_index && scriptpubkey_len <= MAX_PREVOUT_SCRIPTPUBKEY_LEN) {
                memcpy(state->parent_state->program_state->compute_txid.vout_scriptpubkey + state->scriptpubkey_counter,
                    data,
                    data_len);
            }
        } else if (parse_mode == PARSEMODE_LEGACY_PASS1) {
            // nothing to do, all outputs are past the script_code, therefore handled in pass 2
        } else if (parse_mode == PARSEMODE_LEGACY_PASS2) {
            uint32_t sighash_type = state->parent_state->program_state->compute_sighash_legacy.sighash_type;
            int input_index = (int)state->parent_state->program_state->compute_sighash_legacy.input_index;

            if ((sighash_type & 31) == SIGHASH_NONE) {
                // nothing to do, there are no outputs in SIGHASH_NONE
            } else if ((sighash_type & 31) == SIGHASH_SINGLE) {
                if (state->parent_state->out_counter < input_index) {
                    // we already added the 0x00 scriptPubkey for this case in parse_rawtxoutput_scriptpubkey_size,
                    // therefore there is nothing to do here
                } else if (state->parent_state->out_counter == input_index) {
                    // output with index equal to the current input is unchanged
                    crypto_hash_update(&state->parent_state->hash_context->header, data, data_len);
                } else {
                    // outputs with index above the current input were removed, so nothing to do here
                }
            } else {
                // SIGHASH_ALL
                crypto_hash_update(&state->parent_state->hash_context->header, data, data_len);
            }
        } else if (parse_mode == PARSEMODE_SEGWIT_V0) {
            uint32_t sighash_type = state->parent_state->program_state->compute_sighash_legacy.sighash_type;
            int input_index = (int)state->parent_state->program_state->compute_sighash_legacy.input_index;

            if ((sighash_type & 0x1f) != SIGHASH_SINGLE || state->parent_state->out_counter == input_index) {
                crypto_hash_update(&state->parent_state->program_state->compute_sighash_segwit_v0.hashOutputs_context.header, data, data_len);
            }
        } else {
            PRINTF("NOT IMPLEMENTED (%d)\n", __LINE__);
            return -1;
        }

        state->scriptpubkey_counter += data_len;

        if (state->scriptpubkey_counter == state->scriptpubkey_size) {
            return 1; // done
        }
    }
}

static const parsing_step_t parse_rawtxoutput_steps[] = {
    (parsing_step_t)parse_rawtxoutput_value,
    (parsing_step_t)parse_rawtxoutput_scriptpubkey_size,
    (parsing_step_t)parse_rawtxoutput_scriptpubkey_init, (parsing_step_t)parse_rawtxoutput_scriptpubkey,
};

const int n_parse_rawtxoutput_steps = sizeof(parse_rawtxoutput_steps)/sizeof(parse_rawtxoutput_steps[0]);


/*   PARSER FOR A FULL RAWTX */

static int parse_rawtx_init(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove

    // skip the initial 0x00 byte for Merkle leafs
    uint8_t first_byte;
    if (!dbuffer_read_u8(buffers, &first_byte) || first_byte != 0x00) {
        return -1;
    }

    return 1;
}

static int parse_rawtx_version(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    uint8_t version_bytes[4];

    bool result = dbuffer_read_bytes(buffers, version_bytes, 4);
    if (result) {
        ParseMode_t parse_mode = state->parse_mode;
        if (parse_mode == PARSEMODE_TXID || parse_mode == PARSEMODE_LEGACY_PASS1) {
            crypto_hash_update(&state->hash_context->header, version_bytes, 4);
        } else if (parse_mode == PARSEMODE_LEGACY_PASS2) {
            // skip
        } else if (parse_mode == PARSEMODE_SEGWIT_V0) {
            state->program_state->compute_sighash_segwit_v0.nVersion = read_u32_le(version_bytes, 0);
        } else {
            PRINTF("NOT IMPLEMENTED (%d)\n", __LINE__);
            return -1;
        }
    }
    return result;
}


// Checks if this transaction is serialized according to bip144 (segwit), that is, it has a 0x00 marker followed by a
// 0x01 flag where the input count would be expected in the legacy serialization. The marker and flag are read from the
// buffers.
// Does not read any bytes from the buffers if the transaction is in the legacy serialization format.
// The marker and flag (if present) are not added to the hash computation.
static int parse_rawtx_check_segwit(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    if (!dbuffer_can_read(buffers, 1)) {
        return 0;
    }

    // peeks the first byte of the stream, without removing it
    uint8_t first_byte = buffer_can_read(buffers[0], 1) ? buffers[0]->ptr[buffers[0]->offset]
                                                        : buffers[1]->ptr[buffers[1]->offset];

    if (first_byte != 0) {
        state->is_segwit = false;
        return 1; // legacy format, use the legacy parsing scheme
    } else {
        // Segwit format, the first byte is 0x00 and the next should be the 0x01 flag.
        if (!dbuffer_can_read(buffers, 2)) {
            return 0; // need to fetch more data
        }

        uint8_t flag;
        dbuffer_read_u8(buffers, &first_byte); // skip the 0x00 marker
        dbuffer_read_u8(buffers, &flag);
        if (flag != 0x01) {
            PRINTF("Unexpected flag while parsing a segwit tranaction: %02x.", flag);
            return -1;
        }

        state->is_segwit = true;
        return 1;
    }
}

static int parse_rawtx_input_count(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove


    uint64_t n_inputs; 
    bool result = dbuffer_read_varint(buffers, &n_inputs);
    if (result) {
        state->n_inputs = (int)n_inputs;
        ParseMode_t parse_mode = state->parse_mode;
        if (parse_mode == PARSEMODE_TXID) {
            crypto_hash_update_varint(&state->hash_context->header, n_inputs);
        } else if (parse_mode == PARSEMODE_LEGACY_PASS1) {
            // TODO: add right value depending on sighash
            uint32_t sighash_type = state->program_state->compute_sighash_legacy.sighash_type; 
            if (sighash_type & SIGHASH_ANYONECANPAY) {
                // in ANYONECANPAY, the inputs is resized to only contain the current input
                crypto_hash_update_u8(&state->hash_context->header, 1);
            } else {
                crypto_hash_update_varint(&state->hash_context->header, n_inputs);
            }
        } else if (parse_mode == PARSEMODE_LEGACY_PASS2) {
            // skip
        } else if (parse_mode == PARSEMODE_SEGWIT_V0) {
            // skip
        } else {
            PRINTF("NOT IMPLEMENTED (%d)\n", __LINE__);
            return -1;
        }
    }
    return result;
}

static int parse_rawtx_inputs_init(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    state->in_counter = 0;

    if (state->parse_mode == PARSEMODE_SEGWIT_V0) {
        // init hash contexts related to the inputs
        cx_sha256_init(&state->program_state->compute_sighash_segwit_v0.hashPrevouts_context);
        cx_sha256_init(&state->program_state->compute_sighash_segwit_v0.hashSequence_context);
    }

    parser_init_context(&state->input_parser_context, &state->input_parser_state);

    state->input_parser_state.parent_state = state;
    return 1;
}

static int parse_rawtx_inputs(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    while (state->in_counter < state->n_inputs) {
        while (true) {
            bool result = parser_run(parse_rawtxinput_steps,
                                     n_parse_rawtxinput_steps,
                                     &state->input_parser_context,
                                     buffers,
                                     pic);
            if (result != 1) {
                return result; // stream exhausted, or error
            } else {
                break; // completed parsing input
            }
        }

        ++state->in_counter;
        parser_init_context(&state->input_parser_context, &state->input_parser_state);
    }
    return 1;
}

static int parse_rawtx_inputs_finalize(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove

    if (state->parse_mode == PARSEMODE_SEGWIT_V0) {
        uint32_t sighash_type = state->program_state->compute_sighash_segwit_v0.sighash_type;

        // if SIGHASH_ANYONECANPAY, hashPrevouts is zeroed
        if (sighash_type & SIGHASH_ANYONECANPAY) {
            memset(state->program_state->compute_sighash_segwit_v0.hashPrevouts, 0, 32);
        } else {
            crypto_hash_digest(&state->program_state->compute_sighash_segwit_v0.hashPrevouts_context.header,
                               state->program_state->compute_sighash_segwit_v0.hashPrevouts,
                               32);
            cx_hash_sha256(state->program_state->compute_sighash_segwit_v0.hashPrevouts, 32,
                           state->program_state->compute_sighash_segwit_v0.hashPrevouts, 32);
        }


        // if any of SIGHASH_ANYONECANPAY or SIGHASH_SINGLE or SIGHASH_NONE, hashSequence is zeroed
        if ((sighash_type & SIGHASH_ANYONECANPAY)
            || (sighash_type & 0x1f) == SIGHASH_SINGLE
            || (sighash_type & 0x1f) == SIGHASH_NONE)
        {
            memset(state->program_state->compute_sighash_segwit_v0.hashSequence, 0, 32);
        } else {
            crypto_hash_digest(&state->program_state->compute_sighash_segwit_v0.hashSequence_context.header,
                               state->program_state->compute_sighash_segwit_v0.hashSequence,
                               32);
            cx_hash_sha256(state->program_state->compute_sighash_segwit_v0.hashSequence, 32,
                           state->program_state->compute_sighash_segwit_v0.hashSequence, 32);
        }
    }

    return 1;
}

static int parse_rawtx_output_count(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    uint64_t n_outputs; 
    bool result = dbuffer_read_varint(buffers, &n_outputs);
    if (result) {
        state->n_outputs = (int)n_outputs;

        ParseMode_t parse_mode = state->parse_mode;
        if (parse_mode == PARSEMODE_TXID) {
            crypto_hash_update_varint(&state->hash_context->header, n_outputs);
        } else if (parse_mode == PARSEMODE_LEGACY_PASS1) {
            // nothing to do, all outputs are past the script_code, therefore handled in pass 2
        } else if (parse_mode == PARSEMODE_LEGACY_PASS2) {
            uint32_t sighash_type = state->program_state->compute_sighash_legacy.sighash_type;
            int input_index = (int)state->program_state->compute_sighash_legacy.input_index;

            if ((sighash_type & 31) == SIGHASH_NONE) {
                // outputs are stripped, so the new output count is 0
                crypto_hash_update_u8(&state->hash_context->header, 0);
            } else if ((sighash_type & 31) == SIGHASH_SINGLE) {
                // outputs past the current input are stripped, so the output count is input_index + 1
                crypto_hash_update_varint(&state->hash_context->header, input_index + 1);
            } else {
                // SIGHASH_ALL
                crypto_hash_update_varint(&state->hash_context->header, n_outputs);
            }
        } else {
            PRINTF("NOT IMPLEMENTED (%d)\n", __LINE__);
            return -1;
        }
    }
    return result;
}

static int parse_rawtx_outputs_init(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove

    state->out_counter = 0;
    parser_init_context(&state->output_parser_context, &state->output_parser_state);

    if (state->parse_mode == PARSEMODE_SEGWIT_V0) {
        // init hash context related to the outputs
        cx_sha256_init(&state->program_state->compute_sighash_segwit_v0.hashOutputs_context);
    }

    state->output_parser_state.parent_state = state;
    return 1;
}

static int parse_rawtx_outputs(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    while (state->out_counter < state->n_outputs) {
        while (true) {
            bool result = parser_run(parse_rawtxoutput_steps,
                                     n_parse_rawtxoutput_steps,
                                     &state->output_parser_context,
                                     buffers,
                                     pic);
            if (result != 1) {
                return result; // stream exhausted, or error
            } else {
                break; // completed parsing output
            }
        }

        ++state->out_counter;
        parser_init_context(&state->output_parser_context, &state->output_parser_state);
    }
    return 1;
}

static int parse_rawtx_outputs_finalize(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove

    if (state->parse_mode == PARSEMODE_SEGWIT_V0) {
        uint32_t sighash_type = state->program_state->compute_sighash_segwit_v0.sighash_type;

        // hashOutputs is zeroed if either:
        // - sighash type is SIGHASH_NONE (or SIGHASH_NONE | SIGHASH_ANYONECANPAY)
        // - sighash type is SIGHASH_SINGLE and the input index is >= the number of outputs
        // Otherwise:
        // - if SIGHASH_SINGLE, only the corresponding output is part of the hash (handled in the output parsing section)
        // - in any other case, all outputs are hashed in hashOutputs
        
        int in_index = state->program_state->compute_sighash_segwit_v0.input_index;
        if ((sighash_type & 0x1f) == SIGHASH_NONE
            || ((sighash_type & 0x1f) == SIGHASH_SINGLE && in_index >= state->n_outputs))
        {
            memset(state->program_state->compute_sighash_segwit_v0.hashOutputs, 0, 32);
        } else {
            crypto_hash_digest(&state->program_state->compute_sighash_segwit_v0.hashOutputs_context.header,
                               state->program_state->compute_sighash_segwit_v0.hashOutputs,
                               32);
            cx_hash_sha256(state->program_state->compute_sighash_segwit_v0.hashOutputs, 32,
                           state->program_state->compute_sighash_segwit_v0.hashOutputs, 32);
        }
    }
    return 1;
}

static int parse_rawtx_witness_count(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove

    if (!state->is_segwit) {
        state->n_witnesses = 0;
        state->wit_counter = 0;

        return 1; // no witnesses to parse
    }

    uint64_t n_witnesses; 
    bool result = dbuffer_read_varint(buffers, &n_witnesses);
    if (result) {
        state->n_witnesses = (int)n_witnesses;
        state->wit_counter = 0;
        state->cur_witness_length = 0;
    }
    return result;
}

// Parses the witness data; currently, no use is made of that data.
static int parse_rawtx_witnesses(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove

    if (!state->is_segwit) {
        return 1; // no witnesses to parse
    }

    if (state->wit_counter >= state->n_witnesses) {
        return 1; // all witnesses were already parsed
    }

    while (state->wit_counter < state->n_witnesses) {
        // read the witness length if not already read
        if (state->cur_witness_length == 0) {
            // the witness length was not yet read.
            uint64_t cur_witness_length; 
            if (!dbuffer_read_varint(buffers, &cur_witness_length)) {
                return 0; // incomplete, read more data 
            }
            state->cur_witness_length = (int)cur_witness_length;
            state->cur_witness_bytes_read = 0;
        }

        while (state->cur_witness_bytes_read < state->cur_witness_length) {
            uint8_t data[32];
            int remaining_len = state->cur_witness_length - state->cur_witness_bytes_read;

            // We read in chunks of at most 32 bytes, so that we can always interrupt with less than 32 unparsed bytes
            int data_len = MIN(32, remaining_len);
            if (!dbuffer_read_bytes(buffers, data, data_len)) {
                return 0;
            }
            state->cur_witness_bytes_read += data_len;
        }

        // move to parsing the next witness (if any)
        ++state->wit_counter;
        state->cur_witness_length = 0; // reset length to make sure we read the next witness length first
    }
    return 1;
}


static int parse_rawtx_locktime(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove

    uint8_t locktime_bytes[4];
    bool result = dbuffer_read_bytes(buffers, locktime_bytes, 4);
    if (result) {
        state->locktime = read_u32_le(locktime_bytes, 0);

        ParseMode_t parse_mode = state->parse_mode;
        if (parse_mode == PARSEMODE_TXID) {
            crypto_hash_update(&state->hash_context->header, locktime_bytes, 4);
        } else if (parse_mode == PARSEMODE_LEGACY_PASS1) {
            // nothing to do, as we are past the script_code
        } else if (parse_mode == PARSEMODE_LEGACY_PASS2) {
            crypto_hash_update(&state->hash_context->header, locktime_bytes, 4);
        } else if (parse_mode == PARSEMODE_SEGWIT_V0) {
            // nothing to do
        } else {
            PRINTF("NOT IMPLEMENTED (%d)\n", __LINE__);
            return -1;
        }
    }
    return result;
}

static int parse_rawtx_add_sighash(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove

    ParseMode_t parse_mode = state->parse_mode;
    if (parse_mode == PARSEMODE_LEGACY_PASS2) {
        uint8_t sighash_type_bytes[4];
        write_u32_le(sighash_type_bytes, 0, state->program_state->compute_sighash_legacy.sighash_type);
        crypto_hash_update(&state->hash_context->header, sighash_type_bytes, 4);
    }

    // nothing to do for PARSEMODE_SEGWIT_V0

    return 1;
}

static const parsing_step_t parse_rawtx_steps[] = {
    (parsing_step_t)parse_rawtx_init,
    (parsing_step_t)parse_rawtx_version,
    (parsing_step_t)parse_rawtx_check_segwit,
    (parsing_step_t)parse_rawtx_input_count,
    (parsing_step_t)parse_rawtx_inputs_init, (parsing_step_t)parse_rawtx_inputs, (parsing_step_t)parse_rawtx_inputs_finalize,
    (parsing_step_t)parse_rawtx_output_count,
    (parsing_step_t)parse_rawtx_outputs_init, (parsing_step_t)parse_rawtx_outputs, (parsing_step_t)parse_rawtx_outputs_finalize,
    (parsing_step_t)parse_rawtx_witness_count,
    (parsing_step_t)parse_rawtx_witnesses,
    (parsing_step_t)parse_rawtx_locktime,
    (parsing_step_t)parse_rawtx_add_sighash,
};

const int n_parse_rawtx_steps = sizeof(parse_rawtx_steps)/sizeof(parse_rawtx_steps[0]);


void flow_psbt_parse_rawtx(dispatcher_context_t *dc) {
    psbt_parse_rawtx_state_t *state = (psbt_parse_rawtx_state_t *)dc->machine_context_ptr;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    call_get_merkleized_map_value_hash(dc, &state->subcontext.get_merkleized_map_value_hash, start_parsing,
                                       state->map,
                                       state->key,
                                       state->key_len,
                                       state->value_hash);
}


static void cb_process_data_firstpass(psbt_parse_rawtx_state_t *state, buffer_t *data) {
    buffer_t store_buf = buffer_create(state->store, state->store_data_length);
    buffer_t *buffers[] = { &store_buf, data };

    int result = parser_run(parse_rawtx_steps, n_parse_rawtx_steps, &state->parser_context, buffers, pic);
    if (result == 0) {
        parser_consolidate_buffers(buffers, sizeof(state->store));
        state->store_data_length = store_buf.size;
    } else if (result < 0) {
        // TODO: we might want to process other result values; in order to do so, we might need to change the signature
        //       of callbacks to return a success value (and abort on failures).
        PRINTF("Parser error\n"); // TODO: this should be handled somehow
    }
}

static void start_parsing(dispatcher_context_t *dc) {
    psbt_parse_rawtx_state_t *state = (psbt_parse_rawtx_state_t *)dc->machine_context_ptr;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // init the state of the parser (global)
    state->parser_state.hash_context = state->hash_context;
    state->parser_state.program_state = &state->program_state;

    // init the parser, based on the program type
    state->parser_state.parse_mode = state->parse_mode;
    if (state->parse_mode != PARSEMODE_TXID &&
        state->parse_mode != PARSEMODE_LEGACY_PASS1 &&
        state->parse_mode != PARSEMODE_LEGACY_PASS2 &&
        state->parse_mode != PARSEMODE_SEGWIT_V0
    ) {
        PRINTF("Illegal parse mode.\n");
        dc->send_sw(SW_BAD_STATE);
        return;
    }

    int res = call_stream_preimage(dc,
                                   state->value_hash,
                                   make_callback(state, (dispatcher_callback_t)cb_process_data_firstpass));
    if (res < 0) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    state->n_inputs = state->parser_state.n_inputs;
    state->n_outputs = state->parser_state.n_outputs;
}
