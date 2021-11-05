#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include <cmocka.h>

// missing definitions to make it compile without the SDK
unsigned int pic(unsigned int linked_address) {
    return linked_address;
}

#define PRINTF(...) printf
#define PIC(x)      (x)

#include "common/wallet.h"

// in unit tests, size_t integers are currently 8 compiled as 8 bytes; therefore, in the app
// about half of the memory would be needed
#define MAX_POLICY_MAP_MEMORY_SIZE 256

static void test_parse_policy_map_singlesig_1(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];

    int res;

    char *policy = "pkh(@0)";
    buffer_t policy_buf = buffer_create((void *) policy, strlen(policy));

    res = parse_policy_map(&policy_buf, out, sizeof(out));
    assert_int_equal(res, 0);
    policy_node_with_key_t *node_1 = (policy_node_with_key_t *) out;

    assert_int_equal(node_1->type, TOKEN_PKH);
    assert_int_equal(node_1->key_index, 0);
}

static void test_parse_policy_map_singlesig_2(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];

    int res;

    char *policy = "sh(wpkh(@0))";
    buffer_t policy_buf = buffer_create((void *) policy, strlen(policy));

    res = parse_policy_map(&policy_buf, out, sizeof(out));
    assert_int_equal(res, 0);
    policy_node_with_script_t *root = (policy_node_with_script_t *) out;

    assert_int_equal(root->type, TOKEN_SH);

    policy_node_with_key_t *inner = (policy_node_with_key_t *) root->script;

    assert_int_equal(inner->type, TOKEN_WPKH);
    assert_int_equal(inner->key_index, 0);
}

static void test_parse_policy_map_singlesig_3(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];

    int res;

    char *policy = "sh(wsh(pkh(@0)))";
    buffer_t policy_buf = buffer_create((void *) policy, strlen(policy));

    res = parse_policy_map(&policy_buf, out, sizeof(out));
    assert_int_equal(res, 0);
    policy_node_with_script_t *root = (policy_node_with_script_t *) out;

    assert_int_equal(root->type, TOKEN_SH);

    policy_node_with_script_t *mid = (policy_node_with_script_t *) root->script;

    assert_int_equal(mid->type, TOKEN_WSH);

    policy_node_with_key_t *inner = (policy_node_with_key_t *) mid->script;

    assert_int_equal(inner->type, TOKEN_PKH);
    assert_int_equal(inner->key_index, 0);
}

static void test_parse_policy_map_multisig_1(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];

    int res;

    char *policy = "sortedmulti(2,@0,@1,@2)";
    buffer_t policy_buf = buffer_create((void *) policy, strlen(policy));

    res = parse_policy_map(&policy_buf, out, sizeof(out));
    assert_int_equal(res, 0);
    policy_node_multisig_t *node_1 = (policy_node_multisig_t *) out;

    assert_int_equal(node_1->type, TOKEN_SORTEDMULTI);
    assert_int_equal(node_1->k, 2);
    assert_int_equal(node_1->n, 3);
    assert_int_equal(node_1->key_indexes[0], 0);
    assert_int_equal(node_1->key_indexes[1], 1);
    assert_int_equal(node_1->key_indexes[2], 2);
}

static void test_parse_policy_map_multisig_2(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];

    int res;

    char *policy = "wsh(multi(3,@0,@1,@2,@3,@4))";
    buffer_t policy_buf = buffer_create((void *) policy, strlen(policy));

    res = parse_policy_map(&policy_buf, out, sizeof(out));
    assert_int_equal(res, 0);
    policy_node_with_script_t *root = (policy_node_with_script_t *) out;

    assert_int_equal(root->type, TOKEN_WSH);

    policy_node_multisig_t *inner = (policy_node_multisig_t *) root->script;
    assert_int_equal(inner->type, TOKEN_MULTI);

    assert_int_equal(inner->k, 3);
    assert_int_equal(inner->n, 5);
    for (int i = 0; i < 5; i++) assert_int_equal(inner->key_indexes[i], i);
}

static void test_parse_policy_map_multisig_3(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];

    int res;

    char *policy = "sh(wsh(sortedmulti(3,@0,@1,@2,@3,@4)))";
    buffer_t policy_buf = buffer_create((void *) policy, strlen(policy));

    res = parse_policy_map(&policy_buf, out, sizeof(out));
    assert_int_equal(res, 0);
    policy_node_with_script_t *root = (policy_node_with_script_t *) out;

    assert_int_equal(root->type, TOKEN_SH);

    policy_node_with_script_t *mid = (policy_node_with_script_t *) root->script;
    assert_int_equal(mid->type, TOKEN_WSH);

    policy_node_multisig_t *inner = (policy_node_multisig_t *) mid->script;
    assert_int_equal(inner->type, TOKEN_SORTEDMULTI);

    assert_int_equal(inner->k, 3);
    assert_int_equal(inner->n, 5);
    for (int i = 0; i < 5; i++) assert_int_equal(inner->key_indexes[i], i);
}

// convenience function to parse as one liners

static int parse_policy(char *policy, size_t policy_len, uint8_t *out, size_t out_len) {
    buffer_t in_buf = buffer_create((void *) policy, policy_len);
    return parse_policy_map(&in_buf, out, out_len);
}

#define PARSE_POLICY(policy, out, out_len) parse_policy(policy, sizeof(policy) - 1, out, out_len)

static void test_failures(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];

    // excess byte not allowed
    assert_true(0 > PARSE_POLICY("pkh(@0) ", out, sizeof(out)));

    // missing closing parenthesis
    assert_true(0 > PARSE_POLICY("pkh(@0", out, sizeof(out)));

    // unknown token
    assert_true(0 > PARSE_POLICY("yolo(@0)", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("Pkh(@0)", out, sizeof(out)));  // case-sensitive

    // missing or invalid key identifier
    assert_true(0 > PARSE_POLICY("pkh()", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("pkh(@)", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("pkh(0)", out, sizeof(out)));

    // sh not top-level
    assert_true(0 > PARSE_POLICY("sh(sh(pkh(@0)))", out, sizeof(out)));

    // wsh can only be inside sh
    assert_true(0 > PARSE_POLICY("wsh(wsh(pkh(@0)))", out, sizeof(out)));

    // wpkh can only be inside sh
    assert_true(0 > PARSE_POLICY("wsh(wpkh(@0)))", out, sizeof(out)));

    // multi with invalid threshold
    assert_true(
        0 > PARSE_POLICY("multi(6,@0,@1,@2,@3,@4)", out, sizeof(out)));  // threshold larger than n
    assert_true(0 > PARSE_POLICY("multi(0,@0,@1,@2,@3,@4)", out, sizeof(out)));
    // missing threshold or keys in multisig
    assert_true(0 > PARSE_POLICY("multi(@0,@1,@2,@3,@4)", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("multi(1)", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("multi(1,)", out, sizeof(out)));
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_policy_map_singlesig_1),
        cmocka_unit_test(test_parse_policy_map_singlesig_2),
        cmocka_unit_test(test_parse_policy_map_singlesig_3),
        cmocka_unit_test(test_parse_policy_map_multisig_1),
        cmocka_unit_test(test_parse_policy_map_multisig_2),
        cmocka_unit_test(test_parse_policy_map_multisig_3),
        cmocka_unit_test(test_failures),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
