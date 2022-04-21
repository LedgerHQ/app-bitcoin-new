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

    assert_int_equal(node_1->base.type, TOKEN_PKH);
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

    assert_int_equal(root->base.type, TOKEN_SH);

    policy_node_with_key_t *inner = (policy_node_with_key_t *) root->script;

    assert_int_equal(inner->base.type, TOKEN_WPKH);
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

    assert_int_equal(root->base.type, TOKEN_SH);

    policy_node_with_script_t *mid = (policy_node_with_script_t *) root->script;

    assert_int_equal(mid->base.type, TOKEN_WSH);

    policy_node_with_key_t *inner = (policy_node_with_key_t *) mid->script;

    assert_int_equal(inner->base.type, TOKEN_PKH);
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

    assert_int_equal(node_1->base.type, TOKEN_SORTEDMULTI);
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

    assert_int_equal(root->base.type, TOKEN_WSH);

    policy_node_multisig_t *inner = (policy_node_multisig_t *) root->script;
    assert_int_equal(inner->base.type, TOKEN_MULTI);

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

    assert_int_equal(root->base.type, TOKEN_SH);

    policy_node_with_script_t *mid = (policy_node_with_script_t *) root->script;
    assert_int_equal(mid->base.type, TOKEN_WSH);

    policy_node_multisig_t *inner = (policy_node_multisig_t *) mid->script;
    assert_int_equal(inner->base.type, TOKEN_SORTEDMULTI);

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

enum TestMode {
    TESTMODE_INVALID = 0,
    TESTMODE_VALID = 1,
    TESTMODE_NONMAL = 2,      // ignored in our tests
    TESTMODE_NEEDSIG = 4,     // ignored in our tests
    TESTMODE_TIMELOCKMIX = 8  // ignored in our tests
};

static void Test(const char *ms, const char *hexscript, int mode) {
    (void) hexscript;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];

    int res;
    buffer_t policy_buf = buffer_create((void *) ms, strlen(ms));

    res = parse_policy_map(&policy_buf, out, sizeof(out));

    if (mode == TESTMODE_INVALID) {
        assert_true(res < 0);
    } else {
        assert_true(res == 0);
    }
}

static void test_miniscript_types(void **state) {
    (void) state;

    // tests for miniscript type system
    // Tests taken from
    // https://github.com/sipa/miniscript/blob/833471d44151fe407727ff6e4a22ca34198d59fd/bitcoin/test/miniscript_tests.cpp,
    // except that all key expressions are replaced with placeholders @0, @1, ...

    Test("l:older(1)", "?", TESTMODE_VALID | TESTMODE_NONMAL);  // older(1): valid
    Test("l:older(0)", "?", TESTMODE_INVALID);                  // older(0): k must be at least 1
    Test("l:older(2147483647)", "?", TESTMODE_VALID | TESTMODE_NONMAL);  // older(2147483647): valid
    Test("l:older(2147483648)", "?", TESTMODE_INVALID);  // older(2147483648): k must be below 2^31
    Test("u:after(1)", "?", TESTMODE_VALID | TESTMODE_NONMAL);  // after(1): valid
    Test("u:after(0)", "?", TESTMODE_INVALID);                  // after(0): k must be at least 1
    Test("u:after(2147483647)", "?", TESTMODE_VALID | TESTMODE_NONMAL);  // after(2147483647): valid
    Test("u:after(2147483648)", "?", TESTMODE_INVALID);  // after(2147483648): k must be below 2^31
    Test("andor(0,1,1)", "?", TESTMODE_VALID | TESTMODE_NONMAL);  // andor(Bdu,B,B): valid
    Test("andor(a:0,1,1)", "?", TESTMODE_INVALID);                // andor(Wdu,B,B): X must be B
    Test("andor(0,a:1,a:1)", "?", TESTMODE_INVALID);  // andor(Bdu,W,W): Y and Z must be B/V/K
    Test("andor(1,1,1)", "?", TESTMODE_INVALID);      // andor(Bu,B,B): X must be d
    Test("andor(n:or_i(0,after(1)),1,1)", "?", TESTMODE_VALID);  // andor(Bdu,B,B): valid
    Test("andor(or_i(0,after(1)),1,1)", "?", TESTMODE_INVALID);  // andor(Bd,B,B): X must be u
    Test(
        "c:andor(0,pk_k(@0),pk_k("
        "@1))",
        "?",
        TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG);           // andor(Bdu,K,K): valid
    Test("t:andor(0,v:1,v:1)", "?", TESTMODE_VALID | TESTMODE_NONMAL);  // andor(Bdu,V,V): valid
    Test("and_v(v:1,1)", "?", TESTMODE_VALID | TESTMODE_NONMAL);        // and_v(V,B): valid
    Test("t:and_v(v:1,v:1)", "?", TESTMODE_VALID | TESTMODE_NONMAL);    // and_v(V,V): valid
    Test("c:and_v(v:1,pk_k(@0))",
         "?",
         TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG);  // and_v(V,K): valid
    Test("and_v(1,1)", "?", TESTMODE_INVALID);                  // and_v(B,B): X must be V
    Test("and_v(pk_k(@0),1)", "?",
         TESTMODE_INVALID);                                       // and_v(K,B): X must be V
    Test("and_v(v:1,a:1)", "?", TESTMODE_INVALID);                // and_v(K,W): Y must be B/V/K
    Test("and_b(1,a:1)", "?", TESTMODE_VALID | TESTMODE_NONMAL);  // and_b(B,W): valid
    Test("and_b(1,1)", "?", TESTMODE_INVALID);                    // and_b(B,B): Y must W
    Test("and_b(v:1,a:1)", "?", TESTMODE_INVALID);                // and_b(V,W): X must be B
    Test("and_b(a:1,a:1)", "?", TESTMODE_INVALID);                // and_b(W,W): X must be B
    Test("and_b(pk_k(@0),a:1)", "?",
         TESTMODE_INVALID);  // and_b(K,W): X must be B
    Test("or_b(0,a:0)",
         "?",
         TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG);  // or_b(Bd,Wd): valid
    Test("or_b(1,a:0)", "?", TESTMODE_INVALID);                 // or_b(B,Wd): X must be d
    Test("or_b(0,a:1)", "?", TESTMODE_INVALID);                 // or_b(Bd,W): Y must be d
    Test("or_b(0,0)", "?", TESTMODE_INVALID);                   // or_b(Bd,Bd): Y must W
    Test("or_b(v:0,a:0)", "?", TESTMODE_INVALID);               // or_b(V,Wd): X must be B
    Test("or_b(a:0,a:0)", "?", TESTMODE_INVALID);               // or_b(Wd,Wd): X must be B
    Test("or_b(pk_k(@0),a:0)", "?",
         TESTMODE_INVALID);                                        // or_b(Kd,Wd): X must be B
    Test("t:or_c(0,v:1)", "?", TESTMODE_VALID | TESTMODE_NONMAL);  // or_c(Bdu,V): valid
    Test("t:or_c(a:0,v:1)", "?", TESTMODE_INVALID);                // or_c(Wdu,V): X must be B
    Test("t:or_c(1,v:1)", "?", TESTMODE_INVALID);                  // or_c(Bu,V): X must be d
    Test("t:or_c(n:or_i(0,after(1)),v:1)", "?", TESTMODE_VALID);   // or_c(Bdu,V): valid
    Test("t:or_c(or_i(0,after(1)),v:1)", "?", TESTMODE_INVALID);   // or_c(Bd,V): X must be u
    Test("t:or_c(0,1)", "?", TESTMODE_INVALID);                    // or_c(Bdu,B): Y must be V
    Test("or_d(0,1)", "?", TESTMODE_VALID | TESTMODE_NONMAL);      // or_d(Bdu,B): valid
    Test("or_d(a:0,1)", "?", TESTMODE_INVALID);                    // or_d(Wdu,B): X must be B
    Test("or_d(1,1)", "?", TESTMODE_INVALID);                      // or_d(Bu,B): X must be d
    Test("or_d(n:or_i(0,after(1)),1)", "?", TESTMODE_VALID);       // or_d(Bdu,B): valid
    Test("or_d(or_i(0,after(1)),1)", "?", TESTMODE_INVALID);       // or_d(Bd,B): X must be u
    Test("or_d(0,v:1)", "?", TESTMODE_INVALID);                    // or_d(Bdu,V): Y must be B
    Test("or_i(1,1)", "?", TESTMODE_VALID);                        // or_i(B,B): valid
    Test("t:or_i(v:1,v:1)", "?", TESTMODE_VALID);                  // or_i(V,V): valid
    Test(
        "c:or_i(pk_k(@0),pk_k("
        "@1))",
        "?",
        TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG);  // or_i(K,K): valid
    Test("or_i(a:1,a:1)", "?", TESTMODE_INVALID);              // or_i(W,W): X and Y must be B/V/K
    Test("or_b(l:after(100),al:after(1000000000))",
         "?",
         TESTMODE_VALID);  // or_b(timelock, heighlock) valid
    Test("and_b(after(100),a:after(1000000000))",
         "?",
         TESTMODE_VALID | TESTMODE_NONMAL |
             TESTMODE_TIMELOCKMIX);  // and_b(timelock, heighlock) invalid
    Test("pk(@0)", "?",
         TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG);  // alias to c:pk_k
    Test("pkh(@0)", "?",
         TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG);  // alias to c:pk_h
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
        cmocka_unit_test(test_miniscript_types),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
