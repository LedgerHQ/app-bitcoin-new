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
#define MAX_WALLET_POLICY_MEMORY_SIZE 512

static void test_parse_policy_map_singlesig_1(void **state) {
    (void) state;

    uint8_t out[MAX_WALLET_POLICY_BYTES];

    int res;

    char *policy = "pkh(@0/**)";
    buffer_t policy_buf = buffer_create((void *) policy, strlen(policy));

    res = parse_policy_map(&policy_buf, out, sizeof(out), WALLET_POLICY_VERSION_V2);
    assert_int_equal(res, 0);
    policy_node_with_key_t *node_1 = (policy_node_with_key_t *) out;

    assert_int_equal(node_1->base.type, TOKEN_PKH);
    assert_int_equal(node_1->key_placeholder->key_index, 0);
    assert_int_equal(node_1->key_placeholder->num_first, 0);
    assert_int_equal(node_1->key_placeholder->num_second, 1);
}

static void test_parse_policy_map_singlesig_2(void **state) {
    (void) state;

    uint8_t out[MAX_WALLET_POLICY_MEMORY_SIZE];

    int res;

    char *policy = "sh(wpkh(@0/**))";
    buffer_t policy_buf = buffer_create((void *) policy, strlen(policy));

    res = parse_policy_map(&policy_buf, out, sizeof(out), WALLET_POLICY_VERSION_V2);
    assert_int_equal(res, 0);
    policy_node_with_script_t *root = (policy_node_with_script_t *) out;

    assert_int_equal(root->base.type, TOKEN_SH);

    policy_node_with_key_t *inner = (policy_node_with_key_t *) root->script;

    assert_int_equal(inner->base.type, TOKEN_WPKH);
    assert_int_equal(inner->key_placeholder->key_index, 0);
    assert_int_equal(inner->key_placeholder->num_first, 0);
    assert_int_equal(inner->key_placeholder->num_second, 1);
}

static void test_parse_policy_map_singlesig_3(void **state) {
    (void) state;

    uint8_t out[MAX_WALLET_POLICY_MEMORY_SIZE];

    int res;

    char *policy = "sh(wsh(pkh(@0/**)))";
    buffer_t policy_buf = buffer_create((void *) policy, strlen(policy));

    res = parse_policy_map(&policy_buf, out, sizeof(out), WALLET_POLICY_VERSION_V2);
    assert_int_equal(res, 0);
    policy_node_with_script_t *root = (policy_node_with_script_t *) out;

    assert_int_equal(root->base.type, TOKEN_SH);

    policy_node_with_script_t *mid = (policy_node_with_script_t *) root->script;

    assert_int_equal(mid->base.type, TOKEN_WSH);

    policy_node_with_key_t *inner = (policy_node_with_key_t *) mid->script;

    assert_int_equal(inner->base.type, TOKEN_PKH);
    assert_int_equal(inner->key_placeholder->key_index, 0);
    assert_int_equal(inner->key_placeholder->num_first, 0);
    assert_int_equal(inner->key_placeholder->num_second, 1);
}

static void test_parse_policy_map_multisig_1(void **state) {
    (void) state;

    uint8_t out[MAX_WALLET_POLICY_MEMORY_SIZE];

    int res;

    char *policy = "sortedmulti(2,@0/**,@1/**,@2/**)";
    buffer_t policy_buf = buffer_create((void *) policy, strlen(policy));

    res = parse_policy_map(&policy_buf, out, sizeof(out), WALLET_POLICY_VERSION_V2);
    assert_int_equal(res, 0);
    policy_node_multisig_t *node_1 = (policy_node_multisig_t *) out;

    assert_int_equal(node_1->base.type, TOKEN_SORTEDMULTI);
    assert_int_equal(node_1->k, 2);
    assert_int_equal(node_1->n, 3);
    assert_int_equal(node_1->key_placeholders[0].key_index, 0);
    assert_int_equal(node_1->key_placeholders[0].num_first, 0);
    assert_int_equal(node_1->key_placeholders[0].num_second, 1);
    assert_int_equal(node_1->key_placeholders[1].key_index, 1);
    assert_int_equal(node_1->key_placeholders[1].num_first, 0);
    assert_int_equal(node_1->key_placeholders[1].num_second, 1);
    assert_int_equal(node_1->key_placeholders[2].key_index, 2);
    assert_int_equal(node_1->key_placeholders[2].num_first, 0);
    assert_int_equal(node_1->key_placeholders[2].num_second, 1);
}

static void test_parse_policy_map_multisig_2(void **state) {
    (void) state;

    uint8_t out[MAX_WALLET_POLICY_MEMORY_SIZE];

    int res;

    char *policy = "wsh(multi(3,@0/**,@1/**,@2/**,@3/**,@4/**))";
    buffer_t policy_buf = buffer_create((void *) policy, strlen(policy));

    res = parse_policy_map(&policy_buf, out, sizeof(out), WALLET_POLICY_VERSION_V2);
    assert_int_equal(res, 0);
    policy_node_with_script_t *root = (policy_node_with_script_t *) out;

    assert_int_equal(root->base.type, TOKEN_WSH);

    policy_node_multisig_t *inner = (policy_node_multisig_t *) root->script;
    assert_int_equal(inner->base.type, TOKEN_MULTI);

    assert_int_equal(inner->k, 3);
    assert_int_equal(inner->n, 5);
    for (int i = 0; i < 5; i++) {
        assert_int_equal(inner->key_placeholders[i].key_index, i);
        assert_int_equal(inner->key_placeholders[i].num_first, 0);
        assert_int_equal(inner->key_placeholders[i].num_second, 1);
    }
}

static void test_parse_policy_map_multisig_3(void **state) {
    (void) state;

    uint8_t out[MAX_WALLET_POLICY_MEMORY_SIZE];

    int res;

    char *policy = "sh(wsh(sortedmulti(3,@0/**,@1/**,@2/**,@3/**,@4/**)))";
    buffer_t policy_buf = buffer_create((void *) policy, strlen(policy));

    res = parse_policy_map(&policy_buf, out, sizeof(out), WALLET_POLICY_VERSION_V2);
    assert_int_equal(res, 0);
    policy_node_with_script_t *root = (policy_node_with_script_t *) out;

    assert_int_equal(root->base.type, TOKEN_SH);

    policy_node_with_script_t *mid = (policy_node_with_script_t *) root->script;
    assert_int_equal(mid->base.type, TOKEN_WSH);

    policy_node_multisig_t *inner = (policy_node_multisig_t *) mid->script;
    assert_int_equal(inner->base.type, TOKEN_SORTEDMULTI);

    assert_int_equal(inner->k, 3);
    assert_int_equal(inner->n, 5);
    for (int i = 0; i < 5; i++) {
        assert_int_equal(inner->key_placeholders[i].key_index, i);
        assert_int_equal(inner->key_placeholders[i].num_first, 0);
        assert_int_equal(inner->key_placeholders[i].num_second, 1);
    }
}

// convenience function to parse as one liners

static int parse_policy(char *policy, size_t policy_len, uint8_t *out, size_t out_len) {
    buffer_t in_buf = buffer_create((void *) policy, policy_len);
    return parse_policy_map(&in_buf, out, out_len, WALLET_POLICY_VERSION_V2);
}

#define PARSE_POLICY(policy, out, out_len) parse_policy(policy, sizeof(policy) - 1, out, out_len)

static void test_failures(void **state) {
    (void) state;

    uint8_t out[MAX_WALLET_POLICY_MEMORY_SIZE];

    // excess byte not allowed
    assert_true(0 > PARSE_POLICY("pkh(@0/**) ", out, sizeof(out)));

    // missing closing parenthesis
    assert_true(0 > PARSE_POLICY("pkh(@0/**", out, sizeof(out)));

    // unknown token
    assert_true(0 > PARSE_POLICY("yolo(@0/**)", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("Pkh(@0/**)", out, sizeof(out)));  // case-sensitive

    // missing or invalid key identifier
    assert_true(0 > PARSE_POLICY("pkh()", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("pkh(@)", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("pkh(0)", out, sizeof(out)));

    // sh not top-level
    assert_true(0 > PARSE_POLICY("sh(sh(pkh(@0/**)))", out, sizeof(out)));

    // wsh can only be inside sh
    assert_true(0 > PARSE_POLICY("wsh(wsh(pkh(@0/**)))", out, sizeof(out)));

    // wpkh can only be inside sh
    assert_true(0 > PARSE_POLICY("wsh(wpkh(@0/**)))", out, sizeof(out)));

    // multi with invalid threshold
    assert_true(0 > PARSE_POLICY("multi(6,@0/**,@1/**,@2/**,@3/**,@4/**)",
                                 out,
                                 sizeof(out)));  // threshold larger than n
    assert_true(0 > PARSE_POLICY("multi(0,@0/**,@1/**,@2/**,@3/**,@4/**)", out, sizeof(out)));
    // missing threshold or keys in multisig
    assert_true(0 > PARSE_POLICY("multi(@0/**,@1/**,@2/**,@3/**,@4/**)", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("multi(1)", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("multi(1,)", out, sizeof(out)));
}

enum TestMode {
    TESTMODE_INVALID = 0,
    TESTMODE_VALID = 1,
    TESTMODE_NONMAL = 2,
    TESTMODE_NEEDSIG = 4,
    TESTMODE_TIMELOCKMIX = 8  // ignored in our tests
};

static void Test(const char *ms, int mode) {
    char descriptor[1024];

    if (strlen(ms) + sizeof("wsh()") > sizeof(descriptor)) {
        assert(false);
    }

    // Wrap the miniscript inside "wsh"
    strcpy(descriptor, "wsh(");
    strcat(descriptor, ms);
    strcat(descriptor, ")");

    uint8_t out[MAX_WALLET_POLICY_MEMORY_SIZE];

    int res;
    buffer_t policy_buf = buffer_create((void *) descriptor, strlen(descriptor));

    res = parse_policy_map(&policy_buf, out, sizeof(out), WALLET_POLICY_VERSION_V2);

    if (mode == TESTMODE_INVALID) {
        assert_true(res < 0);
    } else {
        assert_true(res == 0);

        policy_node_with_script_t *policy = (policy_node_with_script_t *) out;
        policy_node_ext_info_t ext_info;
        res = compute_miniscript_policy_ext_info(policy->script, &ext_info);

        assert(res == 0);

        int is_expected_needsig = (mode & TESTMODE_NEEDSIG) ? 1 : 0;
        int is_expected_nonmal = (mode & TESTMODE_NONMAL) ? 1 : 0;

        assert(ext_info.s == is_expected_needsig);
        assert(ext_info.m == is_expected_nonmal);
    }
}

static void test_miniscript_types(void **state) {
    (void) state;

    // tests for miniscript type system
    // Tests taken from
    // https://github.com/bitcoin/bitcoin/blob/5bf65ec66e5986c9188e3f6234f1c5c0f8dc7f90/src/test/miniscript_tests.cpp,
    // except that all key expressions are replaced with placeholders @0/**, @1/**, ...

    // clang-format off
    Test("l:older(1)", TESTMODE_VALID | TESTMODE_NONMAL);     // older(1): valid
    Test("l:older(0)", TESTMODE_INVALID);                     // older(0): k must be at least 1
    Test("l:older(2147483647)", TESTMODE_VALID | TESTMODE_NONMAL);  // older(2147483647): valid
    Test("l:older(2147483648)", TESTMODE_INVALID);            // older(2147483648): k must be below 2^31
    Test("u:after(1)", TESTMODE_VALID | TESTMODE_NONMAL);     // after(1): valid
    Test("u:after(0)", TESTMODE_INVALID);                     // after(0): k must be at least 1
    Test("u:after(2147483647)", TESTMODE_VALID | TESTMODE_NONMAL);  // after(2147483647): valid
    Test("u:after(2147483648)", TESTMODE_INVALID);            // after(2147483648): k must be below 2^31
    Test("andor(0,1,1)", TESTMODE_VALID | TESTMODE_NONMAL);   // andor(Bdu,B,B): valid
    Test("andor(a:0,1,1)", TESTMODE_INVALID);                 // andor(Wdu,B,B): X must be B
    Test("andor(0,a:1,a:1)", TESTMODE_INVALID);               // andor(Bdu,W,W): Y and Z must be B/V/K
    Test("andor(1,1,1)", TESTMODE_INVALID);                   // andor(Bu,B,B): X must be d
    Test("andor(n:or_i(0,after(1)),1,1)", TESTMODE_VALID);    // andor(Bdu,B,B): valid
    Test("andor(or_i(0,after(1)),1,1)", TESTMODE_INVALID);    // andor(Bd,B,B): X must be u
    Test("c:andor(0,pk_k(@0/**),pk_k(@1/**))", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG);          // andor(Bdu,K,K): valid
    Test("t:andor(0,v:1,v:1)", TESTMODE_VALID | TESTMODE_NONMAL); // andor(Bdu,V,V): valid
    Test("and_v(v:1,1)", TESTMODE_VALID | TESTMODE_NONMAL);      // and_v(V,B): valid
    Test("t:and_v(v:1,v:1)", TESTMODE_VALID | TESTMODE_NONMAL);  // and_v(V,V): valid
    Test("c:and_v(v:1,pk_k(@0/**))", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG);  // and_v(V,K): valid
    Test("and_v(1,1)", TESTMODE_INVALID);                     // and_v(B,B): X must be V
    Test("and_v(pk_k(@0/**),1)", TESTMODE_INVALID);           // and_v(K,B): X must be V
    Test("and_v(v:1,a:1)", TESTMODE_INVALID);                 // and_v(K,W): Y must be B/V/K
    Test("and_b(1,a:1)", TESTMODE_VALID | TESTMODE_NONMAL);   // and_b(B,W): valid
    Test("and_b(1,1)", TESTMODE_INVALID);                     // and_b(B,B): Y must W
    Test("and_b(v:1,a:1)", TESTMODE_INVALID);                 // and_b(V,W): X must be B
    Test("and_b(a:1,a:1)", TESTMODE_INVALID);                 // and_b(W,W): X must be B
    Test("and_b(pk_k(@0/**),a:1)", TESTMODE_INVALID);         // and_b(K,W): X must be B
    Test("or_b(0,a:0)", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG);  // or_b(Bd,Wd): valid
    Test("or_b(1,a:0)", TESTMODE_INVALID);                    // or_b(B,Wd): X must be d
    Test("or_b(0,a:1)", TESTMODE_INVALID);                    // or_b(Bd,W): Y must be d
    Test("or_b(0,0)", TESTMODE_INVALID);                      // or_b(Bd,Bd): Y must W
    Test("or_b(v:0,a:0)", TESTMODE_INVALID);                  // or_b(V,Wd): X must be B
    Test("or_b(a:0,a:0)", TESTMODE_INVALID);                  // or_b(Wd,Wd): X must be B
    Test("or_b(pk_k(@0/**),a:0)", TESTMODE_INVALID);          // or_b(Kd,Wd): X must be B
    Test("t:or_c(0,v:1)", TESTMODE_VALID | TESTMODE_NONMAL);  // or_c(Bdu,V): valid
    Test("t:or_c(a:0,v:1)", TESTMODE_INVALID);                // or_c(Wdu,V): X must be B
    Test("t:or_c(1,v:1)", TESTMODE_INVALID);                  // or_c(Bu,V): X must be d
    Test("t:or_c(n:or_i(0,after(1)),v:1)", TESTMODE_VALID);   // or_c(Bdu,V): valid
    Test("t:or_c(or_i(0,after(1)),v:1)", TESTMODE_INVALID);   // or_c(Bd,V): X must be u
    Test("t:or_c(0,1)", TESTMODE_INVALID);                    // or_c(Bdu,B): Y must be V
    Test("or_d(0,1)", TESTMODE_VALID | TESTMODE_NONMAL);      // or_d(Bdu,B): valid
    Test("or_d(a:0,1)", TESTMODE_INVALID);                    // or_d(Wdu,B): X must be B
    Test("or_d(1,1)", TESTMODE_INVALID);                      // or_d(Bu,B): X must be d
    Test("or_d(n:or_i(0,after(1)),1)", TESTMODE_VALID);       // or_d(Bdu,B): valid
    Test("or_d(or_i(0,after(1)),1)", TESTMODE_INVALID);       // or_d(Bd,B): X must be u
    Test("or_d(0,v:1)", TESTMODE_INVALID);                    // or_d(Bdu,V): Y must be B
    Test("or_i(1,1)", TESTMODE_VALID);                        // or_i(B,B): valid
    Test("t:or_i(v:1,v:1)", TESTMODE_VALID);                  // or_i(V,V): valid
    Test("c:or_i(pk_k(@0/**),pk_k(@1/**))", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG);  // or_i(K,K): valid
    Test("or_i(a:1,a:1)", TESTMODE_INVALID);                  // or_i(W,W): X and Y must be B/V/K
    Test("or_b(l:after(100),al:after(1000000000))", TESTMODE_VALID);  // or_b(timelock, heighlock) valid
    Test("and_b(after(100),a:after(1000000000))", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_TIMELOCKMIX);  // and_b(timelock, heighlock) invalid
    Test("pk(@0/**)", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG);  // alias to c:pk_k
    Test("pkh(@0/**)", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG);  // alias to c:pk_h

    // Randomly generated test set that covers the majority of type and node type combinations
    Test("lltvln:after(1231488000)", TESTMODE_VALID | TESTMODE_NONMAL);
    Test("uuj:and_v(v:multi(2,@0/**,@1/**),after(1231488000))", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG);
    Test("or_b(un:multi(2,@0/**,@1/**),al:older(16))", TESTMODE_VALID);
    Test("j:and_v(vdv:after(1567547623),older(2016))", TESTMODE_VALID | TESTMODE_NONMAL);
    Test("t:and_v(vu:hash256(131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b),v:sha256(ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5))", TESTMODE_VALID | TESTMODE_NONMAL);
    Test("t:andor(multi(3,@0/**,@1/**,@2/**),v:older(4194305),v:sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2))", TESTMODE_VALID | TESTMODE_NONMAL);
    Test("or_d(multi(1,@0/**),or_b(multi(3,@1/**,@2/**,@3/**),su:after(500000)))", TESTMODE_VALID | TESTMODE_NONMAL);
    Test("or_d(sha256(38df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b6),and_n(un:after(499999999),older(4194305)))", TESTMODE_VALID);
    Test("and_v(or_i(v:multi(2,@0/**,@1/**),v:multi(2,@2/**,@3/**)),sha256(d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c68))", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG);
    Test("j:and_b(multi(2,@0/**,@1/**),s:or_i(older(1),older(4252898)))", TESTMODE_VALID | TESTMODE_NEEDSIG);
    Test("and_b(older(16),s:or_d(sha256(e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f),n:after(1567547623)))", TESTMODE_VALID);
    Test("j:and_v(v:hash160(20195b5a3d650c17f0f29f91c33f8f6335193d07),or_d(sha256(96de8fc8c256fa1e1556d41af431cace7dca68707c78dd88c3acab8b17164c47),older(16)))", TESTMODE_VALID);
    Test("and_b(hash256(32ba476771d01e37807990ead8719f08af494723de1d228f2c2c07cc0aa40bac),a:and_b(hash256(131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b),a:older(1)))", TESTMODE_VALID | TESTMODE_NONMAL);
    Test("thresh(2,multi(2,@0/**,@1/**),a:multi(1,@2/**),ac:pk_k(@3/**))", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG);
    Test("and_n(sha256(d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c68),t:or_i(v:older(4252898),v:older(144)))", TESTMODE_VALID);
    Test("or_d(nd:and_v(v:older(4252898),v:older(4252898)),sha256(38df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b6))", TESTMODE_VALID);
    Test("c:and_v(or_c(sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2),v:multi(1,@0/**)),pk_k(@1/**))", TESTMODE_VALID | TESTMODE_NEEDSIG);
    Test("c:and_v(or_c(multi(2,@0/**,@1/**),v:ripemd160(1b0f3c404d12075c68c938f9f60ebea4f74941a0)),pk_k(@2/**))", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG);
    Test("and_v(andor(hash256(8a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b25),v:hash256(939894f70e6c3a25da75da0cc2071b4076d9b006563cf635986ada2e93c0d735),v:older(50000)),after(499999999))", TESTMODE_VALID);
    Test("andor(hash256(5f8d30e655a7ba0d7596bb3ddfb1d2d20390d23b1845000e1e118b3be1b3f040),j:and_v(v:hash160(3a2bff0da9d96868e66abc4427bea4691cf61ccd),older(4194305)),ripemd160(44d90e2d3714c8663b632fcf0f9d5f22192cc4c8))", TESTMODE_VALID);
    Test("or_i(c:and_v(v:after(500000),pk_k(@0/**)),sha256(d9147961436944f43cd99d28b2bbddbf452ef872b30c8279e255e7daafc7f946))", TESTMODE_VALID | TESTMODE_NONMAL);
    Test("thresh(2,c:pk_h(@0/**),s:sha256(e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f),a:hash160(dd69735817e0e3f6f826a9238dc2e291184f0131))", TESTMODE_VALID);
    Test("and_n(sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2),uc:and_v(v:older(144),pk_k(@0/**)))", TESTMODE_VALID | TESTMODE_NEEDSIG);
    Test("and_n(c:pk_k(@0/**),and_b(l:older(4252898),a:older(16)))", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG | TESTMODE_TIMELOCKMIX);
    Test("c:or_i(and_v(v:older(16),pk_h(@0/**)),pk_h(@1/**))", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG);
    Test("or_d(c:pk_h(@0/**),andor(c:pk_k(@1/**),older(2016),after(1567547623)))", TESTMODE_VALID | TESTMODE_NONMAL);
    Test("c:andor(ripemd160(6ad07d21fd5dfc646f0b30577045ce201616b9ba),pk_h(@0/**),and_v(v:hash256(8a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b25),pk_h(@1/**)))", TESTMODE_VALID | TESTMODE_NEEDSIG);
    Test("c:andor(u:ripemd160(6ad07d21fd5dfc646f0b30577045ce201616b9ba),pk_h(@0/**),or_i(pk_h(@1/**),pk_h(@2/**)))", TESTMODE_VALID | TESTMODE_NEEDSIG);
    Test("c:or_i(andor(c:pk_h(@0/**),pk_h(@1/**),pk_h(@2/**)),pk_k(@3/**))", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG);
    Test("thresh(1,c:pk_k(@0/**),altv:after(1000000000),altv:after(100))", TESTMODE_VALID);
    Test("thresh(2,c:pk_k(@0/**),ac:pk_k(@1/**),altv:after(1000000000),altv:after(100))", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_TIMELOCKMIX);

    // clang-format on
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
