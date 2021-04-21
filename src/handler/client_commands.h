// TODO: for all these commands, we could make some macros or helper functions to create the requests and responses.


/* WALLETS/SCRIPTS */

// Request : <CCMD_GET_PUBKEYS_IN_DERIVATION_ORDER : 1> <merkle_root : 20> <tree_size: 4> <steps (max 10) : 1> <der_1 : 4> <der_2 : 4> ... <der_steps : 4> <n_key_indexes : 1> <index_1 : 1> ... <index_n : 1>
// Response: <n_key_indexes : 1> <sorted_index_1 : 1> ... <sorted_index_n : 1>
#define CCMD_GET_PUBKEYS_IN_DERIVATION_ORDER 0x20


/* MERKLE PROOFS */

// Request : <GET_PREIMAGE : 1> <hash : 20>
// Response: <len = preimage length : 1> <preimage : len>
#define CCMD_GET_PREIMAGE 0x40

// Request : <GET_MERKLE_LEAF_PROOF : 1> <merkle_root : 20> <tree_size: 4> <leaf_index: 4>
// Response: <leaf_hash: 20> <proof_size: 1> <n_proof_elements: 1> <proof_hash 1: 20> <proof_hash 2: 20> ... <proof_hash n_proof_elements: 20>
//           If n_proof_elements < proof_size, then subsequent elements will be given as responses of CCMD_GET_MORE_ELEMENTS.
#define CCMD_GET_MERKLE_LEAF_PROOF 0x41


// Request : <CCMD_GET_MERKLE_LEAF_INDEX : 1> <merkle_root : 20> <leaf_hash : 20>
// Response: <is_found(0 or 1) : 1> <leaf_index : 4>
#define CCMD_GET_MERKLE_LEAF_INDEX 0x42


/* GENERIC/MULTIPURPOSE */

// Used to get additional elements from the host when the required response from an interruption did not fit
// a single message.
// Request : <CCMD_GET_MORE_ELEMENTS : 1>
// Response: <n_elements : 1> <el_len = size of each element: 1> <element 1 : el_len> <element 2 : el_len> ... <element n_elements : el_len> 
#define CCMD_GET_MORE_ELEMENTS 0xA0
