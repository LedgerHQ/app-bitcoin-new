// TODO: for all these commands, we could make some macros or helper functions to create the requests and responses.


#define CCMD_GET_SQUARE 0xFF

// TODO: CCMD_GET_PUBKEY_INFO and CCMD_GET_SORTED_PUBKEY_INFO asks info about keys of a specific wallet,
//       but the wallet id is implied from previous interaction. It might be worth adding the 32-bit wallet ID
//       in order to make each message stateless and unambiguous.
#define CCMD_GET_PUBKEY_INFO 0x01

#define CCMD_GET_SORTED_PUBKEY_INFO 0x02

// Request : <GET_PREIMAGE : 1> <hash : 20>
// Response: <len = preimage length : 1> <preimage : len>
#define CCMD_GET_PREIMAGE 0x40


// Request : <GET_MERKLE_LEAF_PROOF : 1> <merkle_root : 20> <tree_size: 4> <leaf_index: 4>
// Response: <leaf_hash: 20> <proof_size: 1> <n_proof_elements: 1> <proof_hash 1: 20> <proof_hash 2: 20> ... <proof_hash n_proof_elements: 20>
//           If n_proof_elements < proof_size, then subsequent elements will be given as responses of CCMD_GET_MORE_ELEMENTS.
#define CCMD_GET_MERKLE_LEAF_PROOF 0x41

// Used to get additional elements from the host when the required response from an interruption did not fit
// a single message.
// Request : <CCMD_GET_MORE_ELEMENTS : 1>
// Response: <n_elements : 1> <el_len = size of each element: 1> <element 1 : el_len> <element 2 : el_len> ... <element n_elements : el_len> 
#define CCMD_GET_MORE_ELEMENTS 0xA0


// TODO: commands to implement


// Given a Merkle root, uses GET_MERKLE_LEAF_PROOF and GET_PREIMAGE to verify that all the leaves of the Merkle tree are
// in lexicographical order.
#define CCMD_VERIFY_SORTED_MERKLE_TREE 0x42

