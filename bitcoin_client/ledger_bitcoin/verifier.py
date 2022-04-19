import merkle as MT
import common

def verify_proof(root, proof, file_hash, file_index):
    if(file_index%2==0):
        flag = "even"
    else:
        flag = "odd"

    for i in range(0,len(proof)):
        if(flag == "even"):
            file_hash = MT.combine_hashes(file_hash,proof[i])
            flag = "odd"
        else:
            file_hash = MT.combine_hashes(proof[i],file_hash)
            flag = "even"

    calculated_root_hash = file_hash
    return calculated_root_hash == root
