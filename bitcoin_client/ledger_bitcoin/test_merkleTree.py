import common, verifier, merkle as MT
import unittest


class TestMerkle(unittest.TestCase):
    
    def test_floor_lg(self):
        self.assertEqual(MT.floor_lg(1), 0)
        self.assertEqual(MT.floor_lg(2), 1)
        self.assertEqual(MT.floor_lg(3), 1)
        self.assertEqual(MT.floor_lg(4), 2)
        self.assertEqual(MT.floor_lg(5), 2)  
        with self.assertRaises(AssertionError):
            MT.floor_lg(-1)

    def test_ceil_lg(self):
        self.assertEqual(MT.ceil_lg(1),0)
        self.assertEqual(MT.ceil_lg(2),1)
        self.assertEqual(MT.ceil_lg(3),2)
        self.assertEqual(MT.ceil_lg(4),2)
        with self.assertRaises(AssertionError):
            MT.floor_lg(0)
    
    def test_is_power_of_2(self):
        self.assertEqual(MT.is_power_of_2(1),1)
        self.assertEqual(MT.is_power_of_2(2),1)
        self.assertEqual(MT.is_power_of_2(3),0)
        self.assertEqual(MT.is_power_of_2(4),1)
        with self.assertRaises(AssertionError):
            MT.floor_lg(0)
    
    def test_element_hash(self):
        input = bytes([1]*32)
        self.assertEqual(MT.element_hash(input),common.sha256(b'\x00' + input))    
    
    def test_combine_hashes(self):
        input1 = bytes([1]*32)
        input2 = bytes([2]*32)
        self.assertEqual(MT.combine_hashes(input1,input2),common.sha256(b'\x01' + input1 + input2))
    
    def test_make_tree(self):
        input = [bytes([1]*32),bytes([2]*32),bytes([3]*32),bytes([4]*32),bytes([5]*32)]
        leaves = [MT.Node(None, None, None, el) for el in input]
        hash12 = MT.combine_hashes(input[0],input[1])
        hash34 = MT.combine_hashes(input[2],input[3])
        hash1234 = MT.combine_hashes(hash12,hash34)
        hash12345 = MT.combine_hashes(hash1234,input[4])
        self.assertEqual(MT.make_tree(leaves,0,5).value,hash12345)
    
    def test_prove_leaf(self):
        input = [bytes([1]*32),bytes([2]*32),bytes([3]*32),bytes([4]*32),bytes([5]*32)]
        merkleTree1 = MT.MerkleTree(input)

        #for file_index = 2
        file_index = 2
        
        proof = merkleTree1.prove_leaf(2)
        
        leaves = [MT.Node(None, None, None, el) for el in input]
        hash12 = MT.combine_hashes(input[0],input[1])
        hash34 = MT.combine_hashes(input[2],input[3])
        hash1234 = MT.combine_hashes(hash12,hash34)
        hash12345 = MT.combine_hashes(hash1234,input[4])
        
        self.assertEqual(proof[0],input[3])
        self.assertEqual(proof[1],hash12)
        self.assertEqual(proof[2],input[4])
           

if __name__ == '__main__':
    unittest.main()
