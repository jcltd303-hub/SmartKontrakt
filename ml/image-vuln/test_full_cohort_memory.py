import unittest
import tracemalloc
import numpy as np
import resnet1d

class FullCohortMemoryTests(unittest.TestCase):
    def test_encoding_matches_existing_inputs_without_a_second_full_matrix(self):
        rows = [{'bytecode':'0x0304'}, {'bytecode':'0x'+'ff'*17000}]
        rows = (rows*64)
        expected = np.stack([resnet1d.encode_bytes(r['bytecode']) for r in rows])
        self.assertTrue(hasattr(resnet1d,'encode_rows'), 'Full-cohort encoding needs a bounded-memory path')
        tracemalloc.start()
        actual = resnet1d.encode_rows(rows)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        np.testing.assert_array_equal(actual,expected)
        self.assertEqual(actual.dtype,np.uint8)
        self.assertLess(peak,actual.nbytes*1.5,'Do not retain a per-row array list alongside the full matrix')

if __name__=='__main__': unittest.main()
