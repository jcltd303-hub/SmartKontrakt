import unittest
import numpy as np
from novelty import opcode_skeleton, novelty_indices, slice_metrics


class NoveltyTests(unittest.TestCase):
    def test_push_operands_and_widths_do_not_create_novelty(self):
        self.assertEqual(opcode_skeleton('600101'), opcode_skeleton('61ffff01'))
        self.assertEqual(opcode_skeleton('5f01'), opcode_skeleton('600001'))

    def test_push_data_is_not_interpreted_as_instructions(self):
        self.assertEqual(opcode_skeleton('615bff00'), bytes([0x60, 0x00]))
        self.assertEqual(opcode_skeleton('7fff'), bytes([0x60]))

    def test_metadata_does_not_create_novelty(self):
        self.assertEqual(opcode_skeleton('6000a1000002'), opcode_skeleton('6000'))

    def test_instruction_differences_remain_distinct(self):
        self.assertNotEqual(opcode_skeleton('600001'), opcode_skeleton('600002'))

    def test_bad_hex_is_rejected(self):
        for code in ['', '0xabc', 'contract C {}']:
            with self.assertRaises(ValueError):
                opcode_skeleton(code)

    def test_slices_use_train_and_validation_without_test_sibling_leakage(self):
        seen, unseen = novelty_indices(['600101'], ['600202'], ['600301', '600402', '600503', '600603'])
        self.assertEqual(seen, [0, 1])
        self.assertEqual(unseen, [2, 3])
        self.assertEqual(novelty_indices([], [], []), ([], []))
        self.assertEqual(novelty_indices([], [], ['00']), ([], [0]))

    def test_empty_slice_is_null_not_zero_quality(self):
        y = np.array([[1, 0, 0, 0, 0]], dtype=np.float32)
        p = np.array([[.8, .1, .1, .1, .1]])
        self.assertEqual(slice_metrics(y, p, [.5]*5, []), {'count': 0, 'metrics': None})
        result = slice_metrics(y, p, [.5]*5, [0])
        self.assertEqual(result['count'], 1)
        self.assertEqual(result['metrics']['microF1'], 1.0)


if __name__ == '__main__':
    unittest.main()
