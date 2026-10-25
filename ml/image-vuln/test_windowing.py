import unittest
import numpy as np


class WindowTests(unittest.TestCase):
    def test_short_input_matches_existing_zero_pad(self):
        from windowing import encoded_windows
        from resnet1d import encode_bytes
        code='0x6001ff'
        windows=list(encoded_windows(code))
        self.assertEqual(len(windows),1)
        np.testing.assert_array_equal(windows[0],encode_bytes(code))

    def test_window_starts_cover_head_middle_tail_within_budget(self):
        from windowing import window_starts, covered_bytes
        for length in (1,4,5,8,9,31,32):
            starts=window_starts(length,4,8)
            self.assertEqual(starts[0],0)
            self.assertLessEqual(len(starts),8)
            self.assertEqual(covered_bytes(length,starts,4),length)
            if length>4:self.assertEqual(starts[-1],length-4)

    def test_above_budget_is_bounded_and_reports_gaps(self):
        from windowing import window_starts, covered_bytes
        starts=window_starts(41,4,8)
        self.assertEqual(starts,window_starts(41,4,8))
        self.assertEqual((starts[0],starts[-1],len(starts)),(0,37,8))
        self.assertEqual(covered_bytes(41,starts,4),32)

    def test_tail_bytes_are_encoded_without_changing_prefix(self):
        from windowing import encoded_windows
        windows=list(encoded_windows('0x010203040506',4,8))
        np.testing.assert_array_equal(windows[0],[1,2,3,4])
        np.testing.assert_array_equal(windows[-1],[3,4,5,6])

    def test_normalization_fingerprint_protects_proportional_and_zero_vectors(self):
        from windowing import normalized_fingerprint
        a=np.array([1,2,0,0],dtype=np.uint8)
        self.assertEqual(normalized_fingerprint(a),normalized_fingerprint(a*2))
        self.assertNotEqual(normalized_fingerprint(a),normalized_fingerprint(a[::-1]))
        self.assertIsInstance(normalized_fingerprint(np.zeros(4,dtype=np.uint8)),bytes)

    def test_global_batches_keep_contract_ownership_and_prefix(self):
        from windowing import predict_windows
        batches=[]
        def predict(batch):
            batches.append(len(batch))
            return np.repeat(batch[:,0:1]/255.,5,axis=1)
        prefix,pooled,budget=predict_windows(['0x01020304ff060708','0x80000000'],predict,batch_size=2,window_size=4)
        np.testing.assert_allclose(prefix[:,0],[1/255.,128/255.])
        np.testing.assert_allclose(pooled[:,0],[1.,128/255.])
        self.assertEqual(batches,[2,1])
        self.assertEqual(budget['windows'],3)
        self.assertEqual(budget['contracts'],2)
        self.assertEqual(budget['coveredBytes'],budget['rawBytes'])

    def test_invalid_inputs_dimensions_and_predictions_fail_closed(self):
        from windowing import window_starts, encoded_windows, predict_windows
        for length,size,budget in [(0,4,8),(4,0,8),(4,4,0)]:
            with self.assertRaises(ValueError):window_starts(length,size,budget)
        for code in ('0x','0x0','0xzz'):
            with self.assertRaises(ValueError):list(encoded_windows(code))
        for bad in (np.full((1,5),np.nan),np.full((1,5),np.inf),np.ones((1,4)),np.full((1,5),1.01)):
            with self.assertRaises(ValueError):predict_windows(['0x00'],lambda _:bad)
        with self.assertRaises(ValueError):predict_windows(['0x00'],lambda _:np.zeros((1,5)),batch_size=0)


if __name__=='__main__':unittest.main()
