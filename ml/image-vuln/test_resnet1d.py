import unittest
import numpy as np
import torch
from resnet1d import ResNet1D, ResBlock1D, sequence, encode_bytes, normalize_batch


class ResNetTests(unittest.TestCase):
    def test_sequence_pads_normalizes_and_keeps_bytes_after_512(self):
        code = '0x' + ('00'*16000) + 'ff'
        x = sequence(code)
        self.assertEqual(x.shape, (1, 16384))
        self.assertEqual(x[0, 16000], 1.0)
        self.assertEqual(x[0, 16001], 0.0)
        np.testing.assert_allclose(np.linalg.norm(x), 1.0)
        np.testing.assert_array_equal(sequence('00'), np.zeros((1,16384), dtype=np.float32))

    def test_batched_preprocessing_matches_single_sequence(self):
        codes = ['00', 'ff', '0x0102030405']
        batch = normalize_batch(torch.from_numpy(np.stack([encode_bytes(c) for c in codes])))
        np.testing.assert_allclose(batch.numpy(), np.stack([sequence(c) for c in codes]), rtol=1e-6, atol=1e-8)

    def test_sequence_truncates_at_16384_bytes(self):
        np.testing.assert_array_equal(sequence('ff'*16384+'ab'), sequence('ff'*16384))
        with self.assertRaises(ValueError):
            sequence('0xabc')

    def test_architecture_and_real_gradient_step(self):
        torch.set_num_threads(2)
        torch.manual_seed(9)
        model = ResNet1D()
        blocks = [module for module in model.modules() if isinstance(module, ResBlock1D)]
        self.assertEqual([b.conv1.out_channels for b in blocks], [128,128,256,256,256,512])
        self.assertEqual(model.classifier.in_features, 512)
        x = torch.randn(2,1,16384)
        before = model.classifier.weight.detach().clone()
        optimizer = torch.optim.Adam(model.parameters(), lr=.001)
        output = model(x)
        self.assertEqual(tuple(output.shape), (2,5))
        loss = torch.nn.functional.binary_cross_entropy_with_logits(output, torch.zeros(2,5))
        loss.backward()
        optimizer.step()
        self.assertTrue(torch.isfinite(output).all())
        self.assertFalse(torch.equal(before, model.classifier.weight))
        model.eval()
        self.assertTrue(torch.equal(model(x), model(x)))

class CandidateLeakageTests(unittest.TestCase):
    def test_truncation_and_scale_collisions_are_removed_from_training(self):
        from resnet1d import filter_candidate_training
        base = '01'*16384
        rows = {'train':[{'bytecode':base+'02'},{'bytecode':'020406'},{'bytecode':'030201'}],
                'validation':[{'bytecode':base+'03'}], 'test':[{'bytecode':'010203'}]}
        filtered, stats = filter_candidate_training(rows)
        self.assertEqual([r['bytecode'] for r in filtered['train']], ['030201'])
        self.assertEqual(filtered['validation'], rows['validation'])
        self.assertEqual(filtered['test'], rows['test'])
        self.assertEqual(stats['trainingRowsDropped'], 2)

    def test_validation_test_candidate_overlap_is_rejected(self):
        from resnet1d import filter_candidate_training
        with self.assertRaises(ValueError):
            filter_candidate_training({'train':[], 'validation':[{'bytecode':'01'}], 'test':[{'bytecode':'02'}]})


if __name__ == '__main__':
    unittest.main()
