import tempfile
from pathlib import Path
import unittest
import torch
from checkpoint import save_checkpoint, restore_checkpoint


class CheckpointTests(unittest.TestCase):
    def test_resume_restores_optimizer_and_dropout_rng(self):
        torch.manual_seed(17)
        model = torch.nn.Sequential(torch.nn.Linear(3,3), torch.nn.Dropout(.4))
        optimizer = torch.optim.Adam(model.parameters(), lr=.01)
        x = torch.ones(2,3)
        def step():
            optimizer.zero_grad(); loss = model(x).square().mean(); loss.backward(); optimizer.step()
        step()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'last.pt'
            protocol = {'seed':17,'classes':['one','two']}
            save_checkpoint(path, {'protocol':protocol, 'model':model.state_dict(), 'optimizer':optimizer.state_dict(), 'rng':torch.get_rng_state(), 'epoch':1})
            step(); expected = [p.detach().clone() for p in model.parameters()]
            restored = restore_checkpoint(path, model, optimizer, protocol)
            self.assertEqual(restored['epoch'], 1)
            step()
            for actual, wanted in zip(model.parameters(), expected):
                self.assertTrue(torch.equal(actual, wanted))
            with self.assertRaises(ValueError):
                restore_checkpoint(path, model, optimizer, {'seed':18})

class CandidateTests(unittest.TestCase):
    def test_tensor_checkpoint_load_and_inference_are_deterministic(self):
        from core import CLASSES
        from resnet1d import ResNet1D
        from infer_resnet1d import load_candidate, infer
        torch.set_num_threads(2)
        torch.manual_seed(31)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'selected.pt'
            protocol = {'architecture':'upstream-resnet1d-16384-v1','classes':CLASSES,'sequenceLength':16384,'normalization':'per-example L2 after zero-pad/truncate'}
            save_checkpoint(path, {'protocol':protocol,'model':ResNet1D().state_dict(),'thresholds':[.5]*5,'selectedEpoch':1})
            model, payload = load_candidate(path)
            first = infer(model,payload,'ff')
            self.assertEqual(first,infer(model,payload,'ff'))
            self.assertEqual([p['label'] for p in first], CLASSES)
            self.assertTrue(all(0 <= p['score'] <= 1 for p in first))
            payload['protocol']['normalization'] = 'unsupported'
            save_checkpoint(path, payload)
            with self.assertRaises(ValueError):
                load_candidate(path)
            save_checkpoint(path, {'protocol':{},'model':{}})
            with self.assertRaises(ValueError):
                load_candidate(path)

class OutputTests(unittest.TestCase):
    def test_existing_training_output_requires_explicit_resume(self):
        from checkpoint import prepare_output
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            self.assertEqual(prepare_output(path, None), path)
            (path/'last.pt').write_bytes(b'existing checkpoint')
            with self.assertRaises(ValueError):
                prepare_output(path, None)
            self.assertEqual(prepare_output(path, str(path/'last.pt')), path)
            with self.assertRaises(ValueError):
                prepare_output(path, str(path/'missing.pt'))


if __name__ == '__main__':
    unittest.main()
