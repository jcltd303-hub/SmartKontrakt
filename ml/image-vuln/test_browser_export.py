import unittest
import tempfile
from pathlib import Path
import torch
from resnet1d import ResNet1D

class BrowserExportTests(unittest.TestCase):
    def test_export_preserves_float_predictions_and_bounds_shards(self):
        import export_resnet1d
        torch.set_num_threads(2)
        model = ResNet1D().eval()
        cases = [{'bytecode':'0x00'},{'bytecode':'0x60ff600155'}]
        with tempfile.TemporaryDirectory() as directory:
            manifest = export_resnet1d.export_model(model, [.5]*5, cases, Path(directory), 'a'*64, {})
            self.assertEqual(manifest['sequenceLength'],16384)
            self.assertLessEqual(manifest['parityMaxAbsoluteError'],1e-5)
            self.assertEqual(sum(s['bytes'] for s in manifest['shards']),manifest['bytes'])
            self.assertTrue(all(s['bytes'] <= 1024*1024 for s in manifest['shards']))
            self.assertTrue(all((Path(directory)/s['file']).exists() for s in manifest['shards']))

    def test_nonfinite_model_predictions_are_not_reported_as_parity(self):
        import export_resnet1d
        torch.set_num_threads(2)
        model=ResNet1D().eval()
        with torch.no_grad(): model.classifier.bias.fill_(float('nan'))
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                export_resnet1d.export_model(model,[.5]*5,[{'bytecode':'0x00'}],Path(directory),'a'*64,{})

if __name__ == '__main__': unittest.main()
