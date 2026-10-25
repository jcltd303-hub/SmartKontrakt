"""Pin shipped weights to their measured reports and split cohort."""
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ReportTests(unittest.TestCase):
    def test_selected_artifact_and_report_agree(self):
        raw = (ROOT / 'public/models/bytecode-image-v1.json').read_bytes()
        model = json.loads(raw)
        evaluation = json.loads((Path(__file__).with_name('evaluation.json')).read_text())
        comparison = json.loads((Path(__file__).with_name('full-training-comparison.json')).read_text())
        audit = json.loads((Path(__file__).with_name('dataset-audit.json')).read_text())
        selected = comparison['models'][comparison['promotion']['selected']]
        self.assertEqual(selected['artifactSha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(model['training'], evaluation['training'])
        self.assertEqual(model['evaluation'], evaluation['test'])
        self.assertEqual(model['thresholds'], evaluation['thresholds'])
        self.assertEqual(model['training']['counts']['train'], model['training']['availableTrainAfterDedup'])
        self.assertEqual(model['training']['counts']['train'], audit['selectionFingerprints']['train']['count'])
        self.assertEqual(comparison['testOrderedAddressSha256'], audit['selectionFingerprints']['test']['orderedAddressSha256'])
        self.assertEqual(sum(s['count'] for s in comparison['slices'].values()), model['training']['counts']['test'])

    def test_both_models_report_validation_micro_and_fixed_threshold_metrics(self):
        comparison = json.loads((Path(__file__).with_name('full-training-comparison.json')).read_text())
        for model in comparison['models'].values():
            self.assertGreater(model['validation']['microF1'], 0)
            self.assertIn('validationAtFixedHalfThreshold', model)
            self.assertGreater(model['validationAtFixedHalfThreshold']['microF1'], 0)
        expected = 'fullTrain' if comparison['models']['fullTrain']['validation']['macroF1'] > comparison['models']['baseline20k']['validation']['macroF1'] else 'baseline20k'
        self.assertEqual(comparison['promotion']['selected'], expected)


if __name__ == '__main__':
    unittest.main()
