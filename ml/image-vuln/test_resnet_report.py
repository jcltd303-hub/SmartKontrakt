"""Require measured candidate reports to remain consistent with fixed cohorts."""
import json
from pathlib import Path
import re
import unittest
from core import CLASSES


class ResNetReportTests(unittest.TestCase):
    def test_completed_candidate_report_matches_protocol_and_selection(self):
        path = Path(__file__).with_name('resnet1d-evaluation.json')
        self.assertTrue(path.is_file(), 'Completed candidate report must be present')
        report = json.loads(path.read_text())
        protocol = report['protocol']
        self.assertEqual(protocol['architecture'], 'upstream-resnet1d-16384-v1')
        self.assertEqual(protocol['classes'], CLASSES)
        self.assertEqual(protocol['sequenceLength'], 16384)
        self.assertEqual(protocol['counts']['train'], 8192)
        audit = json.loads(path.with_name('dataset-audit.json').read_text())
        for split in ('validation','test'):
            self.assertEqual(protocol['counts'][split], audit['selectionFingerprints'][split]['count'])
            self.assertEqual(report['addressHashes'][split], audit['selectionFingerprints'][split]['orderedAddressSha256'])
        self.assertEqual(report['candidateFiltering']['trainingRowsDropped'], 6)
        self.assertEqual(report['candidateFiltering']['validationTestSharedFingerprints'], 0)
        best = max(report['history'], key=lambda epoch: epoch['validation']['microF1'])
        self.assertEqual(report['selectedEpoch'], best['epoch'])
        self.assertEqual(report['thresholds'], best['thresholds'])
        self.assertEqual(len(report['history']), report['epochs'])
        expected = (best['validation']['microF1'] > report['rgbBaseline']['validation']['microF1'] and
                    best['validation']['macroF1'] > report['rgbBaseline']['validation']['macroF1'])
        self.assertEqual(report['promotionEligibleOnValidation'], expected)
        self.assertIsNotNone(re.fullmatch(r'[a-f0-9]{64}', report['checkpointSha256']))
        self.assertEqual([row['class'] for row in report['test']['perClass']], CLASSES)
        for metric in ('microF1','macroF1','exactMatch'):
            self.assertTrue(0 <= report['test'][metric] <= 1)


if __name__ == '__main__':
    unittest.main()
