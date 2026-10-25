import json
from pathlib import Path
import unittest


class ResNetContinuationReportTests(unittest.TestCase):
    def test_six_epoch_report_preserves_published_pilot_and_exact_protocol(self):
        root=Path(__file__).parent
        current=json.loads((root/'resnet1d-pilot6-evaluation.json').read_text())
        pilot=json.loads((root/'resnet1d-pilot2-evaluation.json').read_text())
        self.assertEqual(current['epochs'],6)
        self.assertEqual(pilot['epochs'],2)
        self.assertEqual(pilot['checkpointSha256'],'83a05a4b22b0c039077b77db6c55eecbd5c95aeb155e0fe92c2035fcc56e6897')
        self.assertEqual(current['protocol'],pilot['protocol'])
        self.assertEqual(current['history'][:2],pilot['history'])
        self.assertEqual(current['addressHashes'],pilot['addressHashes'])
        self.assertEqual(current['candidateFiltering'],pilot['candidateFiltering'])
        provenance=current['resumeProvenance']
        self.assertEqual(provenance['resumedFromEpoch'],2)
        self.assertEqual(provenance['addedEpochs'],4)
        self.assertEqual(provenance['parentSelectedCheckpointSha256'],pilot['checkpointSha256'])
        self.assertEqual(provenance['currentInvocationTrainingAndEvaluationSeconds'],current['trainingAndEvaluationSeconds'])
        self.assertAlmostEqual(provenance['cumulativeMeasuredInvocationSeconds'],pilot['trainingAndEvaluationSeconds']+current['trainingAndEvaluationSeconds'])


if __name__ == '__main__': unittest.main()
