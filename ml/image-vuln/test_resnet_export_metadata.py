import copy
import json
from pathlib import Path
import unittest
import export_resnet1d

class ExportMetadataTests(unittest.TestCase):
    def fixture(self):
        report=json.loads(Path(__file__).with_name('resnet1d-evaluation.json').read_text())
        payload={k:copy.deepcopy(report[k]) for k in ('protocol','selectedEpoch','thresholds')}
        return report,payload

    def test_export_identity_and_provenance_follow_actual_selected_checkpoint(self):
        self.assertTrue(hasattr(export_resnet1d,'export_metadata'),'Export identity must follow its actual cohort and epoch')
        report,payload=self.fixture()
        metadata=export_resnet1d.export_metadata(report,payload,report['checkpointSha256'],'resnet1d-evaluation.json','resnet1d-parity.json')
        self.assertIn('train8192-epoch5',metadata['modelId'])
        self.assertEqual(metadata['training']['epochs'],6)
        self.assertEqual(metadata['evaluationReport'],'resnet1d-evaluation.json')

    def test_report_cannot_describe_a_different_checkpoint_or_protocol(self):
        self.assertTrue(hasattr(export_resnet1d,'export_metadata'))
        for field in ('selectedEpoch','protocol','thresholds'):
            report,payload=self.fixture()
            if field=='selectedEpoch':payload[field]=2
            elif field=='protocol':payload[field]['counts']['train']=55626
            else:payload[field]=[.5]*5
            with self.assertRaises(ValueError):export_resnet1d.export_metadata(report,payload,report['checkpointSha256'],'resnet1d-evaluation.json','resnet1d-parity.json')

if __name__=='__main__':unittest.main()
