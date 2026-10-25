import copy
import json
from pathlib import Path
import unittest
import tempfile
import export_resnet1d

class ExportMetadataTests(unittest.TestCase):
    def fixture(self):
        report=json.loads(Path(__file__).with_name('resnet1d-pilot6-evaluation.json').read_text())
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

    def test_normal_training_output_names_stage_usable_model_sidecars(self):
        report,payload=self.fixture()
        metadata=export_resnet1d.export_metadata(report,payload,report['checkpointSha256'],'evaluation.json','parity.json')
        self.assertEqual(metadata.get('referenceLocation'),'model-directory')
        self.assertEqual(metadata['evaluationReport'],'resnet1d-export-evaluation.json')
        import verify_resnet_browser
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);output=root/'model'
            evaluation=root/'evaluation.json';parity=root/'parity.json'
            evaluation.write_text(json.dumps(report));parity.write_text('{"cases":[]}')
            export_resnet1d.stage_export_references(evaluation,parity,output,metadata)
            reference=verify_resnet_browser.reference_path(metadata['evaluationReport'],'evaluation',output)
            self.assertEqual(json.loads(reference.read_text()),report)
            self.assertEqual((output/metadata['parityFile']).read_bytes(),parity.read_bytes())

if __name__=='__main__':unittest.main()
