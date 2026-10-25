import copy
import json
from pathlib import Path
import unittest

class FullCohortReportTests(unittest.TestCase):
    def fixture(self, micro=.70, macro=.65):
        baseline=json.loads(Path(__file__).with_name('resnet1d-pilot6-evaluation.json').read_text())
        current=copy.deepcopy(baseline)
        current['protocol']['counts']['train']=55626
        current['protocol']['trainCap']=55632
        current['protocol']['contentHashes']['train']='d'*64
        current['epochs']=2;current['selectedEpoch']=2
        current['history']=current['history'][:2]
        current['history'][0]['validation']['microF1']=.60
        current['history'][1]['validation']['microF1']=micro
        current['history'][1]['validation']['macroF1']=macro
        current['thresholds']=current['history'][1]['thresholds']
        current['checkpointSha256']='b'*64
        return current,baseline

    def test_cli_default_self_comparison_refuses_to_overwrite_recorded_decision(self):
        import hashlib
        import io
        import tempfile
        from contextlib import redirect_stdout
        from unittest.mock import patch
        import full_cohort_report
        current,_=self.fixture()
        checkpoint=b'checkpoint'
        current['checkpointSha256']=hashlib.sha256(checkpoint).hexdigest()
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);out=root/'run';out.mkdir()
            original=json.dumps(current)
            (root/'resnet1d-evaluation.json').write_text(original)
            (out/'evaluation.json').write_text(original)
            (out/'selected.pt').write_bytes(checkpoint)
            with patch.object(full_cohort_report,'__file__',str(root/'full_cohort_report.py')), patch('sys.argv',['full_cohort_report.py','--directory',str(out)]), redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError,'identical.*--baseline'):
                    full_cohort_report.main()
            self.assertEqual((out/'evaluation.json').read_text(),original)
            self.assertFalse((out/'raw-evaluation.json').exists())

    def test_rgb_improvement_alone_cannot_replace_the_better_resnet(self):
        from full_cohort_report import annotate_full_cohort
        current,baseline=self.fixture(.65,.61)
        current['test']['microF1']=1.;current['test']['macroF1']=1.
        result=annotate_full_cohort(current,baseline)
        self.assertFalse(result['browserPromotion']['eligibleOnValidation'])
        self.assertFalse(result['promotionEligibleOnValidation'])
        self.assertTrue(result['rgbPromotionEligibleOnValidation'])
        self.assertFalse(result['browserPromotion']['deploymentVerified'])

    def test_both_selected_validation_metrics_must_improve(self):
        from full_cohort_report import annotate_full_cohort
        for micro,macro,expected in [(.70,.65,True),(.70,.62,False)]:
            current,baseline=self.fixture(micro,macro)
            self.assertEqual(annotate_full_cohort(current,baseline)['browserPromotion']['eligibleOnValidation'],expected)

    def test_changed_holdout_or_incomplete_cohort_is_rejected(self):
        from full_cohort_report import annotate_full_cohort
        for mutation in ('hash','count'):
            current,baseline=self.fixture()
            if mutation=='hash':current['protocol']['contentHashes']['test']='c'*64
            else:current['protocol']['counts']['train']=8192
            with self.assertRaises(ValueError):annotate_full_cohort(current,baseline)

    def test_selection_must_use_best_validation_micro_epoch(self):
        from full_cohort_report import annotate_full_cohort
        current,baseline=self.fixture();current['selectedEpoch']=1
        with self.assertRaises(ValueError):annotate_full_cohort(current,baseline)

if __name__=='__main__':unittest.main()
