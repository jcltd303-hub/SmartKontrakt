import copy
import json
from pathlib import Path
import unittest


class WindowEvaluationTests(unittest.TestCase):
    def test_test_scores_cannot_override_validation_or_collision_gate(self):
        from evaluate_resnet_windows import validation_decision
        baseline={'microF1':.73,'macroF1':.70}
        clean={'validationTrainingOverlapContracts':0,'testTrainingOverlapContracts':0,'validationTestSharedFingerprints':0}
        self.assertTrue(validation_decision(baseline,{'microF1':.74,'macroF1':.71},clean)['eligibleOnValidationAndInputAudit'])
        self.assertFalse(validation_decision(baseline,{'microF1':.74,'macroF1':.69},clean)['eligibleOnValidationAndInputAudit'])
        for key in clean:
            dirty={**clean,key:1}
            self.assertFalse(validation_decision(baseline,{'microF1':.99,'macroF1':.99},dirty)['eligibleOnValidationAndInputAudit'])

    def test_collision_audit_counts_contracts_once_and_checks_validation_test(self):
        from evaluate_resnet_windows import collision_audit
        result=collision_audit({b'train'},[{b'train',b'a'},{b'b'}],[{b'train',b'a'},{b'c'}])
        self.assertEqual(result['validationTrainingOverlapContracts'],1)
        self.assertEqual(result['testTrainingOverlapContracts'],1)
        self.assertEqual(result['validationTestSharedFingerprints'],2)

    def test_protocol_requires_exact_counts_and_all_content_hashes(self):
        from evaluate_resnet_windows import verify_protocol
        report=json.loads(Path(__file__).with_name('resnet1d-evaluation.json').read_text())
        counts=copy.deepcopy(report['protocol']['counts']);hashes=copy.deepcopy(report['protocol']['contentHashes'])
        verify_protocol(report,report['protocol'],counts,hashes)
        for split in ('train','validation','test'):
            wrong={**hashes,split:'0'*64}
            with self.assertRaises(ValueError):verify_protocol(report,report['protocol'],counts,wrong)
        with self.assertRaises(ValueError):verify_protocol(report,report['protocol'],{**counts,'test':1},hashes)

    def test_thresholds_use_only_passed_validation_and_match_grid_ties(self):
        import numpy as np
        from evaluate_resnet_windows import validation_thresholds
        y=np.array([[1]*5,[0]*5]);scores=np.array([[.8]*5,[.21]*5])
        thresholds=validation_thresholds(y,scores)
        self.assertTrue(all(abs(t-.225)<1e-12 for t in thresholds))
        with self.assertRaises(ValueError):validation_thresholds(y,np.full((2,5),np.nan))

    def test_ui_summary_comes_from_measured_report_without_changing_selection(self):
        from evaluate_resnet_windows import ui_summary
        report=json.loads(Path(__file__).with_name('resnet1d-window-evaluation.json').read_text())
        original=copy.deepcopy(report);summary=ui_summary(report)
        self.assertEqual(summary['checkpointSha256'],report['checkpointSha256'])
        self.assertEqual(summary['windows']['test']['microF1'],report['models']['windows']['test']['microF1'])
        self.assertEqual(summary['sharedValidationTestWindows'],report['inputAudit']['validationTestSharedFingerprints'])
        self.assertEqual(summary['unseenSkeletonCount'],report['novelty']['unseenSkeleton']['count'])
        self.assertEqual(report,original)


if __name__=='__main__':unittest.main()
