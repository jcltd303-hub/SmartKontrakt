import unittest
from continuation import annotate_continuation


class ContinuationTests(unittest.TestCase):
    def setUp(self):
        self.parent = {'protocol':{'seed':1},'epochs':2,'history':[{'epoch':1},{'epoch':2}], 'trainingAndEvaluationSeconds':100.0, 'checkpointSha256':'a'*64}
        self.current = {'protocol':{'seed':1},'epochs':6,'history':self.parent['history']+[{'epoch':i} for i in range(3,7)], 'trainingAndEvaluationSeconds':180.0}

    def test_records_exact_parent_and_current_timing_without_mutation(self):
        result = annotate_continuation(self.current,self.parent,'b'*64)
        self.assertEqual(result['resumeProvenance']['resumedFromEpoch'],2)
        self.assertEqual(result['resumeProvenance']['addedEpochs'],4)
        self.assertEqual(result['resumeProvenance']['cumulativeMeasuredInvocationSeconds'],280.0)
        self.assertEqual(result['resumeProvenance']['parentResumeCheckpointSha256'],'b'*64)
        self.assertNotIn('resumeProvenance', self.current)
        self.parent['resumeProvenance'] = {'cumulativeMeasuredInvocationSeconds':150.0}
        self.assertEqual(annotate_continuation(self.current,self.parent,'b'*64)['resumeProvenance']['cumulativeMeasuredInvocationSeconds'],330.0)

    def test_rejects_protocol_or_history_changes(self):
        changed = {**self.current,'protocol':{'seed':2}}
        with self.assertRaises(ValueError): annotate_continuation(changed,self.parent,'b'*64)
        changed = {**self.current,'history':[{'epoch':99}]+self.current['history'][1:]}
        with self.assertRaises(ValueError): annotate_continuation(changed,self.parent,'b'*64)
        with self.assertRaises(ValueError): annotate_continuation(self.parent,self.parent,'b'*64)

    def test_rejects_invalid_hashes(self):
        with self.assertRaises(ValueError): annotate_continuation(self.current,self.parent,'not-a-checksum')

class StepCounterTests(unittest.TestCase):
    def test_batchnorm_and_adam_steps_must_match_completed_batches(self):
        from continuation import verify_step_counters
        state={'model':{'layer.num_batches_tracked':1024},'optimizer':{'state':{0:{'step':1024.0}}}}
        self.assertEqual(verify_step_counters(state,1024),{'batchNormCounters':1,'optimizerCounters':1,'completedTrainingBatches':1024})
        with self.assertRaises(ValueError): verify_step_counters(state,3072)
        with self.assertRaises(ValueError): verify_step_counters({'model':{},'optimizer':{'state':{}}},1024)


if __name__ == '__main__': unittest.main()
