import unittest
from pathlib import Path
import verify_resnet_browser

class BrowserReportReferenceTests(unittest.TestCase):
    def test_active_model_can_reference_its_full_cohort_evaluation(self):
        self.assertTrue(hasattr(verify_resnet_browser,'reference_path'))
        path=verify_resnet_browser.reference_path('resnet1d-full-evaluation.json','evaluation')
        self.assertEqual(path,Path(verify_resnet_browser.__file__).parent/'resnet1d-full-evaluation.json')
        for invalid in ('../evaluation.json','resnet1d-full-parity.json','/tmp/resnet1d-full-evaluation.json'):
            with self.assertRaises(ValueError):verify_resnet_browser.reference_path(invalid,'evaluation')

if __name__=='__main__':unittest.main()
