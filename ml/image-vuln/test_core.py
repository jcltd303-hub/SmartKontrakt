import unittest
from core import *
class Tests(unittest.TestCase):
 def test_odd_number_of_bytes(self):
  x=render('0x0102030405');self.assertEqual(x.shape,(3,64,64));self.assertEqual(x[:,0,0].tolist(),[1,2,3]);self.assertEqual(x[:,-1,-1].tolist(),[0,0,0])
 def test_tiny(self):self.assertEqual(render('ff')[:,0,0].tolist(),[255,0,0])
 def test_labels(self):self.assertEqual(labels([0,2,4,5]).tolist(),[1,0,0,1,1])
 def test_cross_split(self):
  r={'hashes':hashes('ff')};out,stats=clean_splits({'train':[r],'test':[r]});self.assertEqual(out,{'train':[],'test':[]})
 def test_image_collision_across_splits(self):
  a={'hashes':hashes('00')};b={'hashes':hashes('000000')}
  self.assertNotEqual(a['hashes'][0],b['hashes'][0]);out,_=clean_splits({'train':[a],'test':[b]});self.assertEqual(out,{'train':[],'test':[]})
 def test_metadata_normalization(self):
  self.assertEqual(hashes('6000a1000002')[1],hashes('6000')[0])
 def test_invalid(self):
  with self.assertRaises(ValueError):render('abc')
if __name__=='__main__':unittest.main()
