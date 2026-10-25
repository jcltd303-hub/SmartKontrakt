"""Verify serialized trained weights reproduce stored Torch parity fixtures."""
import json
from pathlib import Path
import numpy as np
import torch
from train import CNN
from core import CLASSES,render
root=Path(__file__).resolve().parents[2]
artifact=json.loads((root/'public/models/bytecode-image-v1.json').read_text())
fixtures=json.loads((root/'public/models/bytecode-image-v1-parity.json').read_text())
assert artifact['classes']==CLASSES
assert artifact['architecture']=='rgb-cnn-64-v1'
model=CNN()
with torch.no_grad():
 for layer,c in zip(artifact['layers'],model.convs):
  c.weight.copy_(torch.tensor(layer['weight']).reshape(c.weight.shape));c.bias.copy_(torch.tensor(layer['bias']))
 model.linear.weight.copy_(torch.tensor(artifact['linear']['weight']).reshape(5,384));model.linear.bias.copy_(torch.tensor(artifact['linear']['bias']))
 for case in fixtures['cases']:
  p=torch.sigmoid(model(torch.from_numpy(render(case['bytecode'])[None]).float()/255))[0].numpy()
  np.testing.assert_allclose(p,case['probabilities'],rtol=1e-6,atol=1e-7)
assert artifact['evaluation']['microF1']>0
assert len(fixtures['cases'])==5
print('Verified 5 fixtures against reconstructed serialized trained model')
