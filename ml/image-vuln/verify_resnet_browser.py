"""Verify checked-in ONNX shards and independent selected-checkpoint fixtures."""
import hashlib
import json
import re
from pathlib import Path
import numpy as np
import onnx
import onnxruntime as ort
from resnet1d import sequence


def reference_path(name, kind, directory=None):
    if not isinstance(name,str) or len(name)>100 or not re.fullmatch(r'resnet1d(?:-[a-z0-9]+)*-'+kind+r'\.json',name):
        raise ValueError('Invalid model report reference')
    return (Path(directory) if directory is not None else Path(__file__).parent)/name


def verify(directory=Path('public/models')):
    manifest=json.loads((directory/'resnet1d-v1.json').read_text())
    location=manifest.get('referenceLocation','repository')
    if location not in ('repository','model-directory'):raise ValueError('Invalid report reference location')
    reference_directory=directory if location=='model-directory' else None
    report=json.loads(reference_path(manifest.get('evaluationReport','resnet1d-evaluation.json'),'evaluation',reference_directory).read_text())
    assert manifest['checkpointSha256']==report['checkpointSha256']
    assert manifest['thresholds']==report['thresholds']
    data=bytearray()
    for shard in manifest['shards']:
        part=(directory/shard['file']).read_bytes()
        assert len(part)==shard['bytes'] and hashlib.sha256(part).hexdigest()==shard['sha256']
        data.extend(part)
    assert len(data)==manifest['bytes'] and hashlib.sha256(data).hexdigest()==manifest['sha256']
    onnx.checker.check_model(onnx.load_model_from_string(bytes(data)))
    options=ort.SessionOptions(); options.intra_op_num_threads=2
    session=ort.InferenceSession(bytes(data),sess_options=options,providers=['CPUExecutionProvider'])
    fixtures=json.loads(reference_path(manifest.get('parityFile','resnet1d-parity.json'),'parity',reference_directory).read_text())['cases']
    error=0.0
    for case in fixtures:
        actual=session.run(None,{'bytecode':sequence(case['bytecode'])[None]})[0][0]
        expected=case.get('probabilities',case.get('scores'))
        assert np.isfinite(actual).all() and np.isfinite(expected).all(), 'Non-finite parity values'
        error=max(error,float(np.max(np.abs(actual-np.array(expected)))))
    assert np.isfinite(error) and error<=1e-5,error
    print(f'Checked-in ResNet ONNX: {len(fixtures)*5} scores, max error {error}, SHA256 {manifest["sha256"]}')

if __name__=='__main__': verify()
