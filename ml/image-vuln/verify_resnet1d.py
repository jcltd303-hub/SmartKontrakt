"""Reconstruct exported offline candidate and verify independent saved scores."""
import argparse
import hashlib
import json
from pathlib import Path
import numpy as np
import torch
from infer_resnet1d import load_candidate, infer


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', required=True)
    args = parser.parse_args()
    directory = Path(args.directory)
    report = json.loads((directory/'evaluation.json').read_text())
    parity = json.loads((directory/'parity.json').read_text())
    checkpoint = directory/'selected.pt'
    if hashlib.sha256(checkpoint.read_bytes()).hexdigest() != report['checkpointSha256']:
        raise ValueError('Checkpoint does not match evaluation report')
    torch.set_num_threads(8)
    model, payload = load_candidate(checkpoint)
    assert payload['protocol'] == report['protocol']
    assert payload['selectedEpoch'] == report['selectedEpoch']
    assert payload['thresholds'] == report['thresholds']
    assert parity['classes'] == payload['protocol']['classes']
    for case in parity['cases']:
        predictions = infer(model,payload,case['bytecode'])
        np.testing.assert_allclose([p['score'] for p in predictions],case['probabilities'],rtol=1e-5,atol=1e-6)
    print(f"Verified {len(parity['cases'])} ResNet1D cases against reconstructed trained checkpoint")


if __name__ == '__main__':
    main()
