"""Offline candidate inference. Never executes a contract or contacts a chain."""
import argparse
import hashlib
import json
from pathlib import Path
import numpy as np
import torch
from core import CLASSES
from resnet1d import ResNet1D, SEQUENCE_LENGTH, encode_bytes, normalize_batch


def load_candidate(checkpoint):
    payload = torch.load(checkpoint, map_location='cpu', weights_only=True)
    protocol = payload.get('protocol', {})
    if (protocol.get('architecture') != 'upstream-resnet1d-16384-v1'
            or protocol.get('classes') != CLASSES
            or protocol.get('sequenceLength') != SEQUENCE_LENGTH
            or protocol.get('normalization') != 'per-example L2 after zero-pad/truncate'):
        raise ValueError('Unsupported ResNet1D checkpoint protocol')
    thresholds = payload.get('thresholds')
    if not isinstance(thresholds, list) or len(thresholds) != 5 or not all(isinstance(t, (int,float)) and 0 <= t <= 1 for t in thresholds):
        raise ValueError('Invalid class thresholds')
    model = ResNet1D()
    model.load_state_dict(payload['model'], strict=True)
    model.eval()
    return model, payload


def infer(model, payload, bytecode):
    with torch.no_grad():
        scores = torch.sigmoid(model(normalize_batch(torch.from_numpy(encode_bytes(bytecode)[None]))))[0].tolist()
    if not np.isfinite(scores).all():
        raise ValueError('Non-finite model output')
    return [{'label':label,'score':score,'threshold':threshold,'flagged':score >= threshold}
            for label,score,threshold in zip(CLASSES,scores,payload['thresholds'])]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--checkpoint', required=True)
    parser.add_argument('--bytecode-file', required=True)
    args = parser.parse_args()
    torch.set_num_threads(8)
    model, payload = load_candidate(args.checkpoint)
    print(json.dumps({'experimental':True,'architecture':payload['protocol']['architecture'],
                      'checkpointSha256':hashlib.sha256(Path(args.checkpoint).read_bytes()).hexdigest(),
                      'predictions':infer(model,payload,Path(args.bytecode_file).read_text()),
                      'notice':'Uncalibrated Slither-label signals, not confirmed exploitability or a safety verdict.'},indent=2))


if __name__ == '__main__':
    main()
