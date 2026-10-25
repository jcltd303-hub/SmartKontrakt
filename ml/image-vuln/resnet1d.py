"""Long raw-byte residual classifier, adapted from Martina Rossini (MIT, 2022).

Upstream d755f0f2232ce9ef873150ab0dbb0043f04ebded,
src/modeling/network/backbone/resnet_1d.py. License: LICENSE.upstream.
This preserves its feature architecture, with five outputs in this project's
class order. Inputs are 16,384 raw bytes, zero padded, then L2 normalized.
"""
import numpy as np
import torch
from torch import nn
from core import raw_bytes

SEQUENCE_LENGTH = 16384


def encode_bytes(code):
    raw = raw_bytes(code)[:SEQUENCE_LENGTH]
    values = np.zeros(SEQUENCE_LENGTH, dtype=np.uint8)
    values[:len(raw)] = np.frombuffer(raw, dtype=np.uint8)
    return values


def encode_rows(rows):
    """Allocate one uint8 matrix, rather than stacking a second full copy."""
    values = np.empty((len(rows), SEQUENCE_LENGTH), dtype=np.uint8)
    for index, row in enumerate(rows):
        values[index] = encode_bytes(row['bytecode'])
    return values


def normalize_batch(values):
    return torch.nn.functional.normalize(values.float(), dim=-1).unsqueeze(1)


def sequence(code):
    values = encode_bytes(code).astype(np.float32)
    norm = np.linalg.norm(values)
    if norm:
        values /= norm
    return values[None]


class ResBlock1D(nn.Module):
    def __init__(self, channels):
        super().__init__()
        self.conv1 = nn.Conv1d(channels, channels, 3, padding=1)
        self.bn1 = nn.BatchNorm1d(channels)
        self.conv2 = nn.Conv1d(channels, channels, 3, padding=1)
        self.bn2 = nn.BatchNorm1d(channels)
        self.relu = nn.LeakyReLU()

    def forward(self, inputs):
        x = self.relu(self.bn1(self.conv1(inputs)))
        return self.relu(self.bn2(self.conv2(x)) + inputs)


class ResNet1D(nn.Module):
    def __init__(self):
        super().__init__()
        self.layers = nn.Sequential(
            nn.Conv1d(1, 128, 3, stride=3), nn.BatchNorm1d(128), nn.LeakyReLU(),
            ResBlock1D(128), nn.MaxPool1d(3, 3),
            ResBlock1D(128), nn.MaxPool1d(3, 3),
            nn.Conv1d(128, 256, 3, padding=1), nn.BatchNorm1d(256), nn.LeakyReLU(),
            ResBlock1D(256), nn.MaxPool1d(3, 3),
            ResBlock1D(256), nn.MaxPool1d(3, 3),
            ResBlock1D(256), nn.MaxPool1d(3, 3),
            nn.Conv1d(256, 512, 3, padding=1), nn.BatchNorm1d(512), nn.LeakyReLU(),
            ResBlock1D(512), nn.MaxPool1d(3, 3),
            nn.Conv1d(512, 512, 1), nn.BatchNorm1d(512), nn.LeakyReLU(),
            nn.AdaptiveAvgPool1d(1), nn.Dropout(.4), nn.Flatten(),
        )
        self.classifier = nn.Linear(512, 5)

    def forward(self, inputs):
        return self.classifier(self.layers(inputs))


def filter_candidate_training(rows):
    """Protect fixed held-out splits from truncation and L2-scale collisions.

    Integer gcd gives a canonical proportional byte vector, conservatively
    treating mathematically equal L2-normalized inputs as duplicates even if
    floating point reduction differs by a bit across hardware.
    """
    import hashlib
    def fingerprint(row):
        values = encode_bytes(row['bytecode'])
        divisor = int(np.gcd.reduce(values)) or 1
        return hashlib.sha256((values // divisor).tobytes()).digest()
    validation = {fingerprint(row) for row in rows['validation']}
    test = {fingerprint(row) for row in rows['test']}
    if validation & test:
        raise ValueError('Validation/test inputs collide after candidate preprocessing; evaluation split needs revision')
    held_out = validation | test
    retained = []; dropped = []
    for row in rows['train']:
        if fingerprint(row) in held_out:
            dropped.append(row.get('address', 'unspecified'))
        else:
            retained.append(row)
    return {**rows, 'train':retained}, {
        'fingerprint':'16384-byte padded/truncated integer vector divided by gcd, then SHA256; protects proportional L2 inputs',
        'trainingRowsDropped':len(dropped),'trainingAddressesDropped':dropped,
        'availableTrainAfterCandidateFiltering':len(retained),
        'validationTestSharedFingerprints':0,
        'validationUniqueFingerprints':len(validation),'testUniqueFingerprints':len(test),
    }
