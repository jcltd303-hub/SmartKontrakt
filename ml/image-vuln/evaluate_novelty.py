"""Paired diagnostic on a fixed known benchmark; never used for model selection."""
import argparse
import glob
import hashlib
import json
import pickle
from pathlib import Path

import numpy as np
import torch
from core import CLASSES, clean_splits, hashes, labels, render
from novelty import novelty_indices, slice_metrics
from train import CNN, metrics, predict


def model_from_artifact(artifact):
    if artifact['architecture'] != 'rgb-cnn-64-v1' or artifact['classes'] != CLASSES:
        raise ValueError('Expected RGB CNN v1 with the documented class order')
    model = CNN()
    with torch.no_grad():
        for layer, conv in zip(artifact['layers'], model.convs):
            conv.weight.copy_(torch.tensor(layer['weight']).reshape(conv.weight.shape))
            conv.bias.copy_(torch.tensor(layer['bias']))
        model.linear.weight.copy_(torch.tensor(artifact['linear']['weight']).reshape(5, 384))
        model.linear.bias.copy_(torch.tensor(artifact['linear']['bias']))
    return model.eval()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cache', required=True)
    parser.add_argument('--baseline', required=True)
    parser.add_argument('--candidate', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    torch.set_num_threads(8)
    artifacts = {name: json.loads(Path(path).read_text()) for name, path in
                 [('baseline20k', args.baseline), ('fullTrain', args.candidate)]}
    seed = artifacts['fullTrain']['training']['seed']
    for artifact in artifacts.values():
        if artifact['training']['seed'] != seed:
            raise ValueError('Different seeds would change split ordering')
    rows = {split: [] for split in ('train', 'validation', 'test')}
    for split in rows:
        for path in sorted(glob.glob(str(Path(args.cache) / (split + '-*.pkl')))):
            with open(path, 'rb') as source:
                for row in pickle.load(source):
                    try:
                        row['hashes'] = hashes(row['bytecode'])
                    except ValueError:
                        continue
                    rows[split].append(row)
    rows, _ = clean_splits(rows)
    for split in rows:
        rows[split].sort(key=lambda row: hashlib.sha256((str(seed) + row['address']).encode()).hexdigest())
    seen, unseen = novelty_indices(*([r['bytecode'] for r in rows[s]] for s in ('train', 'validation', 'test')))
    ids = lambda indices: hashlib.sha256('\n'.join(rows['test'][i]['address'] for i in indices).encode()).hexdigest()
    result = {
        'protocol': 'Fixed repeated benchmark; no tuning from test/slice results. Exact normalized opcode-skeleton membership, not semantic family isolation or an external benchmark.',
        'noveltyReference': {'train': len(rows['train']), 'validation': len(rows['validation']),
                             'sharedCohortForBothModels': True},
        'slices': {name: {'count': len(indices), 'orderedAddressSha256': ids(indices)} for name, indices in [('seenSkeleton', seen), ('unseenSkeleton', unseen)]},
        'testOrderedAddressSha256': ids(list(range(len(rows['test'])))),
        'models': {},
    }
    tensors = {s: torch.from_numpy(np.stack([render(r['bytecode']) for r in rows[s]])) for s in ('validation', 'test')}
    targets = {s: np.stack([labels(r['slither']) for r in rows[s]]) for s in tensors}
    for name, artifact in artifacts.items():
        for split in tensors:
            if artifact['training']['counts'][split] != len(rows[split]):
                raise ValueError('Artifact/data evaluation split count mismatch')
        model = model_from_artifact(artifact)
        vp = predict(model, tensors['validation'])
        tp = predict(model, tensors['test'])
        result['models'][name] = {
            'trainCount': artifact['training']['counts']['train'],
            'artifactSha256': hashlib.sha256(Path(args.baseline if name == 'baseline20k' else args.candidate).read_bytes()).hexdigest(),
            'validation': metrics(targets['validation'], vp, artifact['thresholds']),
            'validationAtFixedHalfThreshold': metrics(targets['validation'], vp, [.5]*5),
            'test': metrics(targets['test'], tp, artifact['thresholds']),
            'testAtFixedHalfThreshold': metrics(targets['test'], tp, [.5]*5),
            **{slice_name: slice_metrics(targets['test'], tp, artifact['thresholds'], indices) for slice_name, indices in [('seenSkeleton', seen), ('unseenSkeleton', unseen)]},
        }
    # Promotion uses validation only; test/slice scores above never enter this decision.
    result['promotion'] = {
        'criterion': 'Strict improvement in validation macro F1; fixed architecture/hyperparameters',
        'selected': 'fullTrain' if result['models']['fullTrain']['validation']['macroF1'] > result['models']['baseline20k']['validation']['macroF1'] else 'baseline20k',
    }
    Path(args.output).write_text(json.dumps(result, indent=2, allow_nan=False))
    print(json.dumps({k: v for k, v in result.items() if k != 'models'}, indent=2))
    for name, value in result['models'].items():
        print(name, 'validation', value['validation']['microF1'], value['validation']['macroF1'],
              'test', value['test']['microF1'], value['test']['macroF1'],
              'unseen', value['unseenSkeleton']['count'], value['unseenSkeleton']['metrics'])


if __name__ == '__main__':
    main()
