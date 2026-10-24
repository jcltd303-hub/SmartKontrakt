"""Resumable real ResNet1D pilot, with validation-only checkpoint selection."""
import argparse
import glob
import hashlib
import json
import time
from pathlib import Path
import pickle
import numpy as np
import torch
from core import CLASSES, clean_splits, hashes, labels, raw_bytes
from resnet1d import ResNet1D, SEQUENCE_LENGTH, encode_bytes, encode_rows, normalize_batch, filter_candidate_training
from checkpoint import save_checkpoint, restore_checkpoint, prepare_output
from train import metrics


def load_rows(cache, seed, cap):
    rows = {s: [] for s in ('train','validation','test')}
    invalid = {s:0 for s in rows}
    for split in rows:
        for path in sorted(glob.glob(str(Path(cache)/(split+'-*.pkl')))):
            with open(path, 'rb') as source:
                for row in pickle.load(source):
                    try:
                        row['hashes'] = hashes(row['bytecode'])
                    except ValueError:
                        invalid[split] += 1
                        continue
                    rows[split].append(row)
        if not rows[split]:
            raise ValueError('Missing valid cached split: '+split)
    rows, dedup = clean_splits(rows)
    rows, candidate_filtering = filter_candidate_training(rows)
    for split in rows:
        rows[split].sort(key=lambda r: hashlib.sha256((str(seed)+r['address']).encode()).hexdigest())
    rows['train'] = rows['train'][:cap]
    if any(not items for items in rows.values()):
        raise ValueError('Empty split after filtering')
    return rows, dedup, invalid, candidate_filtering


def probabilities(model, data, batch_size):
    model.eval()
    with torch.no_grad():
        return np.concatenate([torch.sigmoid(model(normalize_batch(batch))).numpy()
                               for batch in data.split(batch_size)])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cache', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--train-cap', type=int, default=8192)
    parser.add_argument('--epochs', type=int, default=2, help='Total completed epochs, including resume history')
    parser.add_argument('--batch-size', type=int, default=16)
    parser.add_argument('--threads', type=int, default=8)
    parser.add_argument('--seed', type=int, default=20261024)
    parser.add_argument('--resume')
    args = parser.parse_args()
    if min(args.train_cap, args.epochs, args.batch_size, args.threads) < 1:
        parser.error('Training dimensions must be positive')
    try:
        out = prepare_output(args.output, args.resume)
    except ValueError as error:
        parser.error(str(error))
    torch.set_num_threads(args.threads)
    torch.manual_seed(args.seed)
    torch.use_deterministic_algorithms(True)
    rows, dedup, invalid, candidate_filtering = load_rows(args.cache, args.seed, args.train_cap)
    address_hashes = {s: hashlib.sha256('\n'.join(r['address'] for r in rs).encode()).hexdigest() for s,rs in rows.items()}
    content_hashes = {s: hashlib.sha256(json.dumps([(r['address'],r['hashes'][0],r['slither']) for r in rs],separators=(',',':')).encode()).hexdigest() for s,rs in rows.items()}
    counts = {s:len(rs) for s,rs in rows.items()}
    truncation = {s:sum(len(raw_bytes(r['bytecode'])) > SEQUENCE_LENGTH for r in rs) for s,rs in rows.items()}
    fixtures = [r['bytecode'] for r in rows['validation'][:3]] + ['0x00','0xff']
    data = {s:torch.from_numpy(encode_rows(rs)) for s,rs in rows.items()}
    targets = {s:np.stack([labels(r['slither']) for r in rs]) for s,rs in rows.items()}
    protocol = {'architecture':'upstream-resnet1d-16384-v1','classes':CLASSES,'seed':args.seed,
                'batchSize':args.batch_size,'trainCap':args.train_cap,'counts':counts,
                'candidateFingerprint':candidate_filtering['fingerprint'],'sequenceLength':SEQUENCE_LENGTH,'normalization':'per-example L2 after zero-pad/truncate',
                'optimizer':'Adam lr=.001 weight_decay=.0001; weighted BCE from train only',
                'contentHashes':content_hashes,'torchVersion':str(torch.__version__), 'threads':args.threads}
    # Training retains encoded bytes and targets, not the original hex strings.
    del rows
    import gc
    gc.collect()
    model = ResNet1D()
    optimizer = torch.optim.Adam(model.parameters(),lr=.001,weight_decay=.0001)
    y = torch.from_numpy(targets['train'])
    positive = y.sum(0)
    loss_function = torch.nn.BCEWithLogitsLoss(pos_weight=(len(y)-positive)/positive.clamp(min=1))
    history = []; best_score = -1.; best_state = None; best_thresholds = None; best_epoch = 0; first_epoch = 0
    if args.resume:
        payload = restore_checkpoint(args.resume, model, optimizer, protocol)
        first_epoch = payload['epoch']; history = payload['history']; best_score = payload['bestScore']
        best_state = payload['bestState']; best_thresholds = payload['bestThresholds']; best_epoch = payload['bestEpoch']
        if args.epochs <= first_epoch:
            parser.error('--epochs must exceed the completed resume epoch')
    print(json.dumps({'protocol':protocol,'addressHashes':address_hashes,'truncatedRows':truncation,'candidateFiltering':candidate_filtering}),flush=True)
    start = time.monotonic()
    for epoch in range(first_epoch, args.epochs):
        model.train(); order = torch.randperm(len(y)); total = 0.
        batches = order.split(args.batch_size)
        for index, indices in enumerate(batches):
            optimizer.zero_grad()
            loss = loss_function(model(normalize_batch(data['train'][indices])), y[indices])
            if not torch.isfinite(loss):
                raise RuntimeError('Non-finite training loss; no candidate exported')
            loss.backward(); optimizer.step(); total += float(loss.detach())*len(indices)
            if (index+1) % 64 == 0:
                print(json.dumps({'epoch':epoch+1,'batch':index+1,'batches':len(batches),'loss':float(loss.detach()),'elapsedSeconds':time.monotonic()-start}),flush=True)
        vp = probabilities(model, data['validation'], args.batch_size)
        vy = targets['validation']
        from sklearn.metrics import f1_score
        thresholds = [float(max(np.arange(.05,.951,.025),key=lambda t:f1_score(vy[:,i],vp[:,i]>=t,zero_division=0))) for i in range(5)]
        validation = metrics(vy, vp, thresholds)
        record = {'epoch':epoch+1,'trainLoss':total/len(y),'validation':validation,'thresholds':thresholds,
                  'validationAtFixedHalfThreshold':metrics(vy,vp,[.5]*5)}
        history.append(record)
        if validation['microF1'] > best_score:
            best_score = validation['microF1']; best_epoch = epoch+1; best_thresholds = thresholds
            best_state = {k:v.detach().clone() for k,v in model.state_dict().items()}
        save_checkpoint(out/'last.pt', {'protocol':protocol,'epoch':epoch+1,'model':model.state_dict(),
                        'optimizer':optimizer.state_dict(),'rng':torch.get_rng_state(),'history':history,
                        'bestScore':best_score,'bestEpoch':best_epoch,'bestState':best_state,'bestThresholds':best_thresholds})
        print(json.dumps({'epoch':epoch+1,'validationMicroF1':validation['microF1'],'validationMacroF1':validation['macroF1'],'bestEpoch':best_epoch}),flush=True)
    model.load_state_dict(best_state)
    selected = {'protocol':protocol,'model':best_state,'thresholds':best_thresholds,'selectedEpoch':best_epoch}
    save_checkpoint(out/'selected.pt', selected)
    # Test is first scored only after all validation selection is finished.
    test_p = probabilities(model, data['test'], args.batch_size)
    evaluation = metrics(targets['test'],test_p,best_thresholds)
    fixture_tensor = torch.from_numpy(np.stack([encode_bytes(code) for code in fixtures]))
    fixture_p = probabilities(model,fixture_tensor,args.batch_size)
    parity = {'architecture':protocol['architecture'],'classes':CLASSES,'cases':[{'bytecode':code,'probabilities':p.tolist()} for code,p in zip(fixtures,fixture_p)]}
    (out/'parity.json').write_text(json.dumps(parity,indent=2))
    baseline = json.loads(Path(__file__).with_name('full-training-comparison.json').read_text())['models']['fullTrain']
    report = {'protocol':protocol,'upstreamCommit':'d755f0f2232ce9ef873150ab0dbb0043f04ebded',
              'runKind':'CPU pilot, not upstream benchmark reproduction','epochs':args.epochs,'selectedEpoch':best_epoch,
              'selection':'Maximum validation micro F1; per-class thresholds selected on validation only. Test not used to select.',
              'history':history,'test':evaluation,'testAtFixedHalfThreshold':metrics(targets['test'],test_p,[.5]*5),
              'thresholds':best_thresholds,'invalidDropped':invalid,'deduplication':dedup,'addressHashes':address_hashes,
              'truncatedRows':truncation,'candidateFiltering':candidate_filtering,'trainingAndEvaluationSeconds':time.monotonic()-start,
              'parameters':sum(p.numel() for p in model.parameters()),
              'checkpointSha256':hashlib.sha256((out/'selected.pt').read_bytes()).hexdigest(),
              'rgbBaseline':{'trainCount':baseline['trainCount'],'validation':baseline['validation'],'test':baseline['test']},
              'promotionEligibleOnValidation':best_score > baseline['validation']['microF1'] and history[best_epoch-1]['validation']['macroF1'] > baseline['validation']['macroF1'],
              'limitations':['Finite training cap and epoch budget; actual protocol counts/epochs above are authoritative, not a convergence claim.',
                            'Different training budget from full-data RGB model; reused known test benchmark, not an independent leaderboard reproduction.',
                            'Raw bytecode is truncated at16384 bytes; no semantic family isolation or confirmed exploit ground truth.',
                            'Checkpoint is an offline candidate; browser inference remains the validated RGB CNN.']}
    (out/'evaluation.json').write_text(json.dumps(report,indent=2,allow_nan=False))
    print(json.dumps({'selectedEpoch':best_epoch,'validationMicroF1':best_score,'testMicroF1':evaluation['microF1'],'testMacroF1':evaluation['macroF1'],'checkpointSha256':report['checkpointSha256']}),flush=True)


if __name__ == '__main__':
    main()
