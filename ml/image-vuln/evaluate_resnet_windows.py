"""Offline window experiment: validation selection, fixed-cohort test diagnostics."""
import argparse
import gc
import hashlib
import json
import time
from pathlib import Path
import numpy as np
import torch
from core import labels
from full_cohort_report import selected_validation
from infer_resnet1d import load_candidate
from novelty import novelty_indices, slice_metrics
from resnet1d import encode_bytes, normalize_batch
from train import metrics
from train_resnet1d import load_rows
from windowing import encoded_windows, normalized_fingerprint, predict_windows


def collision_audit(train_prefixes, validation_windows, test_windows):
    train=set(train_prefixes);validation=list(validation_windows);test=list(test_windows)
    val_union=set().union(*validation);test_union=set().union(*test)
    return {'validationTrainingOverlapContracts':sum(bool(s&train) for s in validation),
            'testTrainingOverlapContracts':sum(bool(s&train) for s in test),
            'validationTestSharedFingerprints':len(val_union&test_union),
            'trainingUniquePrefixes':len(train),'validationUniqueWindows':len(val_union),
            'testUniqueWindows':len(test_union)}


def validation_decision(prefix_validation, window_validation, collision_counts):
    improved=all(window_validation[k]>prefix_validation[k] for k in ('microF1','macroF1'))
    clean=all(collision_counts[k]==0 for k in ('validationTrainingOverlapContracts',
              'testTrainingOverlapContracts','validationTestSharedFingerprints'))
    return {'criterion':'Both validation micro/macro F1 strictly improve and no train-prefix/held-out-window or validation/test window collisions',
            'validationImproved':improved,'inputAuditPassed':clean,
            'eligibleOnValidationAndInputAudit':improved and clean,'deploymentVerified':False,
            'browserAction':'Keep verified prefix inference; this is an offline experiment, not browser deployment'}


def verify_protocol(report, checkpoint_protocol, counts, content_hashes):
    if report['protocol']!=checkpoint_protocol:
        raise ValueError('Checkpoint/report protocol mismatch')
    if counts!=checkpoint_protocol['counts'] or content_hashes!=checkpoint_protocol['contentHashes']:
        raise ValueError('Evaluation cohort count/content hash mismatch')


def validation_thresholds(y, probabilities):
    from sklearn.metrics import f1_score
    if probabilities.shape!=y.shape or not np.isfinite(probabilities).all():
        raise ValueError('Invalid validation probabilities')
    return [float(max(np.arange(.05,.951,.025),key=lambda t:f1_score(y[:,i],probabilities[:,i]>=t,zero_division=0))) for i in range(5)]


def require_prefix_reproduction(actual, expected):
    if any(abs(actual[k]-expected[k])>1e-6 for k in ('microF1','macroF1','exactMatch')):
        raise ValueError('Reconstructed prefix metrics differ from published report')


def ui_summary(report):
    audit=report['inputAudit']
    return {'schemaVersion':1,'checkpointSha256':report['checkpointSha256'],
        **{name:{split:{metric:report['models'][name][split][metric] for metric in ('microF1','macroF1')} for split in ('validation','test')} for name in ('prefix','windows')},
        'validationImproved':report['decision']['validationImproved'],
        'inputAuditPassed':report['decision']['inputAuditPassed'],
        'overlappingTrainingContracts':audit['validationTrainingOverlapContracts']+audit['testTrainingOverlapContracts'],
        'sharedValidationTestWindows':audit['validationTestSharedFingerprints'],
        'seenSkeletonCount':report['novelty']['seenSkeleton']['count'],
        'unseenSkeletonCount':report['novelty']['unseenSkeleton']['count']}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--cache',required=True);parser.add_argument('--checkpoint',required=True)
    parser.add_argument('--report',required=True);parser.add_argument('--output',required=True)
    parser.add_argument('--ui-summary',help='Optional compact checkpoint-bound UI JSON output')
    args=parser.parse_args();torch.set_num_threads(8);torch.use_deterministic_algorithms(True)
    report=json.loads(Path(args.report).read_text());sha=hashlib.sha256(Path(args.checkpoint).read_bytes()).hexdigest()
    if sha!=report['checkpointSha256']:raise ValueError('Checkpoint hash differs from report')
    model,payload=load_candidate(args.checkpoint)
    if payload['thresholds']!=report['thresholds'] or payload['selectedEpoch']!=report['selectedEpoch']:
        raise ValueError('Selected checkpoint/report disagree')
    start=time.monotonic();protocol=payload['protocol']
    print(json.dumps({'phase':'loading and auditing fixed cohorts'}),flush=True)
    rows,_,_,filtering=load_rows(args.cache,protocol['seed'],protocol['trainCap'])
    counts={s:len(rs) for s,rs in rows.items()}
    content_hashes={s:hashlib.sha256(json.dumps([(r['address'],r['hashes'][0],r['slither']) for r in rs],separators=(',',':')).encode()).hexdigest() for s,rs in rows.items()}
    verify_protocol(report,protocol,counts,content_hashes)
    if filtering!=report['candidateFiltering']:raise ValueError('Candidate filtering changed')
    seen,unseen=novelty_indices(*( (r['bytecode'] for r in rows[s]) for s in ('train','validation','test')))
    training={normalized_fingerprint(encode_bytes(r['bytecode'])) for r in rows['train']}
    del rows['train'];gc.collect()
    keys={s:[{normalized_fingerprint(w) for w in encoded_windows(r['bytecode'])} for r in rows[s]] for s in rows}
    audit=collision_audit(training,keys['validation'],keys['test']);del training,keys;gc.collect()
    print(json.dumps({'phase':'input audit complete','counts':counts,'inputAudit':audit}),flush=True)
    targets={s:np.stack([labels(r['slither']) for r in rs]) for s,rs in rows.items()}
    def predict_split(split):
        batches=0;began=time.monotonic()
        def predict(batch):
            nonlocal batches
            with torch.no_grad():scores=torch.sigmoid(model(normalize_batch(torch.from_numpy(batch)))).numpy()
            batches+=1
            if batches%128==0:print(json.dumps({'phase':split,'windowBatches':batches,'seconds':time.monotonic()-began}),flush=True)
            return scores
        prefix,pooled,budget=predict_windows((r['bytecode'] for r in rows[split]),predict)
        return prefix,pooled,{**budget,'seconds':time.monotonic()-began}
    vp,vw,val_budget=predict_split('validation')
    thresholds=validation_thresholds(targets['validation'],vw)
    pv=metrics(targets['validation'],vp,report['thresholds']);wv=metrics(targets['validation'],vw,thresholds)
    require_prefix_reproduction(pv,selected_validation(report))
    decision=validation_decision(pv,wv,audit)
    print(json.dumps({'phase':'validation decision frozen before test scoring','decision':decision,'windowThresholds':thresholds,'prefixMicroF1':pv['microF1'],'windowMicroF1':wv['microF1']}),flush=True)
    tp,tw,test_budget=predict_split('test')
    pt=metrics(targets['test'],tp,report['thresholds']);wt=metrics(targets['test'],tw,thresholds)
    require_prefix_reproduction(pt,report['test'])
    ids=lambda ix:hashlib.sha256('\n'.join(rows['test'][i]['address'] for i in ix).encode()).hexdigest()
    result={'schemaVersion':1,'reportKind':'resnet-window-evaluation-v1','checkpointSha256':sha,
            'selectedEpoch':payload['selectedEpoch'],'trainingProtocol':protocol,'contentHashes':content_hashes,
            'experiment':{'windowBytes':16384,'maxWindows':8,'batchWindows':16,'aggregation':'per-class maximum probability','thresholdSelection':'Validation-only per-class F1 over .05..95 step.025; frozen before test scoring','trainingChanged':False},
            'inputAudit':audit,'decision':decision,'coverage':{'validation':val_budget,'test':test_budget},
            'novelty':{'definition':'Exact opcode-skeleton membership in train OR validation; not semantic-family isolation',
                       'seenSkeleton':{'count':len(seen),'orderedAddressSha256':ids(seen)},'unseenSkeleton':{'count':len(unseen),'orderedAddressSha256':ids(unseen)},'testOrderedAddressSha256':ids(range(counts['test']))},
            'models':{},'elapsedSeconds':time.monotonic()-start,
            'limitations':['Known/reused validation and test benchmark with automated Slither labels; not independent exploit ground truth.',
                           'Window max aggregation reuses a prefix-trained model; tail distribution was not part of training.',
                           'At most8 windows; code longer than131072 bytes can contain uncovered gaps.',
                           'Exact skeleton novelty is not semantic-family-disjoint training or evaluation. Slices never select the model.',
                           'No browser window inference or deployment is claimed by this experiment.']}
    for name,validation,test,probabilities,ts in [('prefix',pv,pt,tp,report['thresholds']),('windows',wv,wt,tw,thresholds)]:
        result['models'][name]={'validation':validation,'test':test,'thresholds':ts,
            'testAtFixedHalfThreshold':metrics(targets['test'],probabilities,[.5]*5),
            'seenSkeleton':slice_metrics(targets['test'],probabilities,ts,seen),
            'unseenSkeleton':slice_metrics(targets['test'],probabilities,ts,unseen)}
    output=Path(args.output);temporary=output.with_suffix(output.suffix+'.tmp')
    temporary.write_text(json.dumps(result,indent=2,allow_nan=False)+'\n');temporary.replace(output)
    if args.ui_summary:
        summary=Path(args.ui_summary);temporary=summary.with_suffix(summary.suffix+'.tmp')
        temporary.write_text(json.dumps(ui_summary(result),indent=2,allow_nan=False)+'\n');temporary.replace(summary)
    print(json.dumps({'complete':True,'decision':decision,'validationMicroF1':wv['microF1'],'testMicroF1':wt['microF1'],'slices':result['novelty']}),flush=True)


if __name__=='__main__':main()
