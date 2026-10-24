"""Compare a completed full-cohort experiment with the current ResNet baseline.

Only selected validation metrics determine eligibility. Deployment is separately
verified; a stronger test score never authorizes replacing browser weights.
"""
import argparse
import copy
import hashlib
import json
import math
from pathlib import Path


def selected_validation(report):
    history=report['history'];selected=report['selectedEpoch']
    if report['epochs']!=len(history) or not 1<=selected<=len(history):
        raise ValueError('Incomplete epoch history')
    for record in history:
        for metric in ('microF1','macroF1'):
            value=record['validation'][metric]
            if not isinstance(value,(int,float)) or not math.isfinite(value) or not 0<=value<=1:
                raise ValueError('Invalid validation metric')
    best=max(range(len(history)),key=lambda i:history[i]['validation']['microF1'])+1
    if selected!=best or report['thresholds']!=history[selected-1]['thresholds']:
        raise ValueError('Checkpoint must use the maximum validation micro F1 epoch and its thresholds')
    return history[selected-1]['validation']


def annotate_full_cohort(current, baseline):
    protocol=current['protocol'];reference=baseline['protocol']
    for key in ('architecture','classes','seed','batchSize','sequenceLength','normalization','optimizer','torchVersion','threads'):
        if protocol[key]!=reference[key]:
            raise ValueError('Changed training/input setting: '+key)
    for split in ('validation','test'):
        if (protocol['contentHashes'][split]!=reference['contentHashes'][split]
                or protocol['counts'][split]!=reference['counts'][split]):
            raise ValueError('Held-out cohort changed: '+split)
    available=current['candidateFiltering']['availableTrainAfterCandidateFiltering']
    if protocol['counts']['train']!=available or protocol['trainCap']<available:
        raise ValueError('Experiment did not use the complete eligible training cohort')
    if (protocol['counts']['train']!=reference['counts']['train']
            and protocol['contentHashes']['train']==reference['contentHashes']['train']):
        raise ValueError('Changed training count must change its content hash')
    selected=selected_validation(current);old=selected_validation(baseline)
    result=copy.deepcopy(current)
    result['runKind']=f"Full eligible cohort, bounded {current['epochs']}-epoch CPU experiment; not a convergence or upstream reproduction claim"
    eligible=selected['microF1']>old['microF1'] and selected['macroF1']>old['macroF1']
    result['rgbPromotionEligibleOnValidation']=current.get('rgbPromotionEligibleOnValidation',current.get('promotionEligibleOnValidation'))
    result['promotionEligibleOnValidation']=eligible
    result['browserPromotion']={
        'rule':'Both selected validation micro F1 and macro F1 must strictly exceed current ResNet; test cannot select; deployment verification also required',
        'eligibleOnValidation':eligible,
        'deploymentVerified':False,
        'baseline':{'checkpointSha256':baseline['checkpointSha256'],'trainCount':reference['counts']['train'],
                    'selectedEpoch':baseline['selectedEpoch'],'validation':old},
        'candidateValidation':selected,
    }
    result['limitations']=[
        f"{current['epochs']} epochs is a bounded experiment, not a convergence claim.",
        'Known validation/test benchmark reused across experiments; no semantic family isolation or independent upstream reproduction.',
        'Slither pseudo-labels are not confirmed exploit ground truth. Raw input truncates at 16384 bytes.',
        'Browser weights remain the previously validated ResNet until both validation and deployment gates pass.',
    ]
    return result


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--directory',required=True)
    parser.add_argument('--baseline',default=str(Path(__file__).with_name('resnet1d-evaluation.json')))
    args=parser.parse_args();directory=Path(args.directory)
    raw_path=directory/'raw-evaluation.json'
    source=raw_path if raw_path.exists() else directory/'evaluation.json'
    original=source.read_bytes();current=json.loads(original)
    if hashlib.sha256((directory/'selected.pt').read_bytes()).hexdigest()!=current['checkpointSha256']:
        raise ValueError('Selected checkpoint hash differs from report')
    result=annotate_full_cohort(current,json.loads(Path(args.baseline).read_text()))
    if not raw_path.exists():raw_path.write_bytes(original)
    temporary=directory/'evaluation.json.tmp';temporary.write_text(json.dumps(result,indent=2,allow_nan=False)+'\n')
    temporary.replace(directory/'evaluation.json')
    print(json.dumps(result['browserPromotion']))

if __name__=='__main__':main()
