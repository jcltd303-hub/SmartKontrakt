"""Validate and annotate a resumed experiment without changing model selection."""
import argparse
import hashlib
import json
from pathlib import Path
import re


def annotate_continuation(current, parent, parent_resume_sha):
    if current['protocol'] != parent['protocol']:
        raise ValueError('Continuation protocol changed')
    previous = parent['epochs']
    if current['epochs'] <= previous or len(current['history']) != current['epochs']:
        raise ValueError('Continuation must add completed epochs')
    if current['history'][:previous] != parent['history']:
        raise ValueError('Continuation altered the parent training history')
    if not all(isinstance(value,str) and re.fullmatch('[a-f0-9]{64}',value)
               for value in (parent_resume_sha,parent['checkpointSha256'])):
        raise ValueError('Invalid parent checkpoint SHA256')
    prior_seconds = parent.get('resumeProvenance',{}).get('cumulativeMeasuredInvocationSeconds',parent['trainingAndEvaluationSeconds'])
    return {**current,'resumeProvenance':{
        'resumedFromEpoch':previous,'addedEpochs':current['epochs']-previous,
        'parentSelectedCheckpointSha256':parent['checkpointSha256'],
        'parentResumeCheckpointSha256':parent_resume_sha,
        'currentInvocationTrainingAndEvaluationSeconds':current['trainingAndEvaluationSeconds'],
        'cumulativeMeasuredInvocationSeconds':prior_seconds+current['trainingAndEvaluationSeconds'],
        'timingNote':'Sum of measured invocation training/validation/test durations; excludes data loading, hashing, environment setup and time between runs.',
        'historyPrefixVerified':True,'protocolAndDataHashesVerified':True,
    }}


def verify_step_counters(state, expected_batches):
    def number(value):
        return value.item() if hasattr(value,'item') else value
    bn=[number(v) for k,v in state['model'].items() if k.endswith('num_batches_tracked')]
    steps=[number(v['step']) for v in state['optimizer']['state'].values()]
    if not bn or not steps or any(value != expected_batches for value in bn+steps):
        raise ValueError('Checkpoint training-step counters do not match completed epochs')
    return {'batchNormCounters':len(bn),'optimizerCounters':len(steps),'completedTrainingBatches':expected_batches}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--current-directory',required=True)
    parser.add_argument('--parent-directory',required=True)
    args = parser.parse_args()
    current_dir = Path(args.current_directory); parent_dir = Path(args.parent_directory)
    current = json.loads((current_dir/'evaluation.json').read_text())
    parent = json.loads((parent_dir/'evaluation.json').read_text())
    if hashlib.sha256((parent_dir/'selected.pt').read_bytes()).hexdigest() != parent['checkpointSha256']:
        raise ValueError('Parent selected checkpoint/report mismatch')
    import torch
    state = torch.load(parent_dir/'last.pt',map_location='cpu',weights_only=True)
    if state['epoch'] != parent['epochs'] or state['protocol'] != parent['protocol'] or state['history'] != parent['history']:
        raise ValueError('Parent resume checkpoint/report mismatch')
    batches=(parent['protocol']['counts']['train']+parent['protocol']['batchSize']-1)//parent['protocol']['batchSize']
    verify_step_counters(state,batches*parent['epochs'])
    current_state=torch.load(current_dir/'last.pt',map_location='cpu',weights_only=True)
    if current_state['epoch'] != current['epochs'] or current_state['protocol'] != current['protocol'] or current_state['history'] != current['history']:
        raise ValueError('Current resume checkpoint/report mismatch')
    counters=verify_step_counters(current_state,batches*current['epochs'])
    result = annotate_continuation(current,parent,hashlib.sha256((parent_dir/'last.pt').read_bytes()).hexdigest())
    result['resumeProvenance']['trainingStepCountersVerified']=counters
    (current_dir/'evaluation.json').write_text(json.dumps(result,indent=2,allow_nan=False))
    print(json.dumps(result['resumeProvenance'],indent=2))


if __name__ == '__main__': main()
