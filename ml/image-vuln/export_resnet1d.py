"""Export evaluated float weights; shard for bounded browser downloads."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import numpy as np
import torch
from core import CLASSES
from resnet1d import encode_bytes, normalize_batch
from infer_resnet1d import load_candidate


def export_model(model, thresholds, cases, output, checkpoint_sha, metadata):
    import onnx
    import onnxruntime as ort
    output.mkdir(parents=True, exist_ok=True)
    buffer = io.BytesIO()
    wrapper = torch.nn.Sequential(model.eval(), torch.nn.Sigmoid()).eval()
    torch.onnx.export(wrapper, torch.zeros(1,1,16384), buffer,
                      input_names=['bytecode'], output_names=['probabilities'],
                      opset_version=17, dynamo=False)
    data = buffer.getvalue()
    onnx.checker.check_model(onnx.load_model_from_string(data))
    options = ort.SessionOptions(); options.intra_op_num_threads = 2
    session = ort.InferenceSession(data, sess_options=options, providers=['CPUExecutionProvider'])
    error = 0.0; parity = []
    for case in cases:
        inputs = normalize_batch(torch.from_numpy(encode_bytes(case['bytecode'])[None]))
        with torch.no_grad(): expected = wrapper(inputs).numpy()
        actual = session.run(None, {'bytecode':inputs.numpy()})[0]
        if not np.isfinite(expected).all() or not np.isfinite(actual).all():
            raise ValueError('Non-finite Torch or ONNX predictions')
        error = max(error,float(np.max(np.abs(expected-actual))))
        parity.append({'bytecode':case['bytecode'],'probabilities':expected[0].tolist()})
    if not np.isfinite(error) or error > 1e-5:
        raise ValueError(f'ONNX parity failed: {error}')
    shards = []
    for index, start in enumerate(range(0,len(data),1024*1024)):
        part = data[start:start+1024*1024]
        name = f'resnet1d-v1-{index:02d}.bin'
        (output/name).write_bytes(part)
        shards.append({'file':name,'bytes':len(part),'sha256':hashlib.sha256(part).hexdigest()})
    manifest = {'schemaVersion':1,'modelId':'resnet1d-16384-v1',
                'architecture':'upstream-resnet1d-16384-v1','sequenceLength':16384,
                'normalization':'per-example L2 after zero-pad/truncate',
                'classes':CLASSES,'thresholds':thresholds,'bytes':len(data),
                'sha256':hashlib.sha256(data).hexdigest(),'shards':shards,
                'checkpointSha256':checkpoint_sha,'parityMaxAbsoluteError':error,
                **metadata}
    (output/'resnet1d-v1.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (output/'resnet1d-v1-parity.json').write_text(json.dumps({'cases':parity,'tolerance':1e-5},indent=2)+'\n')
    return manifest


def export_metadata(report, payload, checkpoint_sha, evaluation_report, parity_file):
    if checkpoint_sha != report['checkpointSha256']:
        raise ValueError('Selected checkpoint hash does not match report')
    for key in ('protocol','selectedEpoch','thresholds'):
        if payload[key] != report[key]:
            raise ValueError('Checkpoint and report disagree: '+key)
    epoch=payload['selectedEpoch'];count=payload['protocol']['counts']['train']
    return {'modelId':f'resnet1d-16384-train{count}-epoch{epoch}-v1',
            'evaluationReport':evaluation_report,'parityFile':parity_file,
            'training':{'samples':report['protocol']['counts'],'selectedEpoch':epoch,
                        'epochs':report['epochs'],'checkpointSha256':checkpoint_sha},
            'evaluation':{'validation':report['history'][epoch-1],'test':report['test'],
                          'notice':'Known benchmark reused across experiments; Slither labels, not exploit ground truth.'}}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--checkpoint',required=True)
    parser.add_argument('--report',required=True)
    parser.add_argument('--parity',required=True)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    torch.set_num_threads(8)
    model,payload=load_candidate(args.checkpoint)
    report=json.loads(Path(args.report).read_text())
    checkpoint_sha=hashlib.sha256(Path(args.checkpoint).read_bytes()).hexdigest()
    metadata=export_metadata(report,payload,checkpoint_sha,Path(args.report).name,Path(args.parity).name)
    manifest=export_model(model,payload['thresholds'],json.loads(Path(args.parity).read_text())['cases'],
                          Path(args.output),checkpoint_sha,metadata)
    print(json.dumps({'bytes':manifest['bytes'],'sha256':manifest['sha256'],
                      'parityMaxAbsoluteError':manifest['parityMaxAbsoluteError']}))

if __name__=='__main__': main()
