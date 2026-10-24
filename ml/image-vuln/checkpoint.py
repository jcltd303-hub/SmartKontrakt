"""Atomic tensor-only checkpoint IO; reject resume on a different protocol."""
from pathlib import Path
import torch


def save_checkpoint(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    torch.save(payload, temporary)
    temporary.replace(path)


def restore_checkpoint(path, model, optimizer, protocol):
    payload = torch.load(path, map_location='cpu', weights_only=True)
    if payload.get('protocol') != protocol:
        raise ValueError('Resume protocol/data mismatch; use the same split, preprocessing and optimizer settings')
    model.load_state_dict(payload['model'])
    optimizer.load_state_dict(payload['optimizer'])
    torch.set_rng_state(payload['rng'])
    return payload


def prepare_output(path, resume):
    path = Path(path)
    if resume:
        if not Path(resume).is_file():
            raise ValueError('Resume checkpoint does not exist')
    elif any((path/name).exists() for name in ('last.pt','selected.pt','evaluation.json')):
        raise ValueError('Training output already contains a run; use --resume or a new output directory')
    path.mkdir(parents=True, exist_ok=True)
    return path
