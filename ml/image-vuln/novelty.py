"""Label-independent exact opcode-skeleton novelty; not semantic family detection."""
import hashlib
from core import raw_bytes


def opcode_skeleton(code):
    """Strip plausible metadata, skip PUSH operands and normalize PUSH widths.

    PUSH0 and PUSH1..32 share a token. A truncated PUSH consumes the rest of
    the code, matching its instruction boundary; missing bytes aren't opcodes.
    Non-code data outside a plausible metadata trailer remains a limitation.
    """
    code = raw_bytes(code)
    size = int.from_bytes(code[-2:], 'big') if len(code) > 2 else 0
    if 0 < size < len(code) - 2 and 0xa0 <= code[-size-2] < 0xc0:
        code = code[:-size-2]
    result = bytearray()
    offset = 0
    while offset < len(code):
        opcode = code[offset]
        offset += 1
        if 0x5f <= opcode <= 0x7f:
            result.append(0x60)
            offset += opcode - 0x5f
        else:
            result.append(opcode)
    return bytes(result)


def novelty_indices(training, validation, test):
    """Partition test indices by skeleton membership in training OR validation."""
    def key(code):
        return hashlib.sha256(opcode_skeleton(code)).digest()
    known = {key(code) for codes in (training, validation) for code in codes}
    seen, unseen = [], []
    for index, code in enumerate(test):
        (seen if key(code) in known else unseen).append(index)
    return seen, unseen


def slice_metrics(y, probabilities, thresholds, indices):
    from train import metrics
    return {'count': len(indices), 'metrics': metrics(y[indices], probabilities[indices], thresholds) if indices else None}
