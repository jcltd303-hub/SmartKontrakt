"""Bounded raw-byte windows for an offline fixed-checkpoint experiment."""
import hashlib
import math
import numpy as np
from core import raw_bytes


def window_starts(length, window_size=16384, max_windows=8):
    if any(not isinstance(v,int) or isinstance(v,bool) or v<1 for v in (length,window_size,max_windows)):
        raise ValueError('Window dimensions must be positive integers')
    count=min(max_windows,math.ceil(length/window_size))
    if count==1:return [0]
    return [i*(length-window_size)//(count-1) for i in range(count)]


def covered_bytes(length, starts, window_size=16384):
    covered=0;end=0
    for start in sorted(starts):
        stop=min(length,start+window_size)
        covered+=max(0,stop-max(start,end));end=max(end,stop)
    return covered


def encoded_windows(code, window_size=16384, max_windows=8):
    values=raw_bytes(code)
    for start in window_starts(len(values),window_size,max_windows):
        part=np.frombuffer(values[start:start+window_size],dtype=np.uint8)
        window=np.zeros(window_size,dtype=np.uint8);window[:len(part)]=part
        yield window


def normalized_fingerprint(vector):
    if vector.dtype!=np.uint8 or vector.ndim!=1 or not vector.size:
        raise ValueError('Expected a nonempty uint8 vector')
    divisor=int(np.gcd.reduce(vector)) or 1
    return hashlib.sha256((vector//divisor).tobytes()).digest()


def predict_windows(codes, predict, batch_size=16, window_size=16384, max_windows=8):
    """Keep at most one bounded inference batch; pool by owning contract."""
    if not isinstance(batch_size,int) or isinstance(batch_size,bool) or batch_size<1:
        raise ValueError('Batch size must be positive')
    codes=list(codes)
    prefix=np.zeros((len(codes),5),dtype=np.float32);pooled=np.zeros_like(prefix)
    pending=[];owners=[];firsts=[]
    budget={'contracts':len(codes),'windows':0,'rawBytes':0,'coveredBytes':0,
            'partiallyCoveredContracts':0,'minCoverageFraction':1.,'meanCoverageFraction':None}
    fractions=[]
    def flush():
        scores=np.asarray(predict(np.stack(pending)))
        if scores.shape!=(len(pending),5) or not np.isfinite(scores).all() or (scores<0).any() or (scores>1).any():
            raise ValueError('Invalid window probabilities')
        for owner,first,score in zip(owners,firsts,scores):
            if first:prefix[owner]=score
            pooled[owner]=np.maximum(pooled[owner],score)
        pending.clear();owners.clear();firsts.clear()
    for owner,code in enumerate(codes):
        length=len(raw_bytes(code));starts=window_starts(length,window_size,max_windows)
        covered=covered_bytes(length,starts,window_size)
        budget['windows']+=len(starts);budget['rawBytes']+=length;budget['coveredBytes']+=covered
        budget['partiallyCoveredContracts']+=int(covered<length);fractions.append(covered/length)
        for index,window in enumerate(encoded_windows(code,window_size,max_windows)):
            pending.append(window);owners.append(owner);firsts.append(index==0)
            if len(pending)==batch_size:flush()
    if pending:flush()
    if fractions:
        budget['minCoverageFraction']=min(fractions);budget['meanCoverageFraction']=sum(fractions)/len(fractions)
    return prefix,pooled,budget
