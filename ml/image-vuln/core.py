"""Bytecode image preprocessing and leakage safeguards."""
import hashlib,math,re
import numpy as np
CLASSES=['access-control','arithmetic','reentrancy','unchecked-calls','others']
def raw_bytes(code):
 s=code.strip().lower().removeprefix('0x')
 if not s or len(s)%2 or not re.fullmatch('[0-9a-f]+',s): raise ValueError('Expected nonempty even-length hexadecimal bytecode')
 return bytes.fromhex(s)
def render(code):
 b=raw_bytes(code); side=math.ceil(math.sqrt(math.ceil(len(b)/3)))
 a=np.zeros(side*side*3,dtype=np.uint8);a[:len(b)]=np.frombuffer(b,dtype=np.uint8);a=a.reshape(side,side,3)
 ix=np.minimum(side-1, np.floor((np.arange(64)+.5)*side/64).astype(int))
 return a[ix[:,None],ix[None,:]].transpose(2,0,1).copy()
def labels(values):
 return np.array([int(k in values) for k in [0,1,3,5,2]],dtype=np.float32)
def hashes(code):
 b=raw_bytes(code)
 # Solidity CBOR metadata trailer is stripped only for an extra conservative fingerprint.
 n=int.from_bytes(b[-2:],'big') if len(b)>2 else 0
 normalized=b[:-n-2] if 0<n<len(b)-2 and b[-n-2] in range(0xa0,0xc0) else b
 return (hashlib.sha256(b).hexdigest(),hashlib.sha256(normalized).hexdigest(),hashlib.sha256(render(code).tobytes()).hexdigest())
def clean_splits(rows):
 owners={}; conflicts=set()
 for split,items in rows.items():
  for row in items:
   for h in row['hashes']:
    if h in owners and owners[h]!=split: conflicts.add(h)
    owners[h]=split
 out={};stats={}
 for split,items in rows.items():
  seen=set();out[split]=[];cross=within=0
  for r in items:
   if any(h in conflicts for h in r['hashes']):cross+=1;continue
   if any(h in seen for h in r['hashes']):within+=1;continue
   seen.update(r['hashes']);out[split].append(r)
  stats[split]={'input':len(items),'crossSplitDropped':cross,'withinSplitDropped':within,'retained':len(out[split])}
 return out,stats
