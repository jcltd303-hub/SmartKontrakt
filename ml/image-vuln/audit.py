"""Independent dataset hygiene audit, including contradictory pseudo-labels."""
import argparse,glob,hashlib,json,pickle
from collections import defaultdict
from pathlib import Path
import numpy as np
from core import hashes,clean_splits,labels
from train import metrics

def audit(cache,seed=20261024,cap=20000):
 rows={s:[]for s in ['train','validation','test']};labelsets=defaultdict(set);owners=defaultdict(set);invalid={s:0 for s in rows};maximum={}
 for s in rows:
  maxbytes=0
  for p in sorted(glob.glob(str(Path(cache)/(s+'-*.pkl')))):
   for r in pickle.load(open(p,'rb')):
    try:r['hashes']=hashes(r['bytecode'])
    except ValueError:invalid[s]+=1;continue
    maxbytes=max(maxbytes,(len(r['bytecode'])-2)//2)
    for h in r['hashes']:labelsets[h].add(tuple(labels(r['slither']).tolist()));owners[h].add(s)
    rows[s].append(r)
  maximum[s]=maxbytes
 contradictory={h for h,v in labelsets.items() if len(v)>1}
 cross={h for h,v in owners.items() if len(v)>1}
 out,stats=clean_splits(rows)
 affected={s:sum(any(h in contradictory for h in r['hashes'])for r in rs)for s,rs in rows.items()}
 retained_affected={s:sum(any(h in contradictory for h in r['hashes'])for r in rs)for s,rs in out.items()}
 selections={}
 for s in out:
  out[s].sort(key=lambda r:hashlib.sha256((str(seed)+r['address']).encode()).hexdigest())
  if s=='train':out[s]=out[s][:cap]
  ids='\n'.join(r['address']for r in out[s]);selections[s]={'count':len(out[s]),'orderedAddressSha256':hashlib.sha256(ids.encode()).hexdigest()}
 y=np.stack([labels(r['slither'])for r in out['test']])
 result={'invalidDropped':invalid,'maximumValidByteLength':maximum,'crossSplitSharedFingerprintCount':len(cross),'contradictoryLabelFingerprintCount':len(contradictory),'rowsAffectedByContradictoryLabels':affected,'retainedRowsAffectedByContradictoryLabels':retained_affected,'deduplication':stats,'selectionFingerprints':selections,'allPositiveBaseline':metrics(y,np.ones_like(y),[.5]*5),'note':'Fingerprint groups may overlap (raw, metadata-normalized and image); counts are not distinct contracts. Within-split duplicates keep first official row, including contradictory pseudo-labels; quantified here as label-noise limitation.'}
 return result
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--cache',required=True);a.add_argument('--output',default=str(Path(__file__).with_name('dataset-audit.json')));args=a.parse_args();result=audit(args.cache);Path(args.output).write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
