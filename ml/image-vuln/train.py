"""CPU training/evaluation/export; test labels never participate in selection."""
import argparse,glob,hashlib,json,os,pickle,random,time
from pathlib import Path
import numpy as np
import torch
from torch import nn
from sklearn.metrics import precision_recall_fscore_support,f1_score,average_precision_score,roc_auc_score,accuracy_score
from core import CLASSES,render,labels,hashes,clean_splits
class CNN(nn.Module):
 def __init__(self):
  super().__init__();self.convs=nn.ModuleList([nn.Conv2d(3,8,3,2,1),nn.Conv2d(8,16,3,2,1),nn.Conv2d(16,24,3,2,1)]);self.linear=nn.Linear(384,5)
 def forward(self,x):
  for c in self.convs:x=torch.relu(c(x))
  return self.linear(torch.nn.functional.avg_pool2d(x,2).flatten(1))
def metrics(y,p,t):
 pred=p>=np.array(t);pr,re,f,s=precision_recall_fscore_support(y,pred,average=None,zero_division=0)
 return {'microF1':float(f1_score(y,pred,average='micro',zero_division=0)),'macroF1':float(np.mean(f)),'exactMatch':float(accuracy_score(y,pred)),'perClass':[{ 'class':c,'precision':float(pr[i]),'recall':float(re[i]),'f1':float(f[i]),'support':int(s[i]),'averagePrecision':float(average_precision_score(y[:,i],p[:,i])) if 0<y[:,i].sum()<len(y) else None,'auroc':float(roc_auc_score(y[:,i],p[:,i])) if 0<y[:,i].sum()<len(y) else None}for i,c in enumerate(CLASSES)]}
def predict(model,x):
 model.eval();out=[]
 with torch.no_grad():
  for start in range(0,len(x),256):out.append(torch.sigmoid(model(x[start:start+256].float()/255)).numpy())
 return np.concatenate(out)
def main():
 a=argparse.ArgumentParser();a.add_argument('--cache',required=True);a.add_argument('--output',required=True);a.add_argument('--train-cap',type=int,default=20000);a.add_argument('--epochs',type=int,default=12);a.add_argument('--seed',type=int,default=20261024);a.add_argument('--threads',type=int,default=8);args=a.parse_args()
 torch.set_num_threads(args.threads);torch.manual_seed(args.seed);np.random.seed(args.seed);random.seed(args.seed);torch.use_deterministic_algorithms(True)
 rows={s:[] for s in ['train','validation','test']};invalid={s:0 for s in rows}
 for s in rows:
  for path in sorted(glob.glob(os.path.join(args.cache,s+'-*.pkl'))):
   for r in pickle.load(open(path,'rb')):
    try:r['hashes']=hashes(r['bytecode'])
    except ValueError:invalid[s]+=1;continue
    rows[s].append(r)
  print('hashed',s,len(rows[s]),'invalid',invalid[s],flush=True)
 rows,dedup=clean_splits(rows)
 for s in rows:rows[s].sort(key=lambda r:hashlib.sha256((str(args.seed)+r['address']).encode()).hexdigest())
 before=len(rows['train']);rows['train']=rows['train'][:args.train_cap]
 data={s:(torch.from_numpy(np.stack([render(r['bytecode']) for r in rs])),np.stack([labels(r['slither']) for r in rs]))for s,rs in rows.items()}
 counts={s:len(v[1])for s,v in data.items()};print('counts',counts,'dedup',dedup,flush=True)
 model=CNN();opt=torch.optim.Adam(model.parameters(),lr=.001,weight_decay=1e-4)
 y=torch.from_numpy(data['train'][1]);pos=y.sum(0);weights=(len(y)-pos)/pos.clamp(min=1);loss_fn=nn.BCEWithLogitsLoss(pos_weight=weights)
 history=[];best=-1;best_state=None;best_threshold=None;start=time.time()
 for epoch in range(args.epochs):
  model.train();order=torch.randperm(len(y));total=0
  for ix in order.split(128):
   opt.zero_grad();loss=loss_fn(model(data['train'][0][ix].float()/255),y[ix]);loss.backward();opt.step();total+=float(loss.detach())*len(ix)
  vp=predict(model,data['validation'][0]);vy=data['validation'][1]
  thresholds=[float(max(np.arange(.05,.951,.025),key=lambda t:f1_score(vy[:,i],vp[:,i]>=t,zero_division=0)))for i in range(5)]
  score=f1_score(vy,vp>=np.array(thresholds),average='macro',zero_division=0)
  record={'epoch':epoch+1,'trainLoss':total/len(y),'validationMacroF1':float(score),'thresholds':thresholds};history.append(record);print(record,flush=True)
  if score>best:best=float(score);best_state={k:v.detach().clone()for k,v in model.state_dict().items()};best_threshold=thresholds;best_epoch=epoch+1
 model.load_state_dict(best_state);test_p=predict(model,data['test'][0]);test_y=data['test'][1];evaluation=metrics(test_y,test_p,best_threshold)
 prevalence=data['train'][1].mean(0);base_p=np.tile(prevalence,(len(test_y),1))
 evaluation['allPositiveBaseline']=metrics(test_y,np.ones_like(test_y),[.5]*5)
 evaluation['majorityBaseline']=metrics(test_y,base_p,[.5]*5);evaluation['prevalenceBaseline']=metrics(test_y,base_p,best_threshold)
 training={'dataset':'mwritescode/slither-audited-smart-contracts','config':'big-multilabel','seed':args.seed,'trainCap':args.train_cap,'availableTrainAfterDedup':before,'counts':counts,'invalidDropped':invalid,'deduplication':dedup,'positiveWeights':weights.tolist(),'trainPrevalence':prevalence.tolist(),'selectedEpoch':best_epoch,'epochs':args.epochs,'selection':'Maximum validation macro F1; per-class thresholds maximize validation F1 over 0.05..0.95 step 0.025. Test evaluated once after selection.','history':history,'trainingSeconds':time.time()-start,'torchVersion':torch.__version__,'architecture':'3 convolution layers, average pool, linear; independent sigmoid','optimizer':'Adam lr=0.001 weight_decay=0.0001 batch=128','augmentation':'none'}
 layers=[]
 for c in model.convs:layers.append({'kind':'conv2d','inChannels':c.in_channels,'outChannels':c.out_channels,'kernel':3,'stride':2,'padding':1,'weight':c.weight.detach().flatten().tolist(),'bias':c.bias.detach().tolist()})
 artifact={'schemaVersion':1,'modelId':'bytecode-image-v1','architecture':'rgb-cnn-64-v1','classes':CLASSES,'input':{'size':64,'encoding':'rgb-triplets-square-zero-pad-nearest-center-v1','normalization':'0..1'},'layers':layers,'pool':{'kind':'avg','kernel':2,'stride':2},'linear':{'inFeatures':384,'outFeatures':5,'weight':model.linear.weight.detach().flatten().tolist(),'bias':model.linear.bias.detach().tolist()},'thresholds':best_threshold,'training':training,'evaluation':evaluation}
 out=Path(args.output);out.mkdir(parents=True,exist_ok=True);(out/'bytecode-image-v1.json').write_text(json.dumps(artifact,separators=(',',':'),allow_nan=False))
 fixtures=[r['bytecode']for r in rows['validation'][:3]]+['0x0102030405','0xff']
 with torch.no_grad():parity={'cases':[{'bytecode':code,'probabilities':torch.sigmoid(model(torch.from_numpy(render(code)[None]).float()/255))[0].tolist()}for code in fixtures]}
 (out/'bytecode-image-v1-parity.json').write_text(json.dumps(parity,separators=(',',':')))
 report={'training':training,'test':evaluation,'thresholds':best_threshold};Path(__file__).with_name('evaluation.json').write_text(json.dumps(report,indent=2,allow_nan=False))
 torch.save(model.state_dict(),os.path.join(args.cache,'trained-state.pt'));print(json.dumps(evaluation,indent=2),flush=True)
if __name__=='__main__':main()
