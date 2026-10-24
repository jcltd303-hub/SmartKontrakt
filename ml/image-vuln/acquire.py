"""Fetch only bytecode/labels/address column chunks from official Parquet splits."""
import argparse,io,json,os,pickle,time,concurrent.futures
import requests,pyarrow.parquet as pq
class HTTPRange(io.RawIOBase):
 def __init__(self,url,size):self.url=url;self.size=size;self.pos=0;self.session=requests.Session()
 def readable(self):return True
 def seekable(self):return True
 def tell(self):return self.pos
 def seek(self,n,whence=0):
  self.pos=n if whence==0 else self.pos+n if whence==1 else self.size+n
  return self.pos
 def read(self,n=-1):
  n=min(n if n>=0 else self.size,self.size-self.pos)
  if n<=0:return b''
  start=self.pos;end=start+n-1
  for attempt in range(5):
   try:
    r=self.session.get(self.url,headers={'Range':f'bytes={start}-{end}'},timeout=180);r.raise_for_status()
    if r.status_code!=206 or len(r.content)!=n:raise ValueError(f'Range mismatch {r.status_code} {len(r.content)} != {n}')
    self.pos+=n;return r.content
   except Exception:
    if attempt==4:raise
    time.sleep(attempt+1)
def fetch(entry,out):
 key=entry['split']+'-'+entry['filename'];path=os.path.join(out,key+'.pkl')
 if os.path.exists(path):return path
 p=pq.ParquetFile(HTTPRange(entry['url'],entry['size']))
 rows=p.read(columns=['address','bytecode','slither']).to_pylist()
 with open(path,'wb') as f:pickle.dump(rows,f)
 print(key,len(rows),'saved',flush=True);return path
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--manifest',required=True);a.add_argument('--cache',required=True);args=a.parse_args();os.makedirs(args.cache,exist_ok=True)
 entries=[e for e in json.load(open(args.manifest))['parquet_files'] if e['config']=='big-multilabel']
 with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:list(ex.map(lambda e:fetch(e,args.cache),entries))
