"""Local-only transaction gas benchmark. Start Anvil Osaka on localhost:18548.
Uses mock verifier; never connect this script to a public RPC.
"""
import json, urllib.request, time, os
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
URL='http://127.0.0.1:18548'
def rpc(method,params):
 data=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode()
 response=json.load(urllib.request.urlopen(urllib.request.Request(URL,data,{'Content-Type':'application/json'})))
 if 'error' in response: raise RuntimeError(response['error'])
 return response['result']
def batch(items):
 result=[]
 for start in range(0,len(items),256):
  entries=[{'jsonrpc':'2.0','id':i,'method':m,'params':p} for i,(m,p) in enumerate(items[start:start+256])]
  data=json.dumps(entries).encode()
  responses=json.load(urllib.request.urlopen(urllib.request.Request(URL,data,{'Content-Type':'application/json'})))
  for item in sorted(responses,key=lambda x:x['id']):
   if 'error' in item: raise RuntimeError(item['error'])
   result.append(item['result'])
 return result
word=lambda n:n.to_bytes(32,'big')
hx=lambda b:'0x'+b.hex()
def hashbytes(b):return bytes.fromhex(rpc('web3_sha3',[hx(b)])[2:])
rpc('anvil_reset',[])
target='0x0000000000000000000000000000000000003333'
verifier='0x0000000000000000000000000000000000001111'
rpc('anvil_setCode',[target,json.loads((ROOT/'out/Rollup.sol/Rollup.json').read_text())['deployedBytecode']['object']])
rpc('anvil_setCode',[verifier,json.loads((ROOT/'out/Rollup.t.sol/TestVerifier.json').read_text())['deployedBytecode']['object']])
account=rpc('eth_accounts',[])[0]
chain=int(rpc('eth_chainId',[]),16)
base=int.from_bytes(hashbytes(word(0)),'big')
ceiling=1600
slots=batch([('web3_sha3',[hx(word(m)+word(1))]) for m in range(ceiling*4)])
batch([('anvil_setStorageAt',[target,slot,hx(word(7))]) for slot in slots])
selector=hashbytes(b'commitState(bytes,bytes)')[:4]
keys_hash=hashbytes(word(7)*4)
old=sum((10000+(100<<40))<<(64*i) for i in range(4))
worst = os.environ.get("WORST_WORD") == "1"
new=(1<<256)-1 if worst else sum((10001+(101<<40))<<(64*i) for i in range(4))
def calldata(count,fresh):
 payload=b''.join(i.to_bytes(4,'big')+word(new) for i in range(count))
 transcript=word(chain)+bytes.fromhex(target[2:])+b''.join(i.to_bytes(4,'big')+word(0 if fresh else old)+word(new)+keys_hash for i in range(count))
 proof=hashbytes(transcript)
 padded=payload+b'\0'*((-len(payload))%32)
 return hx(selector+word(64)+word(96+len(padded))+word(len(payload))+padded+word(len(proof))+proof)
def call(count,fresh):
 return {'from':account,'to':target,'data':calldata(count,fresh),'gas':hex(16_777_216)}
results={'environment':'Anvil 1.8.1 Osaka, 16,777,216 transaction cap, mock verifier and 32-byte mock proof','all_nonzero_new_words':worst,'measurements':[]}
for fresh in [False,True]:
 batch([('anvil_setStorageAt',[target,hx(word(base+i)),hx(word(0 if fresh else old))]) for i in range(ceiling)])
 rpc('anvil_setStorageAt',[target,hx(word(0)),hx(word(0 if fresh else ceiling))])
 low,high=0,ceiling
 while low<high:
  middle=(low+high+1)//2
  try: rpc('eth_call',[call(middle,fresh),'latest']);fits=True
  except RuntimeError as error:
   if 'out of gas' not in str(error).lower() and 'outofgas' not in str(error).lower() and 'reentrancysentryoog' not in str(error).lower(): raise
   fits=False
  if fits:low=middle
  else:high=middle-1
 # eth_call does not change state; receipt measurement is isolated by snapshot/revert.
 row={'fresh':fresh,'maximum_words_mock_only':low,'samples':[]}
 for count in sorted(set([128,512,low,low+1])):
  snapshot=rpc('evm_snapshot',[])
  request=call(count,fresh)
  try:
   tx=rpc('eth_sendTransaction',[request])
   for attempt in range(100):
    receipt=rpc('eth_getTransactionReceipt',[tx])
    if receipt is not None: break
    time.sleep(0.05)
   if receipt is None: raise RuntimeError('local receipt timeout')
   row['samples'].append({'words':count,'gas_used':int(receipt['gasUsed'],16),'success':int(receipt['status'],16)==1})
  finally:rpc('evm_revert',[snapshot])
 print(json.dumps(row),flush=True)
 results['measurements'].append(row)
(ROOT/'benchmarks'/('transaction-gas-worst.json' if worst else 'transaction-gas.json')).write_text(json.dumps(results,indent=2)+'\n')
