#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={"Effect":(0x002A4AA4,152,"fc8982922fb7bba57f9f0052110e69463503c4f343c90fc030846e61e7a2e049"),"Down":(0x002E0584,807,"279517cb863c131495de999594e2eecb0ec3cfaada975d4215ee0efd7fb2b6f6")}
class ProofError(RuntimeError):pass
def sha_path(p):
 h=hashlib.sha256()
 with open(p,"rb") as f:
  for x in iter(lambda:f.read(1024*1024),b""):h.update(x)
 return h.hexdigest()
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\0\0":raise ProofError("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0];osz=struct.unpack_from("<H",pe,q+20)[0];s=q+24+osz;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def code(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise ProofError("RVA unmapped")
 b=pe[o]
 if b&3==2:h=1;n=b>>2
 else:fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise ProofError(l)
def br(c,o,op,target,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=target:raise ProofError(l)
def f32(c,o,v,l):
 if c[o]!=0x22 or struct.unpack_from("<f",c,o+1)[0]!=struct.unpack("<f",struct.pack("<f",v))[0]:raise ProofError(l)
def verify(path):
 got=sha_path(path)
 if got!=DLL_SHA:raise ProofError("DLL SHA "+got)
 pe=Path(path).read_bytes();ss=sections(pe);cs={}
 for n,(r,s,h) in M.items():
  c=code(pe,ss,r)
  if len(c)!=s or hashlib.sha256(c).hexdigest()!=h:raise ProofError(n+" body")
  cs[n]=c
 c=cs["Effect"]
 tok(c,0x0001,0x7B,0x04005679,"Prefab_RopeExplosion")
 tok(c,0x0007,0x28,0x0A00000F,"Object.op_Inequality")
 br(c,0x000C,0x39,0x007C,"prefab-null branch")
 tok(c,0x0012,0x7B,0x04005679,"Prefab load instantiate")
 tok(c,0x0017,0x28,0x2B000051,"MethodSpec instantiate")
 tok(c,0x001E,0x6F,0x2B000391,"MethodSpec component")
 tok(c,0x0025,0x6F,0x0A000050,"object transform")
 tok(c,0x002B,0x6F,0x0A00007A,"set_position")
 tok(c,0x0031,0x6F,0x0A000050,"object transform2")
 tok(c,0x0037,0x6F,0x0A00004F,"GetChild0")
 tok(c,0x003C,0x6F,0x0A000028,"child0 gameObject")
 tok(c,0x004A,0x6F,0x0A000050,"root transform loop")
 tok(c,0x0050,0x6F,0x0A00004F,"GetChild loop")
 tok(c,0x0055,0x6F,0x0A000028,"loop child gameObject")
 tok(c,0x005D,0x28,0x06004876,"LayerMan.GetLayerID")
 tok(c,0x0062,0x6F,0x0A0000D7,"GameObject.set_layer")
 tok(c,0x006D,0x6F,0x0A000050,"root transform count")
 tok(c,0x0072,0x6F,0x0A000047,"get_childCount")
 br(c,0x0077,0x3F,0x0049,"loop blt")
 tok(c,0x007C,0x28,0x060050C8,"Ring.GetInst")
 if c[0x0081:0x0083]!=bytes([0x1F,0x0A]):raise ProofError("ring shake arg 10")
 tok(c,0x0083,0x6F,0x060050E3,"mRingShake")
 tok(c,0x0088,0x28,0x06004879,"MatchCamera.GetInst")
 f32(c,0x008D,2.0,"vibration 2")
 tok(c,0x0092,0x6F,0x06004884,"ReqVivration")
 if c[0x0097]!=0x2A:raise ProofError("ret")
 tok(cs["Down"],0x030F,0x6F,0x060048CB,"FACT-0049 caller")
 return {"dll_sha256":got,"method":{"code_size":len(c),"code_sha256":M["Effect"][2]}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_PLAY_MINE_EXPLOSION: PASS");return 0
 except (OSError,ValueError,ProofError) as e:
  print("PROVE_PLAY_MINE_EXPLOSION: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
