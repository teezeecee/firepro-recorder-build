#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
"EndAIAct":(0x002F60F5,33,"596a7249879f79a09b58884b3296525e4a2fd50a7549e53565f10b10b6d91d2f"),
"EndPriAct":(0x002FD4D7,38,"4f3be7710b4a49b035c4f3d0bcc0be43bc6a36afb09368200886656b9e6ae460"),
"Update":(0x002FFC68,984,"6cea6fc2585177a22c56446c0be26152eed5061fdb0239837f775cad0c2be6d9"),
"UpdateAnimation":(0x002DB890,738,"1e18c732ea0674fae8fdecc0b0d06fc976ec4494df663156925e99c4485b4c00")}
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
def br(c,o,op,t,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=t:raise ProofError(l)
def verify(path):
 got=sha_path(path)
 if got!=DLL_SHA:raise ProofError("DLL SHA "+got)
 pe=Path(path).read_bytes();ss=sections(pe);cs={}
 for n,(r,s,h) in M.items():
  c=code(pe,ss,r)
  if len(c)!=s or hashlib.sha256(c).hexdigest()!=h:raise ProofError(n+" body")
  cs[n]=c
 c=cs["EndAIAct"]
 if c[0:2]!=bytes([0x02,0x16]):raise ProofError("EndAIAct duration args")
 tok(c,0x0002,0x7D,0x0400614C,"aiActDuration zero")
 if c[0x0007:0x0009]!=bytes([0x02,0x16]):raise ProofError("EndAIAct action args")
 tok(c,0x0009,0x7D,0x0400614B,"aiAct zero")
 tok(c,0x000F,0x7B,0x04006151,"currentPriAct")
 if c[0x0014]!=0x15:raise ProofError("raw -1")
 br(c,0x0015,0x3B,0x0020,"currentPriAct == -1")
 tok(c,0x001B,0x28,0x0600500B,"EndPriAct call")
 if c[0x0020]!=0x2A:raise ProofError("EndAIAct ret")
 c=cs["EndPriAct"]
 tok(c,0x0001,0x7B,0x0400616A,"keepLastSkill")
 br(c,0x0006,0x3A,0x0017,"keepLastSkill true skip")
 tok(c,0x000C,0x7B,0x0400614A,"PlObj")
 if c[0x0011]!=0x15:raise ProofError("SetLastSkill raw -1")
 tok(c,0x0012,0x6F,0x06004EB1,"SetLastSkill callvirt")
 tok(c,0x0019,0x7D,0x0400616A,"keepLastSkill zero")
 if c[0x001F:0x0021]!=bytes([0x02,0x15]):raise ProofError("currentPriAct reset args")
 tok(c,0x0021,0x7D,0x04006151,"currentPriAct -1")
 if c[0x0025]!=0x2A:raise ProofError("EndPriAct ret")
 tok(cs["Update"],0x025D,0x28,0x06004FAD,"Update EndAIAct caller")
 tok(cs["UpdateAnimation"],0x028F,0x6F,0x0600500B,"UpdateAnimation EndPriAct caller")
 return {"dll_sha256":got,"methods":{"EndAIAct":{"code_size":len(cs["EndAIAct"]),"code_sha256":M["EndAIAct"][2]},"EndPriAct":{"code_size":len(cs["EndPriAct"]),"code_sha256":M["EndPriAct"][2]}}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_END_AI_ACT_LIFECYCLE: PASS");return 0
 except (OSError,ValueError,ProofError) as e:
  print("PROVE_END_AI_ACT_LIFECYCLE: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
