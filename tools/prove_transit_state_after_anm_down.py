#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={"Down":(0x002E0584,807,"279517cb863c131495de999594e2eecb0ec3cfaada975d4215ee0efd7fb2b6f6"),"Transit":(0x002E0B8C,1438,"cb9c68b98a1db450cee699fde8a7ab45926cb582dafa5b9e78e51b87d8886bb6")}
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
def i4(c,o,v,l):
 if c[o]!=0x20 or struct.unpack_from("<i",c,o+1)[0]!=v:raise ProofError(l)
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
 c=cs["Down"]
 tok(c,0x0006,0x6F,0x06004E7C,"GetCurrentFormDispInfo")
 tok(c,0x0025,0x28,0x06004964,"ChangePlayerDirToLR")
 i4(c,0x003A,256,"FormRev mask256")
 tok(c,0x004C,0x28,0x06004963,"ChangePlayerDirToLRAndReverse")
 # KO animations / states
 i4(c,0x0081,296,"KO form100 anim");tok(c,0x008A,0x28,0x06004EAE,"KO state17")
 i4(c,0x0094,297,"KO other anim");tok(c,0x009D,0x28,0x06004EAE,"KO state18")
 tok(c,0x00AB,0x6F,0x06004E6F,"KO ReqBasic")
 # ordered limbs and animations
 for off,t in [(0x00BE,0x04005FC2),(0x00FF,0x04005FC3),(0x0140,0x04005FC4),(0x0181,0x04005FC5)]:tok(c,off,0x7B,t,"limb "+hex(off))
 for off,v in [(0x00E8,354),(0x0129,356),(0x016A,358),(0x01AB,360)]:i4(c,off,v,"raw limb anim")
 for off in [0x00F4,0x0135,0x0176,0x01B7]:tok(c,off,0x28,0x06004ED8,"SetDownTime255")
 i4(c,0x01C1,180,"default anim180")
 tok(c,0x01F4,0x6F,0x06004E6F,"common ReqBasic")
 # mine branch
 tok(c,0x023F,0x28,0x060050FC,"IsStepOnMine")
 tok(c,0x0268,0x28,0x06004F1F,"Bleeding")
 f32(c,0x026D,9216.0,"damage base9216")
 tok(c,0x027D,0x28,0x0600495C,"GetHealth")
 tok(c,0x028A,0x28,0x06004ECB,"AddHP")
 f32(c,0x0290,9216.0,"ConsumeSP9216");tok(c,0x0295,0x28,0x06004ED1,"ConsumeSP")
 tok(c,0x029C,0x28,0x06004EDC,"SetLastDamage")
 tok(c,0x02AD,0x28,0x06004F0C,"ForceSetDownTime")
 i4(c,0x02C3,200,"min down200");tok(c,0x02C8,0x28,0x06004ED8,"SetDownTime200")
 tok(c,0x030F,0x6F,0x060048CB,"Play_MineExplosion")
 if c[0x0314:0x0316]!=bytes([0x1F,0x43]):raise ProofError("SE raw67")
 tok(c,0x0321,0x28,0x06004970,"PlayMatchSE")
 if c[0x0326]!=0x2A:raise ProofError("ret")
 tok(cs["Transit"],0x011B,0x28,0x06004EC6,"FACT-0048 caller")
 return {"dll_sha256":got,"method":{"code_size":len(c),"code_sha256":M["Down"][2]}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_TRANSIT_STATE_AFTER_ANM_DOWN: PASS");return 0
 except (OSError,ValueError,ProofError) as e:
  print("PROVE_TRANSIT_STATE_AFTER_ANM_DOWN: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
