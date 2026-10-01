#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={"Auto":(0x002E08B8,712,"6bd624830f79c47cf800b28715a0f2628127003f9bf80484b8da7793ecaeb56d"),"Transit":(0x002E0B8C,1438,"cb9c68b98a1db450cee699fde8a7ab45926cb582dafa5b9e78e51b87d8886bb6")}
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
 c=cs["Auto"]
 tok(c,0x0016,0x6F,0x06005065,"GetPlObj")
 tok(c,0x0023,0x7B,0x04005ED9,"SkillSlotID")
 tok(c,0x0028,0x7D,0x04006010,"AutoRunWaza")
 tok(c,0x005D,0x28,0x0A000089,"Vector2 implicit")
 tok(c,0x0062,0x6F,0x060050E9,"ring area")
 for off in [0x0095,0x00B8,0x00F0,0x0113]:tok(c,off,0x28,0x06004961,"upper triangle "+hex(off))
 tok(c,0x0162,0x28,0x060050FB,"inside cross line")
 tok(c,0x019C,0x28,0x0A0009B6,"Mathf.Sqrt")
 f32(c,0x01A5,2.0833332538604736,"distance threshold 1")
 f32(c,0x01B3,2.9166665077209473,"distance threshold 2")
 tok(c,0x020D,0x28,0x06004EAE,"state56")
 tok(c,0x0230,0x6F,0x06004E6F,"ReqBasic")
 tok(c,0x0296,0x28,0x06004EAE,"state10")
 tok(c,0x029E,0x6F,0x06004EAE,"target state47")
 tok(c,0x02AA,0x6F,0x06004E75,"StartAnm7")
 tok(c,0x02C2,0x6F,0x06004E77,"StartOpponentAnmM")
 if c[0x02C7]!=0x2A:raise ProofError("ret")
 tok(cs["Transit"],0x03A6,0x28,0x06004EC7,"FACT-0048 caller")
 return {"dll_sha256":got,"method":{"code_size":len(c),"code_sha256":M["Auto"][2]}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_TRANSIT_STATE_AFTER_ANM_AUTORUN: PASS");return 0
 except (OSError,ValueError,ProofError) as e:
  print("PROVE_TRANSIT_STATE_AFTER_ANM_AUTORUN: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
