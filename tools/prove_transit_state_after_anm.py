#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={"Transit":(0x002E0B8C,1438,"cb9c68b98a1db450cee699fde8a7ab45926cb582dafa5b9e78e51b87d8886bb6"),"UpdatePlayer":(0x002F4308,836,"da9fecfe8759295bfca091cebf9c3d58f54802008907127c9658db73eadfbf15")}
TARGETS=[0x0172,0x059D,0x02D9,0x0331,0x059D,0x026A,0x01F5,0x0350,0x03A5,0x03B0,0x03C9,0x0418,0x04A8,0x0584]
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
def switch_targets(c,o):
 if c[o]!=0x45:raise ProofError("switch opcode")
 n=struct.unpack_from("<I",c,o+1)[0];base=o+5+4*n
 return [base+struct.unpack_from("<i",c,o+5+4*i)[0] for i in range(n)]
def verify(path):
 got=sha_path(path)
 if got!=DLL_SHA:raise ProofError("DLL SHA "+got)
 pe=Path(path).read_bytes();ss=sections(pe);cs={}
 for n,(r,s,h) in M.items():
  c=code(pe,ss,r)
  if len(c)!=s or hashlib.sha256(c).hexdigest()!=h:raise ProofError(n+" body")
  cs[n]=c
 c=cs["Transit"]
 tok(c,0x0006,0x6F,0x06004E79,"IsAnmComplete")
 tok(c,0x0034,0x6F,0x06005065,"GetPlObj")
 tok(c,0x003B,0x28,0x06004EC5,"PostprocessEachState")
 tok(c,0x006C,0x6F,0x060050EE,"Octagon collision")
 tok(c,0x0086,0x6F,0x060050E9,"Rhombus area")
 tok(c,0x00A1,0x6F,0x060050F7,"runway center")
 tok(c,0x00B3,0x28,0x06004F1C,"mForceFallStatus")
 tok(c,0x00BE,0x28,0x06004EE3,"mForceDropStatus")
 tok(c,0x00D6,0x28,0x06004EDA,"SetStunTime111")
 tok(c,0x00E1,0x28,0x06004ED8,"SetDownTime143")
 tok(c,0x00F4,0x6F,0x06004E7C,"GetCurrentFormDispInfo")
 tok(c,0x011B,0x28,0x06004EC6,"TransitStateAfterAnm_Down")
 if switch_targets(c,0x0130)!=TARGETS:raise ProofError("AnimeEnd switch targets")
 tok(c,0x03A6,0x28,0x06004EC7,"TransitStateAfterAnm_AutoRun")
 # representative case calls
 for off,t in [(0x01BD,0x06004EAE),(0x01DD,0x06004E6F),(0x02B0,0x06004EAE),(0x02CF,0x06004E6F),(0x030E,0x06004EAE),(0x0320,0x06004E6F),(0x0353,0x06004EAE),(0x0383,0x06004E75),(0x039B,0x06004E77),(0x052A,0x06004EAE),(0x054D,0x06004E6F),(0x0587,0x06004EAE)]:
  tok(c,off,0x28 if off not in (0x01DD,0x02CF,0x0320,0x0383,0x039B,0x054D) else 0x6F,t,"case call "+hex(off))
 tok(cs["UpdatePlayer"],0x0066,0x28,0x06004EC8,"FACT-0047 caller")
 if c[0x059D]!=0x2A:raise ProofError("final return")
 return {"dll_sha256":got,"method":{"code_size":len(c),"code_sha256":M["Transit"][2]},"switch_targets":[hex(x) for x in TARGETS]}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_TRANSIT_STATE_AFTER_ANM: PASS");return 0
 except (OSError,ValueError,ProofError) as e:
  print("PROVE_TRANSIT_STATE_AFTER_ANM: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
