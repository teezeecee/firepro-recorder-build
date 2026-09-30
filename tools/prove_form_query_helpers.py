#!/usr/bin/env python3
import argparse,hashlib,json,struct
from pathlib import Path

DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
METHODS={
 "IsAnmComplete":(0x002DB5A8,69,"766907d7d20a39e44a0af0fef66b1d47f6548b29eaa8beba381d29f1d91456c1"),
 "IsLastForm":(0x002DB5FC,55,"8d7732e16017ba91bf17d733b6602560309e02121b3399203dd52964aa5d1694"),
 "IsPrevLastAnmFrame":(0x002DB640,69,"21448fc69b9fb12146af52cd1fcbb9d21ae7a3069e4647438e91f04380e78627"),
 "GetCurrentFormDispInfo":(0x002DB694,117,"7bb1c23a0880b9ebe1d997e643e069597c94c0784a03e03ba2b9a1ab207045c0")
}
class ProofError(RuntimeError): pass
def sha_path(p):
 h=hashlib.sha256()
 with open(p,"rb") as f:
  for c in iter(lambda:f.read(1024*1024),b""):h.update(c)
 return h.hexdigest()
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\0\0":raise ProofError("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0];osz=struct.unpack_from("<H",pe,q+20)[0];s=q+24+osz;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,vs,rp,rs))
 return out
def rvaoff(pe,ss,rva):
 for va,vs,rp,rs in ss:
  if va<=rva<va+max(vs,rs):return rp+rva-va
 raise ProofError("RVA unmapped")
def mcode(pe,ss,rva):
 o=rvaoff(pe,ss,rva);b=pe[o]
 if b&3==2:h=1;n=b>>2
 elif b&3==3:
  fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 else:raise ProofError("bad IL header")
 return pe[o+h:o+h+n]
def tok(code,off,op,t,label):
 if code[off]!=op or struct.unpack_from("<I",code,off+1)[0]!=t:raise ProofError(label)
def verify(path):
 got=sha_path(path)
 if got!=DLL_SHA:raise ProofError("DLL SHA "+got)
 pe=Path(path).read_bytes();ss=sections(pe);out={}
 codes={}
 for name,(rva,size,sha) in METHODS.items():
  c=mcode(pe,ss,rva);codes[name]=c
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise ProofError(name+" body")
  out[name]={"rva":f"0x{rva:08X}","code_size":len(c),"code_sha256":sha}
 c=codes["IsAnmComplete"]
 tok(c,0x0001,0x7B,0x04005ED4,"complete duration")
 tok(c,0x000F,0x7B,0x04005EEA,"complete boot")
 tok(c,0x001C,0x7B,0x04005ED0,"complete skill")
 tok(c,0x0027,0x7B,0x04005ED1,"complete anm idx")
 tok(c,0x002F,0x7B,0x04005ED5,"complete form idx")
 tok(c,0x0035,0x7B,0x04007C93,"complete formNum")
 c=codes["IsLastForm"]
 tok(c,0x0001,0x7B,0x04005EEA,"last boot")
 tok(c,0x000E,0x7B,0x04005ED0,"last skill")
 tok(c,0x0019,0x7B,0x04005ED1,"last anm idx")
 tok(c,0x0021,0x7B,0x04005ED5,"last form idx")
 tok(c,0x0027,0x7B,0x04007C93,"last formNum")
 c=codes["IsPrevLastAnmFrame"]
 tok(c,0x0001,0x7B,0x04005ED4,"prev duration")
 if c[0x0006]!=0x17:raise ProofError("prev threshold")
 tok(c,0x000F,0x7B,0x04005EEA,"prev boot")
 tok(c,0x002F,0x7B,0x04005ED5,"prev form idx")
 tok(c,0x0035,0x7B,0x04007C93,"prev formNum")
 c=codes["GetCurrentFormDispInfo"]
 tok(c,0x0001,0x7B,0x04005ED0,"info CurrentSkill")
 tok(c,0x000E,0x7B,0x04005ED1,"info CurrentAnmIdx #1")
 tok(c,0x001A,0x7B,0x04005ED1,"info CurrentAnmIdx #2")
 tok(c,0x0020,0x7B,0x04005ED0,"info CurrentSkill #2")
 tok(c,0x0025,0x7B,0x04007C7A,"info anmData length")
 tok(c,0x0034,0x7B,0x04005ED0,"info CurrentSkill #3")
 tok(c,0x0039,0x7B,0x04007C7A,"info anmData element")
 tok(c,0x0047,0x7B,0x04005ED5,"info form idx #1")
 tok(c,0x0053,0x7B,0x04005ED5,"info form idx #2")
 tok(c,0x0059,0x7B,0x04007C9F,"info formDispList length")
 tok(c,0x0068,0x7B,0x04007C9F,"info formDispList return")
 tok(c,0x006E,0x7B,0x04005ED5,"info return idx")
 if c[0x0073]!=0x9A or c[0x0074]!=0x2A:raise ProofError("info return")
 return {"dll_sha256":got,"methods":out}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_FORM_QUERY_HELPERS: PASS");return 0
 except (OSError,ValueError,ProofError) as e:
  print("PROVE_FORM_QUERY_HELPERS: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
