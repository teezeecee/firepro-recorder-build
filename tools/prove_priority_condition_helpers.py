#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "IsEffectiveFall":(0x002FA69C,111,"022740847f18e115a477191d3dff827edb956e998dae7496eb1ed591b26ae6eb"),
 "mEquExistCehck":(0x002E8263,22,"62f4465a263d518b20434cedb4b42170c20ce2113adfaeb967e19f1ff7b3d204"),
 "IsLotPriorityAct":(0x002FCE8C,534,"95906f7bec4bf47c92137113114297c666b46a997ca3a1c487e0a1b71c496461")
}
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
 fb=pe[o]
 if fb&3==2:h=1;n=fb>>2
 elif fb&3==3:
  fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 else:raise ProofError("bad IL header")
 return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise ProofError(l)
def br(c,o,op,t,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=t:raise ProofError(l)
def verify(path):
 got=sha_path(path)
 if got!=DLL_SHA:raise ProofError("DLL SHA "+got)
 pe=Path(path).read_bytes();ss=sections(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise ProofError(n+" body")
  cs[n]=c
 c=cs["IsEffectiveFall"]
 for x in [(0x0000,0x7E,0x040061FA,"PlayerMan.inst"),(0x0006,0x7B,0x0400614A,"PlObj"),(0x000B,0x7B,0x04005FB1,"Target"),(0x0010,0x6F,0x06005065,"GetPlObj"),
 (0x0016,0x7E,0x04002AD1,"GlobalWork.inst"),(0x001B,0x7B,0x04002AD2,"MatchSetting"),(0x0022,0x7B,0x040057D0,"Victory #3"),(0x0030,0x7B,0x040057D0,"Victory #4"),
 (0x003E,0x7B,0x0400614A,"PlObj zone"),(0x0043,0x7B,0x04005FEE,"Zone"),(0x0051,0x7B,0x0400614A,"PlObj right"),(0x0056,0x7B,0x04006043,"self hasRight"),(0x0061,0x7B,0x04006043,"target hasRight")]:tok(c,*x)
 for x in [(0x0028,0x40,0x002F,"Victory !=3"),(0x0036,0x40,0x003D,"Victory !=4"),(0x0049,0x40,0x0050,"Zone !=1"),(0x005B,0x39,0x006B,"self hasRight"),(0x0066,0x3A,0x006D,"target hasRight")]:br(c,*x)
 if c[0x0027]!=0x19 or c[0x0035]!=0x1A or c[0x0048]!=0x17:raise ProofError("raw values")
 if c[0x006B:0x006F]!=bytes([0x16,0x2A,0x17,0x2A]):raise ProofError("false/true returns")
 c=cs["mEquExistCehck"]
 tok(c,0x0001,0x7B,0x04005FB3,"WresParam");tok(c,0x0006,0x7B,0x040010A6,"skillSlot")
 if c[0x000B:0x000D]!=bytes([0x03,0x94]):raise ProofError("slot ldelem.i4")
 br(c,0x000D,0x39,0x0014,"slot element zero")
 if c[0x0012:0x0016]!=bytes([0x17,0x2A,0x16,0x2A]):raise ProofError("equip returns")
 i=cs["IsLotPriorityAct"]
 tok(i,0x00D6,0x28,0x06004FE9,"IsLot IsEffectiveFall")
 tok(i,0x011F,0x6F,0x06004F1D,"IsLot equip89")
 tok(i,0x0168,0x6F,0x06004F1D,"IsLot equip1013")
 tok(i,0x01F9,0x6F,0x06004F1D,"IsLot equip21")
 return {"dll_sha256":got,"methods":{
  "IsEffectiveFall":{"code_size":len(cs["IsEffectiveFall"]),"code_sha256":M["IsEffectiveFall"][2]},
  "mEquExistCehck":{"code_size":len(cs["mEquExistCehck"]),"code_sha256":M["mEquExistCehck"][2]}}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_PRIORITY_CONDITION_HELPERS: PASS");return 0
 except (OSError,ValueError,ProofError) as e:
  print("PROVE_PRIORITY_CONDITION_HELPERS: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
