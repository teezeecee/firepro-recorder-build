#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "IsLotPriorityAct":(0x002FCE8C,534,"95906f7bec4bf47c92137113114297c666b46a997ca3a1c487e0a1b71c496461"),
 "ProcessPriorityAct":(0x002FD31C,431,"0db6da9710767a5629dec05b3a7521e0aa1cb83f55d6332a648e89fa5917afc1")
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
 c=cs["IsLotPriorityAct"]
 for x in [(0x0000,0x7E,0x040061FA,"PlayerMan.inst"),(0x0006,0x7B,0x0400614A,"PlObj"),(0x000B,0x7B,0x04005FB1,"TargetPlIdx"),(0x0010,0x6F,0x06005065,"GetPlObj"),(0x0016,0x7E,0x04006355,"Ring.inst"),(0x001B,0x7B,0x0400637A,"venueSetting")]:tok(c,*x)
 if c[0x21]!=0x03 or c[0x22]!=0x45:raise ProofError("switch prefix")
 n=struct.unpack_from("<I",c,0x23)[0]
 if n!=41:raise ProofError("switch count")
 base=0x27+4*n
 targets=[base+struct.unpack_from("<i",c,0x27+4*i)[0] for i in range(n)]
 exp=[0x00D0]*6+[0x00D5]*2+[0x00E7]*2+[0x0130]*4+[0x0179]*4+[0x017E]*3+[0x01AC]+[0x020A]*13+[0x020F]*6
 if targets!=exp:raise ProofError("switch targets")
 tok(c,0x00D6,0x28,0x06004FE9,"IsEffectiveFall");br(c,0x00DB,0x3A,0x00E2,"fall true")
 for x in [(0x00E8,0x7B,0x04005FB7,"State89a"),(0x00F5,0x7B,0x04005FB7,"State89b"),(0x0104,0x7B,0x04005FEE,"Zone89"),(0x0110,0x7E,0x04006147,"map89"),(0x0119,0x7B,0x0400614A,"PlObj89"),(0x011F,0x6F,0x06004F1D,"mEqu89"),
 (0x0131,0x7B,0x04005FB7,"State1013a"),(0x013E,0x7B,0x04005FB7,"State1013b"),(0x014D,0x7B,0x04005FEE,"Zone1013"),(0x0159,0x7E,0x04006147,"map1013"),(0x0162,0x7B,0x0400614A,"PlObj1013"),(0x0168,0x6F,0x06004F1D,"mEqu1013"),
 (0x017F,0x7B,0x04005FEE,"Zone1820"),(0x018C,0x7B,0x04006468,"ring1820a"),(0x019A,0x7B,0x04006468,"ring1820b"),
 (0x01AD,0x7B,0x04005FB7,"State21a"),(0x01BA,0x7B,0x04005FB7,"State21b"),(0x01C9,0x7B,0x04005FEE,"Zone21"),(0x01D6,0x7B,0x04006468,"ring21a"),(0x01E4,0x7B,0x04006468,"ring21b"),(0x01F2,0x7B,0x0400614A,"PlObj21"),(0x01F9,0x6F,0x06004F1D,"mEqu21")]:tok(c,*x)
 for x in [(0x00EF,0x3B,0x0103,"state18 89"),(0x00FC,0x3B,0x0103,"state17 89"),(0x0109,0x39,0x0110,"zone89"),(0x0124,0x3A,0x012B,"equip89"),
 (0x0138,0x3B,0x014C,"state18 1013"),(0x0145,0x3B,0x014C,"state17 1013"),(0x0152,0x39,0x0159,"zone1013"),(0x016D,0x3A,0x0174,"equip1013"),
 (0x0184,0x39,0x018B,"zone1820"),(0x0192,0x40,0x0199,"ring1820 !=1"),(0x01A0,0x40,0x01A7,"ring1820 !=3"),
 (0x01B4,0x3B,0x01C8,"state18 21"),(0x01C1,0x3B,0x01C8,"state17 21"),(0x01CE,0x39,0x01D5,"zone21"),(0x01DC,0x40,0x01E3,"ring21 !=1"),(0x01EA,0x40,0x01F1,"ring21 !=3"),(0x01FE,0x3A,0x0205,"equip21")]:br(c,*x)
 if c[0x01F7:0x01F9]!=bytes([0x1F,0x2F]):raise ProofError("raw equipment 47")
 for o in [0x00CB,0x00D0,0x00E2,0x012B,0x0174,0x0179,0x01A7,0x0205,0x020A,0x020F]:br(c,o,0x38,0x0214,"true join")
 if c[0x0214:0x0216]!=bytes([0x17,0x2A]):raise ProofError("true return")
 p=cs["ProcessPriorityAct"];tok(p,0x0155,0x28,0x06005008,"ProcessPriorityAct caller")
 return {"dll_sha256":got,"method":{"code_size":len(c),"code_sha256":M["IsLotPriorityAct"][2]},"switch_count":41}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_IS_LOT_PRIORITY_ACT: PASS");return 0
 except (OSError,ValueError,ProofError) as e:
  print("PROVE_IS_LOT_PRIORITY_ACT: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
