#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "TryToDoPriorityAct":(0x002FD0B0,606,"f1818f56bcb7b04635a7c1b9cb814f1e20480577a20287b2d8ee4d438e109191"),
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
def i4(c,o,v,l):
 if c[o]!=0x20 or struct.unpack_from("<i",c,o+1)[0]!=v:raise ProofError(l)
def verify(path):
 got=sha_path(path)
 if got!=DLL_SHA:raise ProofError("DLL SHA "+got)
 pe=Path(path).read_bytes();ss=sections(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise ProofError(n+" body")
  cs[n]=c
 c=cs["TryToDoPriorityAct"]
 if c[0]!=0x03 or c[1]!=0x45:raise ProofError("switch prefix")
 n=struct.unpack_from("<I",c,2)[0]
 if n!=41:raise ProofError("switch count")
 base=6+4*n
 targets=[base+struct.unpack_from("<i",c,6+4*i)[0] for i in range(n)]
 exp=[0x00AF]*6+[0x00D0]*2+[0x00F1]*2+[0x014D]*4+[0x01BF]*4+[0x01E2]*3+[0x0204]+[0x021D]*13+[0x023D]*6
 if targets!=exp:raise ProofError("switch targets")
 for off in [0x00AF,0x00D0,0x00F1,0x014D,0x01BF,0x01E2,0x021D,0x023D]:tok(c,off,0x7E,0x04006147,"PriotityActToAIOpt")
 for off in [0x00C6,0x00E7,0x0143,0x01B5,0x01DB,0x01FA,0x0213,0x0233,0x0252]:tok(c,off,0x7D,0x04006151,"currentPriAct")
 for off in [0x00BF,0x00E0]:tok(c,off,0x28,0x06004FA4,"SetAIAct_DownAtk")
 i4(c,0x00B9,180,"down 180a");i4(c,0x00DA,180,"down 180b")
 if c[0x00BE]!=0x17 or c[0x00DF]!=0x17:raise ProofError("down flag1")
 for x in [(0x00FA,0x7B,0x0400614A,"PlObj89"),(0x0101,0x6F,0x06004EB2,"GetSkillData89"),(0x010E,0x7B,0x04005FB1,"Target89"),(0x0114,0x28,0x06004FEC,"GetDiveCorner_LR"),(0x012F,0x28,0x06004FA2,"RunUpStand"),(0x013C,0x28,0x06004FA3,"RunUpDown"),
 (0x0157,0x7B,0x0400614A,"PlObj1013"),(0x015F,0x6F,0x06004EB2,"GetSkillData1013"),(0x016C,0x7B,0x04005FB7,"State"),(0x017D,0x7B,0x04005FEF,"PostPos"),(0x0190,0x7B,0x04005FB1,"Target1013"),(0x0197,0x28,0x06004FEB,"GetDiveCorner"),(0x01AE,0x28,0x06004FA1,"SetAIAct_CornerDive"),
 (0x01C9,0x7E,0x04006143,"PerformanceKeyTbl"),(0x01D4,0x7D,0x04006118,"padPush"),
 (0x01F3,0x28,0x06004FAA,"PriAct_RunAtk"),(0x020C,0x28,0x06004F9D,"SetAIAct"),(0x022C,0x28,0x06004F9E,"GoGrapple"),(0x024B,0x28,0x06004FA0,"GoBackGrapple")]:tok(c,*x)
 br(c,0x011E,0x40,0x0125,"cornerLR!=-1");br(c,0x0127,0x40,0x0139,"act!=8");br(c,0x0134,0x38,0x0141,"runup join")
 br(c,0x0172,0x40,0x0189,"state!=6");br(c,0x0184,0x38,0x01A8,"postpos join");br(c,0x01A1,0x40,0x01A8,"corner!=-1")
 if c[0x01D0:0x01D3]!=bytes([0x1F,0x56,0x59]):raise ProofError("performance -86")
 if c[0x01DA]!=0x15 or c[0x01E0:0x01E2]!=bytes([0x18,0x2A]):raise ProofError("performance current=-1 return2")
 i4(c,0x01EE,768,"run attack 768")
 if c[0x0205:0x0207]!=bytes([0x1F,0x11]):raise ProofError("act21 action17")
 i4(c,0x0207,768,"act21 768")
 if c[0x0229:0x022C]!=bytes([0x18,0x1F,0x20]):raise ProofError("grapple args 2,32")
 if c[0x0249:0x024B]!=bytes([0x1F,0x20]):raise ProofError("back grapple arg32")
 br(c,0x00AA,0x38,0x025C,"default return1")
 if c[0x025C:0x025E]!=bytes([0x17,0x2A]):raise ProofError("raw return1")
 p=cs["ProcessPriorityAct"];tok(p,0x0180,0x28,0x06005009,"ProcessPriorityAct caller")
 return {"dll_sha256":got,"method":{"code_size":len(c),"code_sha256":M["TryToDoPriorityAct"][2]},"switch_count":41}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_TRY_TO_DO_PRIORITY_ACT: PASS");return 0
 except (OSError,ValueError,ProofError) as e:
  print("PROVE_TRY_TO_DO_PRIORITY_ACT: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
