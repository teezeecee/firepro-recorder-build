#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00316C6C
SIZE=45
CODE_SHA="d353bf6e7046434074ecca1c5a62cb8cd9ec636500659fc5b9083f2943c7d841"
CALLER_RVA=0x0006CA54
CALLER_SHA="f49006bbea8bcc23f4ac9019fc646d7fd2dc09edad531bc204b027a920bcc8c2"
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\\0\\0":raise E("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def body(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3==2:return pe[o+1:o+1+(b>>2)]
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,t,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=t:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);c=body(pe,ss,RVA);cc=body(pe,ss,CALLER_RVA)
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if hashlib.sha256(cc).hexdigest()!=CALLER_SHA:raise E("caller")
 if c[0]!=0x03:raise E("dlc arg")
 tok(c,0x0001,0x28,0x06001033,"DLCChecker.IsOwner")
 br(c,0x0006,0x3A,0x000D,"owner true")
 if c[0x000B:0x000D]!=bytes([0x16,0x2A]):raise E("owner false return")
 if c[0x000D]!=0x02:raise E("this")
 tok(c,0x000E,0x7B,0x0400650C,"dlcVersion")
 if c[0x0013:0x0015]!=bytes([0x03,0x94]):raise E("dlcVersion[dlc]")
 br(c,0x0015,0x39,0x002B,"version zero")
 if c[0x001A:0x001C]!=bytes([0x03,0x19]):raise E("dlc/raw3")
 br(c,0x001C,0x40,0x0029,"dlc != 3")
 if c[0x0021:0x0023]!=bytes([0x02,0x18]):raise E("this/raw2")
 tok(c,0x0023,0x28,0x060051C9,"recursive IsDLCInstalled")
 if c[0x0028]!=0x2A:raise E("recursive return")
 if c[0x0029:0x002B]!=bytes([0x17,0x2A]):raise E("non3 true return")
 if c[0x002B:0x002D]!=bytes([0x16,0x2A]):raise E("version false return")
 tok(cc,0x0027,0x6F,0x060051C9,"FACT-0117 caller")
 print("PROVE_SAVE_DATA_IS_DLC_INSTALLED: PASS")
if __name__=="__main__":main()
