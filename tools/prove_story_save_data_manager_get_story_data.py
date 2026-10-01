#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x0023A1BD
SIZE=12
CODE_SHA="564cd017b6b587e05dc90b0c95294394b6d0d874e7c59dee6c493fa3182cb611"
CALLER_RVA=0x00314983
CALLER_SHA="dcca7695b47672ce7825fed3223764f312476b6d900da9aa66b929a54916780b"
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\0\0":raise E("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def code(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3==2:h=1;n=b>>2
 else:
  fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);c=code(pe,ss,RVA);cc=code(pe,ss,CALLER_RVA)
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if hashlib.sha256(cc).hexdigest()!=CALLER_SHA:raise E("caller")
 if c[0x0000]!=0x02:raise E("this")
 tok(c,0x0001,0x7E,0x04004856,"StoryWork.storyScenario")
 tok(c,0x0006,0x28,0x06003C25,"GetStoryData(StoryScenario)")
 if c[0x000B]!=0x2A:raise E("ret")
 tok(cc,0x001C,0x7E,0x0400497D,"StorySaveDataManager.inst")
 tok(cc,0x0021,0x6F,0x06003C24,"FACT-0101 caller")
 print("PROVE_STORY_SAVE_DATA_MANAGER_GET_STORY_DATA: PASS")
if __name__=="__main__":main()
