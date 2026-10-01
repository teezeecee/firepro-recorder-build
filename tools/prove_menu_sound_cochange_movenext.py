#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00324C5C
SIZE=196
CODE_SHA="9d1407458612aaaf641a3eb39d593c95ae61e1e459a85eaa9240647a95763a1f"
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\\0\\0":raise E("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def method(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3==2:return {"flags":2,"max_stack":8,"local_sig":0,"code":pe[o+1:o+1+(b>>2)]}
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return {"flags":fs&0x0FFF,"max_stack":struct.unpack_from("<H",pe,o+2)[0],"local_sig":struct.unpack_from("<I",pe,o+8)[0],"code":pe[o+h:o+h+n]}
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,t,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=t:raise E(l)
def brs(c,o,op,t,l):
 if c[o]!=op or o+2+int.from_bytes(c[o+1:o+2],"little",signed=True)!=t:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 m=method(pe,sections(pe),RVA);c=m["code"]
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if m["flags"]!=0x0013 or m["max_stack"]!=2 or m["local_sig"]!=0x11000047:raise E("header")
 if c[0]!=0x02:raise E("this pc load")
 tok(c,0x0001,0x7B,0x0400C244,"$PC load")
 if c[0x0006:0x0009]!=bytes([0x0A,0x02,0x15]):raise E("state local / -1")
 tok(c,0x0009,0x7D,0x0400C244,"$PC=-1")
 if c[0x000E]!=0x06 or c[0x000F]!=0x45:raise E("switch")
 if struct.unpack_from("<I",c,0x0010)[0]!=2:raise E("switch count")
 base=0x0014+8
 t0=base+struct.unpack_from("<i",c,0x0014)[0];t1=base+struct.unpack_from("<i",c,0x0018)[0]
 if (t0,t1)!=(0x0021,0x005B):raise E("switch targets")
 br(c,0x001C,0x38,0x00C0,"switch default")
 if c[0x0021:0x0023]!=bytes([0x02,0x02]):raise E("init receivers")
 tok(c,0x0023,0x7B,0x0400C23D,"fn")
 tok(c,0x0028,0x28,0x0A000675,"Resources.LoadAsync")
 tok(c,0x002D,0x7D,0x0400C23E,"resReq store")
 br(c,0x0032,0x38,0x005B,"init to poll")
 if c[0x0037]!=0x02 or c[0x0038]!=0x22 or struct.unpack_from("<f",c,0x0039)[0]!=0.0:raise E("WaitForSeconds zero")
 tok(c,0x003D,0x73,0x0A000679,"WaitForSeconds ctor")
 tok(c,0x0042,0x7D,0x0400C242,"$current")
 if c[0x0047]!=0x02:raise E("disposing receiver")
 tok(c,0x0048,0x7B,0x0400C243,"$disposing")
 brs(c,0x004D,0x2D,0x0056,"disposing true")
 if c[0x004F:0x0051]!=bytes([0x02,0x17]):raise E("pc resume args")
 tok(c,0x0051,0x7D,0x0400C244,"$PC=1")
 br(c,0x0056,0x38,0x00C2,"yield true")
 if c[0x005B]!=0x02:raise E("poll receiver")
 tok(c,0x005C,0x7B,0x0400C23E,"resReq poll")
 tok(c,0x0061,0x6F,0x0A000676,"get_isDone")
 br(c,0x0066,0x39,0x0037,"not done")
 tok(c,0x006B,0x7E,0x040086F4,"audioClipInfo")
 if c[0x0070]!=0x02:raise E("system sound receiver")
 tok(c,0x0071,0x7B,0x0400C23F,"system_sound #1")
 if c[0x0076]!=0x9A:raise E("audioClipInfo index")
 if c[0x0077]!=0x02:raise E("asset receiver")
 tok(c,0x0078,0x7B,0x0400C23E,"resReq asset")
 tok(c,0x007D,0x6F,0x0A000677,"get_asset")
 tok(c,0x0082,0x75,0x01000012,"AudioClip isinst")
 tok(c,0x0087,0x7D,0x0400874B,"AudioClipInfo.audioClip")
 if c[0x008C]!=0x02:raise E("onLoad receiver #1")
 tok(c,0x008D,0x7B,0x0400C240,"onLoad #1")
 br(c,0x0092,0x39,0x00A2,"onLoad null")
 if c[0x0097]!=0x02:raise E("onLoad receiver #2")
 tok(c,0x0098,0x7B,0x0400C240,"onLoad #2")
 tok(c,0x009D,0x6F,0x0A0003DE,"Action.Invoke")
 if c[0x00A2]!=0x02:raise E("bStart receiver")
 tok(c,0x00A3,0x7B,0x0400C241,"bStart")
 br(c,0x00A8,0x39,0x00B9,"bStart false")
 if c[0x00AD]!=0x02:raise E("system sound receiver #2")
 tok(c,0x00AE,0x7B,0x0400C23F,"system_sound #2")
 if c[0x00B3]!=0x17:raise E("Play_BGM raw1")
 tok(c,0x00B4,0x28,0x0600529E,"Play_BGM")
 if c[0x00B9:0x00BB]!=bytes([0x02,0x15]):raise E("final pc args")
 tok(c,0x00BB,0x7D,0x0400C244,"final $PC=-1")
 if c[0x00C0:0x00C4]!=bytes([0x16,0x2A,0x17,0x2A]):raise E("false/true returns")
 print("PROVE_MENU_SOUND_COCHANGE_MOVENEXT: PASS")
if __name__=="__main__":main()
