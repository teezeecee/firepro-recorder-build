#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00324D5C
SIZE=248
CODE_SHA="e52c9533e53cc4ced4f3643da73e1e997b793257adba26adbc42fa9c4e834754"
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
 if b&3==2:return {"flags":2,"header":1,"max_stack":8,"local_sig":0,"code":pe[o+1:o+1+(b>>2)]}
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return {"flags":fs&0x0FFF,"header":h,"max_stack":struct.unpack_from("<H",pe,o+2)[0],"local_sig":struct.unpack_from("<I",pe,o+8)[0],"code":pe[o+h:o+h+n]}
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,target,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=target:raise E(l)
def brs(c,o,op,target,l):
 if c[o]!=op or o+2+struct.unpack_from("<b",c,o+1)[0]!=target:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 m=method(pe,sections(pe),RVA);c=m["code"]
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if m["flags"]!=0x0013 or m["header"]!=12 or m["max_stack"]!=2 or m["local_sig"]!=0x1100121C:raise E("header")
 tok(c,0x0001,0x7B,0x0400C24C,"$PC load")
 tok(c,0x0009,0x7D,0x0400C24C,"$PC=-1")
 if c[0x000F]!=0x45 or struct.unpack_from("<I",c,0x0010)[0]!=2:raise E("switch")
 base=0x001C
 targets=[base+struct.unpack_from("<i",c,0x0014+i*4)[0] for i in range(2)]
 if targets!=[0x0021,0x005B]:raise E("switch targets")
 br(c,0x001C,0x38,0x00F4,"default")
 tok(c,0x0023,0x7B,0x0400C245,"fn")
 tok(c,0x0028,0x28,0x0A000FAB,"LoadFromFileAsync")
 tok(c,0x002D,0x7D,0x0400C246,"request store")
 br(c,0x0032,0x38,0x005B,"init join")
 if c[0x0037]!=0x02 or c[0x0038]!=0x22 or struct.unpack_from("<f",c,0x0039)[0]!=0.0:raise E("WaitForSeconds args")
 tok(c,0x003D,0x73,0x0A000679,"WaitForSeconds ctor")
 tok(c,0x0042,0x7D,0x0400C24A,"$current")
 tok(c,0x0048,0x7B,0x0400C24B,"$disposing")
 brs(c,0x004D,0x2D,0x0056,"disposing")
 tok(c,0x0051,0x7D,0x0400C24C,"$PC=1")
 br(c,0x0056,0x38,0x00F6,"yield true")
 tok(c,0x005C,0x7B,0x0400C246,"request poll")
 tok(c,0x0061,0x6F,0x0A000676,"isDone")
 br(c,0x0066,0x39,0x0037,"poll loop")
 tok(c,0x006C,0x7B,0x0400C246,"request asset #1")
 tok(c,0x0071,0x6F,0x0A000FAC,"get_assetBundle #1")
 if c[0x0076]!=0x14:raise E("null")
 tok(c,0x0077,0x28,0x0A00000F,"Object inequality")
 br(c,0x007C,0x39,0x00C0,"bundle null")
 tok(c,0x0082,0x7B,0x0400C246,"request asset #2")
 tok(c,0x0087,0x6F,0x0A000FAC,"get_assetBundle #2")
 tok(c,0x008D,0x7B,0x0400C245,"fn path")
 tok(c,0x0092,0x28,0x0A00071A,"Path.GetFileName")
 tok(c,0x0097,0x6F,0x2B000100,"LoadAsset AudioClip")
 tok(c,0x009D,0x7E,0x040086F4,"audioClipInfo")
 tok(c,0x00A3,0x7B,0x0400C247,"system_sound #1")
 if c[0x00A8]!=0x9A or c[0x00A9]!=0x07:raise E("array/local clip")
 tok(c,0x00AA,0x6F,0x060052C2,"FACT-0113 AudioClipInfo.Set")
 tok(c,0x00B0,0x7B,0x0400C246,"request asset #3")
 tok(c,0x00B5,0x6F,0x0A000FAC,"get_assetBundle #3")
 if c[0x00BA]!=0x16:raise E("Unload false")
 tok(c,0x00BB,0x6F,0x0A00079E,"AssetBundle.Unload")
 tok(c,0x00C1,0x7B,0x0400C248,"onLoad gate")
 br(c,0x00C6,0x39,0x00D6,"onLoad null")
 tok(c,0x00CC,0x7B,0x0400C248,"onLoad invoke receiver")
 tok(c,0x00D1,0x6F,0x0A0003DE,"Action.Invoke")
 tok(c,0x00D7,0x7B,0x0400C249,"bStart")
 br(c,0x00DC,0x39,0x00ED,"bStart false")
 tok(c,0x00E2,0x7B,0x0400C247,"system_sound #2")
 if c[0x00E7]!=0x17:raise E("raw1")
 tok(c,0x00E8,0x28,0x0600529E,"Play_BGM")
 tok(c,0x00EF,0x7D,0x0400C24C,"final $PC")
 if c[0x00F4:0x00F8]!=bytes([0x16,0x2A,0x17,0x2A]):raise E("returns")
 print("PROVE_MENU_SOUND_COCHANGE_BUNDLE_MOVENEXT: PASS")
if __name__=="__main__":main()
