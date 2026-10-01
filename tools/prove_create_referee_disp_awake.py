#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x0016B410
SIZE=203
CODE_SHA="c6838190cec43f4419a3adb7d1d18f7d38e4810430ed454c346d422f8a8db9b4"
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
 if b&3==2:return {"max_stack":8,"local_sig":0,"code":pe[o+1:o+1+(b>>2)]}
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return {"max_stack":struct.unpack_from("<H",pe,o+2)[0],"local_sig":struct.unpack_from("<I",pe,o+8)[0],"code":pe[o+h:o+h+n]}
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,t,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=t:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 m=method(pe,sections(pe),RVA);c=m["code"]
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if m["max_stack"]!=4 or m["local_sig"]!=0x11000966:raise E("header")
 tok(c,0x0001,0x72,0x7004AC4C,"full referee layer path")
 tok(c,0x0006,0x28,0x0A000662,"GameObject.Find #1")
 tok(c,0x000B,0x7D,0x040032D6,"Obj_ParentReferee store #1")
 tok(c,0x0011,0x7B,0x040032D6,"Obj_ParentReferee load")
 if c[0x0016]!=0x14:raise E("null")
 tok(c,0x0017,0x28,0x0A000006,"Object equality")
 br(c,0x001C,0x39,0x009C,"existing parent branch")
 tok(c,0x0021,0x72,0x7002DE90,"dialog camera path")
 tok(c,0x0026,0x28,0x0A000662,"GameObject.Find #2")
 tok(c,0x002D,0x73,0x0A0001F4,"GameObject ctor")
 tok(c,0x0032,0x7D,0x040032D6,"Obj_ParentReferee store #2")
 tok(c,0x0038,0x7B,0x040032D6,"Obj_ParentReferee transform owner")
 tok(c,0x003D,0x6F,0x0A000050,"get_transform child")
 tok(c,0x0043,0x6F,0x0A000050,"get_transform parent")
 tok(c,0x0048,0x6F,0x0A000061,"set_parent")
 tok(c,0x004E,0x7B,0x040032D6,"name owner")
 tok(c,0x0053,0x72,0x7004ACB2,"referee layer name")
 tok(c,0x0058,0x6F,0x0A0000E1,"set_name")
 tok(c,0x005E,0x7B,0x040032D6,"position owner")
 tok(c,0x0063,0x6F,0x0A000050,"get_transform position")
 tok(c,0x0068,0x28,0x0A00003D,"Vector3.zero")
 tok(c,0x006D,0x6F,0x0A00005B,"set_localPosition")
 tok(c,0x0073,0x7B,0x040032D6,"scale one owner")
 tok(c,0x0078,0x6F,0x0A000050,"get_transform scale one")
 tok(c,0x007D,0x28,0x0A0000D4,"Vector3.one")
 tok(c,0x0082,0x6F,0x0A00005D,"set_localScale one")
 tok(c,0x0088,0x7B,0x040032D6,"layer owner")
 tok(c,0x008D,0x72,0x7004ACDA,"UI_Dialog")
 tok(c,0x0092,0x28,0x0A000202,"NameToLayer")
 tok(c,0x0097,0x6F,0x0A0000D7,"set_layer")
 if c[0x009C]!=0x22 or struct.unpack_from("<f",c,0x009D)[0]!=130.0:raise E("raw scale 130")
 tok(c,0x00A3,0x7B,0x040032D6,"final scale owner")
 tok(c,0x00A8,0x6F,0x0A000050,"get_transform final scale")
 if c[0x00AD:0x00B0]!=bytes([0x07,0x07,0x07]):raise E("scale triple")
 tok(c,0x00B0,0x73,0x0A000044,"Vector3 ctor")
 tok(c,0x00B5,0x6F,0x0A00005D,"set_localScale 130")
 tok(c,0x00BB,0x28,0x060050B2,"FACT-0065 GetInst")
 tok(c,0x00C0,0x6F,0x060050B5,"FACT-0066 CreateReferee")
 tok(c,0x00C5,0x7D,0x040032D7,"referee store")
 if c[0x00CA]!=0x2A:raise E("ret")
 print("PROVE_CREATE_REFEREE_DISP_AWAKE: PASS")
if __name__=="__main__":main()
