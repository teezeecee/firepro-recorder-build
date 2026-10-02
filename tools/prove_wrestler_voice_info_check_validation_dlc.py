#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x0006F080
SIZE=65
CODE_SHA="d6297fd525cdb31260595c4e0a1705c380f1201b6392c91b59d5589ecba0ccc4"
ISDLC_RVA=0x0006F0D0
ISDLC_SHA="2acb70b4c1485d922c4cb298c85655aced949090d9446da112ff0935df31c9f6"
SAVE_RVA=0x00316C6C
SAVE_SHA="d353bf6e7046434074ecca1c5a62cb8cd9ec636500659fc5b9083f2943c7d841"
FACT0178_RVA=0x00323E44
FACT0178_SHA="4a24846ef6fe5b1e729ee484cbdac32e5744eb183a9b23562fd7d865a8410f94"
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\0\0":raise E("not PE")
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
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe)
 m=method(pe,ss,RVA);c=m["code"]
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if m["flags"]!=0x0013 or m["header"]!=12 or m["max_stack"]!=2 or m["local_sig"]!=0x110002DE:raise E("header")
 if hashlib.sha256(method(pe,ss,ISDLC_RVA)["code"]).hexdigest()!=ISDLC_SHA:raise E("FACT-0179 body")
 if hashlib.sha256(method(pe,ss,SAVE_RVA)["code"]).hexdigest()!=SAVE_SHA:raise E("FACT-0119 body")
 p=method(pe,ss,FACT0178_RVA)["code"]
 if hashlib.sha256(p).hexdigest()!=FACT0178_SHA:raise E("FACT-0178 body")
 if c[0]!=0x02:raise E("this")
 tok(c,0x0001,0x28,0x060011E4,"FACT-0179 IsDLC")
 br(c,0x0006,0x3A,0x000D,"IsDLC true")
 if c[0x000B:0x000D]!=bytes([0x17,0x2A]):raise E("IsDLC false true-return")
 if c[0x000D:0x000F]!=bytes([0x16,0x0A]):raise E("local init")
 br(c,0x000F,0x38,0x0037,"loop test")
 if c[0x0014]!=0x02:raise E("this dlc")
 tok(c,0x0015,0x7B,0x040011DE,"dlc")
 if c[0x001A:0x001C]!=bytes([0x06,0x91]):raise E("dlc index")
 br(c,0x001C,0x39,0x0033,"dlc false")
 tok(c,0x0021,0x7E,0x040064EC,"SaveData.inst")
 if c[0x0026]!=0x06:raise E("DLCEnum local")
 tok(c,0x0027,0x6F,0x060051C9,"FACT-0119 IsDLCInstalled")
 br(c,0x002C,0x39,0x0033,"not installed")
 if c[0x0031:0x0033]!=bytes([0x17,0x2A]):raise E("installed true-return")
 if c[0x0033:0x0037]!=bytes([0x06,0x17,0x58,0x0A]):raise E("increment")
 if c[0x0037:0x003A]!=bytes([0x06,0x1F,0x0D]):raise E("raw13 bound")
 br(c,0x003A,0x3F,0x0014,"loop back")
 if c[0x003F:0x0041]!=bytes([0x16,0x2A]):raise E("false return")
 if p[0x01CF]!=0x28 or struct.unpack_from("<I",p,0x01D0)[0]!=0x060011E3:raise E("FACT-0178 caller")
 print("PROVE_WRESTLER_VOICE_INFO_CHECK_VALIDATION_DLC: PASS")
if __name__=="__main__":main()
