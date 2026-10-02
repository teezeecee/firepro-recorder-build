#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x0006F210; SIZE=96; CODE_SHA="12e664e407030c367665e38466387ae43d43134ae0c1e183c918aa89ee3e34ba"
EH_HEX="011000000000410015560008c2000001"; EH_SHA="94de01fa84600402f67fcb97192f92de809361ea7d8c69299fba78f3037503ac"
CALLER_RVA=0x0006F28C; CALLER_SHA="51600ca58d83133003e36ec3afd834efa865af3cd33749c16af5e5f0e68d9a1d"
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]; n=struct.unpack_from("<H",pe,q+6)[0]; z=struct.unpack_from("<H",pe,q+20)[0]; s=q+24+z; out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def method(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3==2:return {"offset":o,"header":1,"flags":2,"max_stack":8,"local_sig":0,"code":pe[o+1:o+1+(b>>2)]}
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return {"offset":o,"header":h,"flags":fs&0x0FFF,"max_stack":struct.unpack_from("<H",pe,o+2)[0],"local_sig":struct.unpack_from("<I",pe,o+8)[0],"code":pe[o+h:o+h+n]}
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,target,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=target:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);m=method(pe,ss,RVA);c=m["code"];p=method(pe,ss,CALLER_RVA)["code"]
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if m["flags"]!=0x001B or m["header"]!=12 or m["max_stack"]!=3 or m["local_sig"]!=0x11000002:raise E("header")
 if hashlib.sha256(p).hexdigest()!=CALLER_SHA:raise E("caller")
 if c[0]!=0x02:raise E("s")
 tok(c,0x0001,0x28,0x0A000015,"IsNullOrEmpty")
 br(c,0x0006,0x39,0x000D,"not null/empty")
 if c[0x000B:0x000D]!=bytes([0x16,0x2A]):raise E("empty return 0")
 if c[0x000D:0x0010]!=bytes([0x02,0x16,0x17]):raise E("prefix args")
 tok(c,0x0010,0x6F,0x0A000018,"Substring prefix")
 tok(c,0x0015,0x72,0x70007CF6,"N")
 tok(c,0x001A,0x6F,0x0A00030C,"Equals N")
 br(c,0x001F,0x39,0x0026,"not N")
 if c[0x0024:0x0026]!=bytes([0x15,0x2A]):raise E("N return -1")
 if c[0x0026:0x0029]!=bytes([0x02,0x03,0x17]):raise E("space args")
 tok(c,0x0029,0x6F,0x0A000018,"Substring dgt")
 tok(c,0x002E,0x72,0x7000046F,"space")
 tok(c,0x0033,0x6F,0x0A00030C,"Equals space")
 br(c,0x0038,0x3A,0x003F,"space true")
 if c[0x003D:0x003F]!=bytes([0x16,0x2A]):raise E("space return 0")
 if c[0x003F:0x0044]!=bytes([0x16,0x0A,0x02,0x16,0x03]):raise E("parse setup")
 tok(c,0x0044,0x6F,0x0A000018,"Substring parse")
 tok(c,0x0049,0x28,0x0A0006DE,"Int32.Parse")
 if c[0x004E:0x0051]!=bytes([0x0A,0x06,0x0B]):raise E("parse locals")
 br(c,0x0051,0xDD,0x005E,"parse leave")
 if c[0x0056:0x0059]!=bytes([0x26,0x16,0x0B]):raise E("catch zero")
 br(c,0x0059,0xDD,0x005E,"catch leave")
 if c[0x005E:0x0060]!=bytes([0x07,0x2A]):raise E("ret local1")
 end=(m["offset"]+m["header"]+len(c)+3)&~3
 eh=pe[end:end+16]
 if eh.hex()!=EH_HEX or hashlib.sha256(eh).hexdigest()!=EH_SHA:raise E("EH")
 tok(p,0x0243,0x28,0x060011E9,"Parse caller")
 print("PROVE_WRESTLER_VOICE_INFO_MANAGER_PARSE_PRM_INT: PASS")
if __name__=="__main__":main()
