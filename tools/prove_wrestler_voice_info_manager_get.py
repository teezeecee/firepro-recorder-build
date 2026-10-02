#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x0006F15C
SIZE=79
CODE_SHA="28ecb121c6b122a6a493c0e865d1b061d3679204933aad2909bd7759801e48ea"
EH_HEX="0110000002000c00313d000e00000000"
EH_SHA="047cd8520a6ef4751de3efd2feb22a33873fdd1bdf86a56aa084a7da14f3af68"
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
 if b&3==2:return {"offset":o,"flags":2,"header":1,"max_stack":8,"local_sig":0,"code":pe[o+1:o+1+(b>>2)]}
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return {"offset":o,"flags":fs&0x0FFF,"header":h,"max_stack":struct.unpack_from("<H",pe,o+2)[0],"local_sig":struct.unpack_from("<I",pe,o+8)[0],"code":pe[o+h:o+h+n]}
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,op,target,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=target:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);m=method(pe,ss,RVA);c=m["code"];p=method(pe,ss,FACT0178_RVA)["code"]
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if m["flags"]!=0x001B or m["header"]!=12 or m["max_stack"]!=2 or m["local_sig"]!=0x1100034C:raise E("header")
 if hashlib.sha256(p).hexdigest()!=FACT0178_SHA:raise E("FACT-0178 body")
 if c[0]!=0x02:raise E("this")
 tok(c,0x0001,0x7B,0x040011E7,"wrestlerVoiceInfo field")
 tok(c,0x0006,0x6F,0x0A000787,"GetEnumerator")
 if c[0x000B]!=0x0B:raise E("stloc.1")
 br(c,0x000C,0x38,0x002C,"initial loop branch")
 if c[0x0011:0x0013]!=bytes([0x12,0x01]):raise E("enumerator address")
 tok(c,0x0013,0x28,0x0A000788,"get_Current")
 if c[0x0018:0x001A]!=bytes([0x0A,0x06]):raise E("current local")
 tok(c,0x001A,0x7B,0x040011DD,"type field")
 if c[0x001F]!=0x03:raise E("type argument")
 br(c,0x0020,0x40,0x002C,"type mismatch")
 if c[0x0025:0x0027]!=bytes([0x06,0x0C]):raise E("match store")
 br(c,0x0027,0xDD,0x004D,"match leave")
 if c[0x002C:0x002E]!=bytes([0x12,0x01]):raise E("enumerator address move")
 tok(c,0x002E,0x28,0x0A000789,"MoveNext")
 br(c,0x0033,0x3A,0x0011,"loop back")
 br(c,0x0038,0xDD,0x004B,"no-match leave")
 if c[0x003D:0x003F]!=bytes([0x12,0x01]):raise E("finally enumerator address")
 if c[0x003F:0x0041]!=bytes([0xFE,0x16]) or struct.unpack_from("<I",c,0x0041)[0]!=0x1B00010D:raise E("constrained enumerator")
 tok(c,0x0045,0x6F,0x0A00011F,"IDisposable.Dispose")
 if c[0x004A]!=0xDC:raise E("endfinally")
 if c[0x004B:0x004D]!=bytes([0x14,0x2A]):raise E("null return")
 if c[0x004D:0x004F]!=bytes([0x08,0x2A]):raise E("match return")
 end=(m["offset"]+m["header"]+len(c)+3)&~3
 eh=pe[end:end+16]
 if eh.hex()!=EH_HEX or hashlib.sha256(eh).hexdigest()!=EH_SHA:raise E("EH")
 for off in (0x013B,0x0464):
  if p[off]!=0x28 or struct.unpack_from("<I",p,off+1)[0]!=0x060011E7:raise E("FACT-0178 caller "+hex(off))
 print("PROVE_WRESTLER_VOICE_INFO_MANAGER_GET: PASS")
if __name__=="__main__":main()
