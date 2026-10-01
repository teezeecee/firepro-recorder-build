#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={"Lookup":(0x00308040,104,"edf4f6904d007e70cf4d2cec22ab4c31f61d4898d18fd3107d886d2239a5a964"),"Update":(0x00307E94,415,"5d41c826c5bc4929960746b1b03abdd389b4911c89ec01a48fda0eba6e6c9e4a")}
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,"rb") as f:
  for x in iter(lambda:f.read(1<<20),b""):h.update(x)
 return h.hexdigest()
def secs(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0];n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def code(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3==2:h=1;n=b>>2
 else:fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def br(c,o,t,l):
 if c[o]!=0x3F or o+5+struct.unpack_from("<i",c,o+1)[0]!=t:raise E(l)
def verify(path):
 if sh(path)!=DLL_SHA:raise E("dll")
 pe=Path(path).read_bytes();ss=secs(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E(n+" body")
  cs[n]=c
 c=cs["Lookup"]
 tok(c,0x0001,0x7B,0x040062B1,"CurrentAnmIdx #1");br(c,0x0007,0x0024,"negative CurrentAnmIdx")
 tok(c,0x000D,0x7B,0x040062B1,"CurrentAnmIdx #2");tok(c,0x0013,0x7B,0x040062B0,"CurrentSkill")
 tok(c,0x0018,0x7B,0x04007C7A,"anmData length")
 if c[0x001D:0x001F]!=bytes([0x8E,0x69]):raise E("anmData length conversion")
 br(c,0x001F,0x0026,"CurrentAnmIdx upper bound")
 if c[0x0024:0x0026]!=bytes([0x14,0x2A]):raise E("animation null return")
 tok(c,0x0027,0x7B,0x040062B0,"CurrentSkill select");tok(c,0x002C,0x7B,0x04007C7A,"anmData select")
 tok(c,0x0032,0x7B,0x040062B1,"CurrentAnmIdx select")
 if c[0x0037:0x0039]!=bytes([0x9A,0x0A]):raise E("animation element local")
 tok(c,0x003A,0x7B,0x040062B3,"currentFormIdx #1");br(c,0x0040,0x0058,"negative currentFormIdx")
 tok(c,0x0046,0x7B,0x040062B3,"currentFormIdx #2");tok(c,0x004C,0x7B,0x04007C9F,"formDispList length")
 if c[0x0051:0x0053]!=bytes([0x8E,0x69]):raise E("formDispList length conversion")
 br(c,0x0053,0x005A,"currentFormIdx upper bound")
 if c[0x0058:0x005A]!=bytes([0x14,0x2A]):raise E("form null return")
 tok(c,0x005B,0x7B,0x04007C9F,"formDispList select");tok(c,0x0061,0x7B,0x040062B3,"currentFormIdx select")
 if c[0x0066:0x0068]!=bytes([0x9A,0x2A]):raise E("final element return")
 tok(cs["Update"],0x00DF,0x28,0x06005098,"FACT-0070 call #1");tok(cs["Update"],0x0109,0x28,0x06005098,"FACT-0070 call #2")
 return {"dll_sha256":DLL_SHA,"method":{"code_size":len(c),"code_sha256":M["Lookup"][2]},"fact_0070_calls":["0x00DF","0x0109"]}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_REFEREE_FORM_DISP_LOOKUP: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_REFEREE_FORM_DISP_LOOKUP: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
