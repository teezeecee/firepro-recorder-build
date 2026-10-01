#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6";RVA=0x002B0AE4;SIZE=95;SHA="20b2b0b4629e94a1522ac997f16d94062fd0e3ad779184615939a1ee3a794aae"
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,"rb") as f:
  for x in iter(lambda:f.read(1<<20),b""):h.update(x)
 return h.hexdigest()
def code(pe,rva):
 q=struct.unpack_from("<I",pe,0x3c)[0];n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8)
  if va<=rva<va+max(vs,rs):o=rp+rva-va;break
 b=pe[o];h=1 if b&3==2 else (struct.unpack_from("<H",pe,o)[0]>>12)*4;n=b>>2 if b&3==2 else struct.unpack_from("<I",pe,o+4)[0]
 return pe[o+h:o+h+n]
def tok(c,o,op,t):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(hex(o))
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 if sh(x.dll)!=DLL_SHA:raise E("dll")
 c=code(Path(x.dll).read_bytes(),RVA)
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=SHA:raise E("body")
 tok(c,0,0x7E,0x0400576C);tok(c,6,0x28,0x0A00000F);tok(c,0x10,0x7E,0x0400576C);tok(c,0x15,0x7B,0x04005752)
 tok(c,0x1F,0x7E,0x0400591E);tok(c,0x24,0x6F,0x06004A7D);tok(c,0x2E,0x7E,0x0400576C);tok(c,0x33,0x7B,0x04005738)
 if c[0x38:0x3B]!=bytes([0x1F,0x14,0x5E]):raise E("mod20")
 tok(c,0x41,0x7E,0x040086E4);tok(c,0x47,0x28,0x0A00000F);tok(c,0x51,0x7E,0x040086E4)
 if c[0x56:0x59]!=bytes([0x02,0x03,0x04]):raise E("forward")
 tok(c,0x59,0x6F,0x06005277)
 print("PROVE_PLAY_MATCH_SE: PASS")
if __name__=="__main__":main()
