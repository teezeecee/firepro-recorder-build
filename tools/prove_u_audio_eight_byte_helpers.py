#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
EXPECTED={
0x060052D4:(0x0032574F,"4f5732000000810045630a005c480000553d","a7ef316dd7fe39b4eaeda4d2e2e77ba05490faf1bfb2ef51a007d2e76bcb182f",bytes.fromhex("02167dea8700042a")),
0x060052E2:(0x0032588D,"8d5832000000e601f1630a00744801005a3d","58193cf76ec4ea1593941160a6d4a33e52eabe8941423467e4856a4a1d58a521",bytes.fromhex("020328d75200062a")),
0x060052E5:(0x003259BD,"bd5932000000e60103640a00794800005c3d","79994be6176e273a75d4c1d2971a5a3e1dbd12aa3428791124fd0d7429e79caf",bytes.fromhex("02037de68700042a"))
}
class E(RuntimeError):pass
def ix(rows,t):return 4 if rows.get(t,0)>=65536 else 2
def cix(rows,tables,bits):return 4 if max(rows.get(t,0) for t in tables)>=(1<<(16-bits)) else 2
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 q=struct.unpack_from("<I",pe,0x3c)[0];n=struct.unpack_from("<H",pe,q+6)[0];opt=struct.unpack_from("<H",pe,q+20)[0]
 oo=q+24;magic=struct.unpack_from("<H",pe,oo)[0];dd=oo+(112 if magic==0x20b else 96);secs=[];so=oo+opt
 for i in range(n):
  o=so+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);secs.append((va,max(vs,rs),rp))
 def ro(rva):
  for va,sz,rp in secs:
   if va<=rva<va+sz:return rp+rva-va
  raise E("rva")
 cli=ro(struct.unpack_from("<I",pe,dd+14*8)[0]);mo=ro(struct.unpack_from("<I",pe,cli+8)[0]);vl=struct.unpack_from("<I",pe,mo+12)[0];p=(mo+16+vl+3)&~3
 _,ns=struct.unpack_from("<HH",pe,p);p+=4;streams={}
 for _ in range(ns):
  off,size=struct.unpack_from("<II",pe,p);p+=8;e=pe.index(b"\0",p);name=pe[p:e].decode();p=(e+4)&~3;streams[name]=(mo+off,size)
 t=streams["#~"][0];p=t+4;_,_,hs,_=struct.unpack_from("<BBBB",pe,p);p+=4;valid,_=struct.unpack_from("<QQ",pe,p);p+=16;rows={}
 for tid in range(64):
  if (valid>>tid)&1:rows[tid]=struct.unpack_from("<I",pe,p)[0];p+=4
 ss=4 if hs&1 else 2;gs=4 if hs&2 else 2;bs=4 if hs&4 else 2
 sizes={0:2+ss+gs*3,1:cix(rows,[0,26,35,1],2)+ss*2,2:4+ss*2+cix(rows,[2,1,27],2)+ix(rows,4)+ix(rows,6),3:ix(rows,4),4:2+ss+bs,5:ix(rows,6),6:4+2+2+ss+bs+ix(rows,8)}
 off=p
 for tid in range(6):
  if tid in rows:off+=sizes[tid]*rows[tid]
 if sizes[6]!=18:raise E("MethodDef size")
 for tok,(rva,rowhex,sha,expected_body) in EXPECTED.items():
  rid=tok&0xffffff;row=pe[off+(rid-1)*18:off+rid*18]
  if row.hex()!=rowhex or struct.unpack_from("<I",row,0)[0]!=rva:raise E("row "+hex(tok))
  o=ro(rva);b=pe[o]
  if b&3!=2:raise E("tiny "+hex(tok))
  code=pe[o+1:o+1+(b>>2)]
  if code!=expected_body or hashlib.sha256(code).hexdigest()!=sha:raise E("body "+hex(tok))
 for tok in EXPECTED:
  tkn=struct.pack("<I",tok)
  for pre in [b"\x28",b"\x6f",b"\xfe\x06",b"\xfe\x07",b"\x73"]:
   if pe.find(pre+tkn)>=0:raise E("inbound direct ref "+hex(tok))
 print("PROVE_U_AUDIO_EIGHT_BYTE_HELPERS: PASS")
if __name__=="__main__":main()
