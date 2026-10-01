#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path

DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
EXPECTED={
0x060052CA:(0x0032567D,"7d5632000000860084620a005c480000523d",13,"62a68c749da17a7c536b2ef155fd300637ffd8bd582da8979c28fdd87bf83d1c"),
0x060052CB:(0x0032568B,"8b5632000000e60998620a007ce50200523d",7,"f0eb7b6d2625782d43a08476d93acb464e82bc45c00d660925f2176d82bc8c4b"),
0x060052D0:(0x003256D4,"d456320000008608d2620a0087e50200543d",86,"5524703abb8912537cca2bf60cf25fdcde63df8bcc2ea51a0db76d5dc8e858c4"),
0x060052D6:(0x00325776,"765732000000e609628a07006e480100553d",41,"49f83f2ff33655f9bece0288383a552b4e5a31346d16547fcfd1028ecfdc7b0b"),
0x060052DC:(0x00325827,"275832000000e609048a070070550000573d",13,"e3434a65b5c1a9c14959c686924c525e57f68f1cf3fbde7c02a25819e891480c"),
0x060052E0:(0x0032587C,"7c583200000086009c630a0070550000593d",8,"bf7afe343990f70067b2d0a5f418a180d7f1abee664827c4b4e6e18940403ca7"),
0x060052E4:(0x00325970,"705932000000e601f28a0700794800005b3d",65,"b5b74da6ab2322d1895635e2add04dd52f9ee9ca4a3846825a9b6fe4631e3ef4"),
0x060052E6:(0x003259C8,"c8593200000081000b640a005c4800005d3d",141,"3ff6f18fdb7ed86c92f309f6496f6d7fc3a7cee75b55c9174345fac0efaeee4c"),
0x060052E7:(0x00325A80,"805a32000000e601ac5a0600a4e502005d3d",564,"25cfa99ab6e97f650b4e517fa419b12acb018df2aab2933a87b40953a7084a26"),
0x060052EE:(0x00325E6A,"6a5e32000000810024640a00d0e502005f3d",13,"124f59a872afec501c29839a33e627e58a6c5339d59456ad7f66f6b7323e237d")
}
class E(RuntimeError):pass
def ix(rows,t):return 4 if rows.get(t,0)>=65536 else 2
def cix(rows,tables,bits):return 4 if max(rows.get(t,0) for t in tables)>=(1<<(16-bits)) else 2
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll hash")
 q=struct.unpack_from("<I",pe,0x3c)[0]
 n=struct.unpack_from("<H",pe,q+6)[0]; opt=struct.unpack_from("<H",pe,q+20)[0]
 oo=q+24; magic=struct.unpack_from("<H",pe,oo)[0]; dd=oo+(112 if magic==0x20b else 96)
 secs=[]; so=oo+opt
 for i in range(n):
  o=so+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);secs.append((va,max(vs,rs),rp))
 def ro(rva):
  for va,sz,rp in secs:
   if va<=rva<va+sz:return rp+rva-va
  raise E("rva")
 cli=ro(struct.unpack_from("<I",pe,dd+14*8)[0])
 mo=ro(struct.unpack_from("<I",pe,cli+8)[0])
 vl=struct.unpack_from("<I",pe,mo+12)[0]; p=(mo+16+vl+3)&~3
 _,ns=struct.unpack_from("<HH",pe,p);p+=4
 streams={}
 for _ in range(ns):
  off,size=struct.unpack_from("<II",pe,p);p+=8;e=pe.index(b"\0",p);name=pe[p:e].decode();p=(e+4)&~3;streams[name]=(mo+off,size)
 t=streams["#~"][0];p=t+4;_,_,hs,_=struct.unpack_from("<BBBB",pe,p);p+=4;valid,_=struct.unpack_from("<QQ",pe,p);p+=16
 rows={}
 for tid in range(64):
  if (valid>>tid)&1:rows[tid]=struct.unpack_from("<I",pe,p)[0];p+=4
 ss=4 if hs&1 else 2; gs=4 if hs&2 else 2; bs=4 if hs&4 else 2
 sizes={
 0:2+ss+gs*3,
 1:cix(rows,[0,26,35,1],2)+ss*2,
 2:4+ss*2+cix(rows,[2,1,27],2)+ix(rows,4)+ix(rows,6),
 3:ix(rows,4),
 4:2+ss+bs,
 5:ix(rows,6),
 6:4+2+2+ss+bs+ix(rows,8)
 }
 off=p
 for tid in range(6):
  if tid in rows:off+=sizes[tid]*rows[tid]
 method_off=off; method_size=sizes[6]
 if method_size!=18:raise E("MethodDef row size")
 for token,(rva,row_hex,body_size,body_sha) in EXPECTED.items():
  rid=token&0xffffff; row=pe[method_off+(rid-1)*method_size:method_off+rid*method_size]
  if row.hex()!=row_hex:raise E("MethodDef row "+hex(token))
  if struct.unpack_from("<I",row,0)[0]!=rva:raise E("MethodDef RVA "+hex(token))
  o=ro(rva); b=pe[o]
  if b&3==2:h=1;size=b>>2
  else:
   fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;size=struct.unpack_from("<I",pe,o+4)[0]
  code=pe[o+h:o+h+size]
  if size!=body_size or hashlib.sha256(code).hexdigest()!=body_sha:raise E("body "+hex(token))
 print("PROVE_U_AUDIO_METHODDEF_RVA_AUDIT: PASS")
if __name__=="__main__":main()
