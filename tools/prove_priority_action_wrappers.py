#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
"DownAtk":(0x002F604F,30,"fb38a89d3118cf815885af4d76af0a9a8a2c4744c5d9352a6f58cca215640589"),
"RunUpStand":(0x002F6023,21,"94e61e33b42bff7c649e3d687172f74aa95a6083618dc9fa82e1e3c1e6fdd431"),
"RunUpDown":(0x002F6039,21,"fc342bf4ac6481bbab368979011af8b3a878a91e00528b03d11c7f8021ce0b81"),
"CornerDive":(0x002F6000,34,"76067b8223899419015727846653c64dcf88f7aba379d6621dac196ef2bcb802"),
"PriRunAtk":(0x002F60C8,17,"09d1a53cf821b1ed7cf1f66622e3b14e1cfd5d8d86b4de366aaba3387e8ad46f"),
"GoGrapple":(0x002F5FC6,23,"978e82da32179445718786287df804ca334ac6f1889e726bec8774e5a13ccf12"),
"GoBackGrapple":(0x002F5FEF,16,"78b1f889deb727931a2cf293d6125dbba940b2f77b8d67e400fa8c99cdf195ac"),
"Try":(0x002FD0B0,606,"f1818f56bcb7b04635a7c1b9cb814f1e20480577a20287b2d8ee4d438e109191")}
class ProofError(RuntimeError):pass
def sha_path(p):
 h=hashlib.sha256()
 with open(p,"rb") as f:
  for x in iter(lambda:f.read(1024*1024),b""):h.update(x)
 return h.hexdigest()
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\0\0":raise ProofError("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0];osz=struct.unpack_from("<H",pe,q+20)[0];s=q+24+osz;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def code(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise ProofError("RVA unmapped")
 b=pe[o]
 if b&3==2:h=1;n=b>>2
 else:fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise ProofError(l)
def i4(c,o,v,l):
 if c[o]!=0x20 or struct.unpack_from("<i",c,o+1)[0]!=v:raise ProofError(l)
def verify(path):
 got=sha_path(path)
 if got!=DLL_SHA:raise ProofError("DLL SHA "+got)
 pe=Path(path).read_bytes();ss=sections(pe);cs={}
 for n,(r,s,h) in M.items():
  c=code(pe,ss,r)
  if len(c)!=s or hashlib.sha256(c).hexdigest()!=h:raise ProofError(n+" body")
  cs[n]=c
 c=cs["DownAtk"]; 
 if c[0:3]!=bytes([0x02,0x1F,0x13]) or c[3]!=0x04:raise ProofError("Down args")
 tok(c,4,0x28,0x06004F9D,"Down SetAIAct");tok(c,0x0B,0x7D,0x0400614E,"Down aiActPrm");tok(c,0x18,0x7D,0x0400614D,"Down aiActStep")
 for n,raw in [("RunUpStand",9),("RunUpDown",10)]:
  c=cs[n]
  if c[0]!=0x02 or c[1:3]!=bytes([0x1F,raw]):raise ProofError(n+" action")
  i4(c,3,512,n+" time");tok(c,8,0x28,0x06004F9D,n+" SetAIAct");tok(c,0x0F,0x7D,0x0400614F,n+" destCorner")
 c=cs["CornerDive"]
 if c[0:2]!=bytes([0x02,0x1B]):raise ProofError("Corner action")
 i4(c,2,256,"Corner time");tok(c,7,0x28,0x06004F9D,"Corner SetAIAct");tok(c,0x0E,0x7D,0x0400614F,"Corner dest");tok(c,0x15,0x7D,0x04006160,"Corner next");tok(c,0x1C,0x7D,0x0400616C,"Corner perf")
 c=cs["PriRunAtk"]
 if c[0:3]!=bytes([0x02,0x1F,0x10]) or c[3]!=0x04:raise ProofError("RunAtk args")
 tok(c,4,0x28,0x06004F9D,"RunAtk SetAIAct");tok(c,0x0B,0x7D,0x0400614E,"RunAtk prm")
 c=cs["GoGrapple"]
 if c[0:2]!=bytes([0x02,0x17]) or c[2]!=0x05:raise ProofError("Grapple args")
 tok(c,3,0x28,0x06004F9D,"Grapple SetAIAct");tok(c,0x0A,0x7D,0x04006160,"Grapple next");tok(c,0x11,0x7D,0x0400614E,"Grapple prm")
 c=cs["GoBackGrapple"]
 if c[0:2]!=bytes([0x02,0x19]) or c[2]!=0x04:raise ProofError("Back args")
 tok(c,3,0x28,0x06004F9D,"Back SetAIAct");tok(c,0x0A,0x7D,0x04006160,"Back next")
 tr=cs["Try"]
 for off,t in [(0x00BF,0x06004FA4),(0x00E0,0x06004FA4),(0x012F,0x06004FA2),(0x013C,0x06004FA3),(0x01AE,0x06004FA1),(0x01F3,0x06004FAA),(0x022C,0x06004F9E),(0x024B,0x06004FA0)]:tok(tr,off,0x28,t,"Try caller")
 return {"dll_sha256":got,"methods":{n:{"code_size":len(cs[n]),"code_sha256":M[n][2]} for n in M if n!="Try"}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_PRIORITY_ACTION_WRAPPERS: PASS");return 0
 except (OSError,ValueError,ProofError) as e:
  print("PROVE_PRIORITY_ACTION_WRAPPERS: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
