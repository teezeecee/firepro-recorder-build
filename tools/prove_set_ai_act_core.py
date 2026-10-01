#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
"SetAIAct":(0x002F5F54,102,"58725b1757df7dd4bb511637f82b17f0ec95140b0a213f420cf88b318d04d065"),
"Counter":(0x002F60EC,8,"cff3981d35f0878efae84ea0b7f25c9c403437bc3e9413041ba509fbb361fa1a"),
"Try":(0x002FD0B0,606,"f1818f56bcb7b04635a7c1b9cb814f1e20480577a20287b2d8ee4d438e109191"),
"DownAtk":(0x002F604F,30,"fb38a89d3118cf815885af4d76af0a9a8a2c4744c5d9352a6f58cca215640589"),
"RunUpStand":(0x002F6023,21,"94e61e33b42bff7c649e3d687172f74aa95a6083618dc9fa82e1e3c1e6fdd431"),
"RunUpDown":(0x002F6039,21,"fc342bf4ac6481bbab368979011af8b3a878a91e00528b03d11c7f8021ce0b81"),
"CornerDive":(0x002F6000,34,"76067b8223899419015727846653c64dcf88f7aba379d6621dac196ef2bcb802"),
"PriRunAtk":(0x002F60C8,17,"09d1a53cf821b1ed7cf1f66622e3b14e1cfd5d8d86b4de366aaba3387e8ad46f"),
"GoGrapple":(0x002F5FC6,23,"978e82da32179445718786287df804ca334ac6f1889e726bec8774e5a13ccf12"),
"GoBackGrapple":(0x002F5FEF,16,"78b1f889deb727931a2cf293d6125dbba940b2f77b8d67e400fa8c99cdf195ac")}
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
def br(c,o,op,t,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=t:raise ProofError(l)
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
 c=cs["SetAIAct"]
 tok(c,0x0001,0x7B,0x0400614B,"aiAct load")
 br(c,0x0007,0x40,0x0014,"same/different action split")
 tok(c,0x000E,0x28,0x06004FAC,"same action SetAIActCounter")
 tok(c,0x0016,0x7D,0x0400614B,"aiAct store")
 tok(c,0x001D,0x28,0x06004FAC,"changed action SetAIActCounter")
 tok(c,0x0024,0x7D,0x0400614D,"aiActStep zero")
 tok(c,0x002A,0x7B,0x0400614B,"aiAct raw20 load")
 if c[0x002F:0x0031]!=bytes([0x1F,0x14]):raise ProofError("raw20")
 br(c,0x0031,0x40,0x0044,"raw20 increment gate")
 tok(c,0x0038,0x7B,0x0400616B,"drag counter load")
 tok(c,0x003F,0x7D,0x0400616B,"drag counter increment store")
 tok(c,0x0045,0x7B,0x0400614B,"aiAct raw20 reset gate")
 if c[0x004A:0x004C]!=bytes([0x1F,0x14]):raise ProofError("raw20 reset compare")
 br(c,0x004C,0x3B,0x0065,"raw20 keep")
 tok(c,0x0052,0x7B,0x0400614B,"aiAct raw19 load")
 if c[0x0057:0x0059]!=bytes([0x1F,0x13]):raise ProofError("raw19")
 br(c,0x0059,0x3B,0x0065,"raw19 keep")
 tok(c,0x0060,0x7D,0x0400616B,"drag counter reset")
 if c[0x0065]!=0x2A:raise ProofError("SetAIAct ret")
 c=cs["Counter"]
 if c[0:2]!=bytes([0x02,0x03]):raise ProofError("Counter args")
 tok(c,0x0002,0x7D,0x0400614C,"aiActDuration store")
 if c[0x0007]!=0x2A:raise ProofError("Counter ret")
 # caller family
 for n,off in [("DownAtk",0x4),("RunUpStand",0x8),("RunUpDown",0x8),("CornerDive",0x7),("PriRunAtk",0x4),("GoGrapple",0x3),("GoBackGrapple",0x3)]:
  tok(cs[n],off,0x28,0x06004F9D,n+" SetAIAct caller")
 tr=cs["Try"]
 tok(tr,0x020C,0x28,0x06004F9D,"Try raw-act21 SetAIAct")
 return {"dll_sha256":got,"methods":{"SetAIAct":{"code_size":len(cs["SetAIAct"]),"code_sha256":M["SetAIAct"][2]},"SetAIActCounter":{"code_size":len(cs["Counter"]),"code_sha256":M["Counter"][2]}}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_SET_AI_ACT_CORE: PASS");return 0
 except (OSError,ValueError,ProofError) as e:
  print("PROVE_SET_AI_ACT_CORE: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
