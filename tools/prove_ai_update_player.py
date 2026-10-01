#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
"UpdatePlayer":(0x002F4308,836,"da9fecfe8759295bfca091cebf9c3d58f54802008907127c9658db73eadfbf15"),
"Entrance":(0x002AA570,822,"574be9a2193d91b436a4a241a5dee31bd03c08b32ca09d28dbdf4afd60990cde"),
"Match":(0x002AA8B4,1152,"b6841694e03be5ca4c73e966a13802de9fe7339ab63540ffdf5edaee96ea9dfe")}
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
def verify(path):
 got=sha_path(path)
 if got!=DLL_SHA:raise ProofError("DLL SHA "+got)
 pe=Path(path).read_bytes();ss=sections(pe);cs={}
 for n,(r,s,h) in M.items():
  c=code(pe,ss,r)
  if len(c)!=s or hashlib.sha256(c).hexdigest()!=h:raise ProofError(n+" body")
  cs[n]=c
 c=cs["UpdatePlayer"]
 tok(c,0x0006,0x7D,0x04005FB6,"PlPosOfs")
 tok(c,0x000D,0x7B,0x04005FB7,"State")
 tok(c,0x0012,0x7D,0x04005FB8,"PrevState")
 tok(c,0x0018,0x7B,0x04006043,"hasRight")
 tok(c,0x0023,0x7B,0x0400603F,"hasRightFrm")
 tok(c,0x0034,0x6F,0x06004FFE,"CalcTouchTime")
 tok(c,0x0054,0x28,0x06004F76,"MakeKeyData")
 tok(c,0x005A,0x28,0x06004F21,"ProcessRecover")
 tok(c,0x0060,0x28,0x06004F22,"CheckFallToOutOfRing")
 tok(c,0x0066,0x28,0x06004EC8,"TransitStateAfterAnm")
 if c[0x0071:0x0073]!=bytes([0x1F,0x40]):raise ProofError("Status2 mask64")
 tok(c,0x007C,0x28,0x06004EAE,"ChangeState10")
 tok(c,0x0099,0x6F,0x06004E6F,"ReqBasicAnm status2")
 tok(c,0x00AE,0x28,0x06004F23,"MultiGrappleCheck")
 tok(c,0x00B4,0x28,0x06004F28,"Process_Down")
 tok(c,0x00BA,0x28,0x06004F31,"GatherInformation")
 tok(c,0x00C0,0x28,0x06004F30,"DecideTargetEnemy")
 tok(c,0x00E3,0x28,0x06004F2F,"SetPlayerDirToTarget")
 tok(c,0x00EE,0x28,0x06004F2E,"SetPlayerDir_Walking")
 for off,t in [(0x00F4,0x06004F35),(0x00FA,0x06004F36),(0x0100,0x06004F3D),(0x0106,0x06004F51),(0x010C,0x06004F52),(0x0112,0x06004F62),(0x0118,0x06004F66),(0x011E,0x06004F67),(0x0124,0x06004F71)]:
  tok(c,off,0x28,t,"ordered helper "+hex(off))
 br(c,0x0130,0x3D,0x01DB,"State > 4")
 tok(c,0x0137,0x7D,0x04006051,"disable down time clear")
 tok(c,0x014D,0x28,0x06004ECE,"SetBP zero")
 if c[0x0158]!=0x20 or struct.unpack_from("<i",c,0x0159)[0]!=256:raise ProofError("pad mask256")
 tok(c,0x0165,0x28,0x06004EAE,"ChangeState4")
 if c[0x0181]!=0x20 or struct.unpack_from("<i",c,0x0182)[0]!=496:raise ProofError("anm base496")
 tok(c,0x0195,0x6F,0x06004E6F,"ReqBasicAnm pad")
 tok(c,0x01AE,0x28,0x06004F07,"ProcessWalk")
 tok(c,0x01B9,0x28,0x06004F08,"WrestlerStand")
 tok(c,0x01D6,0x7D,0x0400605D,"isPossibleToGrapple")
 tok(c,0x01DC,0x28,0x06004F78,"GrappleCheck")
 tok(c,0x01E7,0x6F,0x06004E7E,"UpdateAnimation")
 if c[0x01F2]!=0x1E:raise ProofError("Zone raw8")
 br(c,0x01F3,0x40,0x029A,"Zone8 gate")
 tok(c,0x021F,0x28,0x06004A90,"CalcLinearFunctinParam")
 tok(c,0x023C,0x28,0x06004A91,"IsIntersect #1")
 tok(c,0x026C,0x28,0x06004A91,"IsIntersect #2")
 tok(c,0x0280,0x28,0x06004A93,"NearestPoint")
 if c[0x028F]!=0x22 or struct.unpack_from("<f",c,0x0290)[0]!=1.5:raise ProofError("z multiplier1.5")
 tok(c,0x02BF,0x28,0x06004F7F,"VibratePlayer")
 tok(c,0x0331,0x28,0x06004F74,"Start_ForceControl")
 tok(c,0x033E,0x28,0x06004F80,"ProcessBloodstain")
 if c[0x0343]!=0x2A:raise ProofError("ret")
 tok(cs["Entrance"],0x00CC,0x6F,0x06004F87,"Entrance caller")
 tok(cs["Match"],0x026F,0x6F,0x06004F87,"Match caller")
 return {"dll_sha256":got,"method":{"code_size":len(c),"code_sha256":M["UpdatePlayer"][2]}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_AI_UPDATE_PLAYER: PASS");return 0
 except (OSError,ValueError,ProofError) as e:
  print("PROVE_AI_UPDATE_PLAYER: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
