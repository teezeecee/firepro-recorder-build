#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={"Leaf":(0x0029018C,477,"ba5e6b908f65b9feecf9b3c43ab61fbb139abf93eea50f11ae66585a92efbc32"),"Caller":(0x0028FE43,50,"36b8ed39e946a670d66af8344565ee39ada17a831fb66a84935def5e66450dc0")}
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
def br(c,o,op,t,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=t:raise E(l)
def f32(c,o,v,l):
 if c[o]!=0x22 or struct.unpack_from("<f",c,o+1)[0]!=struct.unpack("<f",struct.pack("<f",v))[0]:raise E(l)
def verify(path):
 if sh(path)!=DLL_SHA:raise E("dll")
 pe=Path(path).read_bytes();ss=secs(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E(n+" body")
  cs[n]=c
 c=cs["Leaf"]
 tok(c,0x0000,0x28,0x06004907,"MatchMain.GetInst");tok(c,0x0007,0x7B,0x0400573B,"matchTime");tok(c,0x000C,0x7B,0x0400572F,"sec")
 if c[0x0011:0x0016]!=bytes([0x17,0x58,0x1F,0x14,0x5D]):raise E("(sec+1)%20")
 br(c,0x0016,0x3A,0x009D,"nonzero remainder skip refresh")
 tok(c,0x0028,0x28,0x0600505D,"PlayerMan.GetInst refresh");tok(c,0x002E,0x6F,0x06005065,"GetPlObj refresh")
 tok(c,0x0035,0x28,0x0A00002A,"player truth refresh");tok(c,0x0045,0x7B,0x04006057,"isSleep refresh");tok(c,0x0055,0x7B,0x04006043,"hasRight refresh")
 tok(c,0x0066,0x7B,0x04005FBF,"HP");f32(c,0x006B,2.0,"HP factor");tok(c,0x0072,0x7B,0x04005FC0,"SP");f32(c,0x0078,3.0,"divisor")
 if c[0x0084:0x0087]!=bytes([0x08,0x1E,0x3F]):raise E("refresh loop <8")
 tok(c,0x008C,0x7E,0x040054CE,"CheerHpTbl");tok(c,0x0092,0x28,0x0600495C,"MatchMisc.GetHealth")
 tok(c,0x0098,0x7D,0x040054CC,"CheerLevel_HP")
 tok(c,0x009F,0x7B,0x040054CB,"CheerLevel_Base");tok(c,0x00A5,0x7B,0x040054CC,"CheerLevel_HP read");tok(c,0x00AB,0x7D,0x040054CA,"CheerLevel_Total base")
 tok(c,0x00BB,0x28,0x0600505D,"PlayerMan.GetInst zone");tok(c,0x00C2,0x6F,0x06005065,"GetPlObj zone");tok(c,0x00CB,0x28,0x0A00002A,"player truth zone");tok(c,0x00DC,0x7B,0x04006057,"isSleep zone")
 for off in [0x00ED,0x00FA,0x0107,0x0114]:tok(c,off,0x7B,0x04005FEE,"Zone")
 if c[0x00F2:0x00F4]!=bytes([0x17,0x3B]):raise E("Zone1"); 
 if c[0x00FF:0x0101]!=bytes([0x19,0x3B]):raise E("Zone3")
 if c[0x010C:0x010E]!=bytes([0x1E,0x3B]):raise E("Zone8")
 if c[0x0119:0x011C]!=bytes([0x1F,0x09,0x40]):raise E("Zone9")
 if c[0x0126:0x012A]!=bytes([0x11,0x04,0x18,0x3F]):raise E("zone count two")
 tok(c,0x0130,0x7B,0x040054CA,"CheerLevel_Total zone read");tok(c,0x0137,0x7D,0x040054CA,"CheerLevel_Total zone write")
 tok(c,0x0157,0x28,0x0600505D,"PlayerMan.GetInst sally");tok(c,0x015E,0x6F,0x06005065,"GetPlObj sally");tok(c,0x0167,0x28,0x0A00002A,"player truth sally");tok(c,0x0178,0x7B,0x04006057,"isSleep sally");tok(c,0x0189,0x7B,0x04005FE4,"isSallying")
 tok(c,0x0195,0x7B,0x040054CA,"CheerLevel_Total sally read");tok(c,0x019C,0x7D,0x040054CA,"CheerLevel_Total sally write")
 tok(c,0x01B5,0x7B,0x040054CA,"total clamp low read")
 if c[0x01BA:0x01BC]!=bytes([0x1F,0xFC]):raise E("raw -4");br(c,0x01BC,0x3C,0x01C9,"low clamp")
 tok(c,0x01C4,0x7D,0x040054CA,"total clamp low write");tok(c,0x01CA,0x7B,0x040054CA,"total clamp high read")
 if c[0x01CF:0x01D1]!=bytes([0x1A,0x3E]):raise E("raw 4 high");tok(c,0x01D7,0x7D,0x040054CA,"total clamp high write")
 if c[0x01DC]!=0x2A:raise E("ret")
 tok(cs["Caller"],0x0024,0x28,0x060047E0,"FACT-0079 caller")
 return {"dll_sha256":DLL_SHA,"method":{"code_size":len(c),"code_sha256":M["Leaf"][2]},"player_indices":[0,7],"zone_values":[1,3,8,9],"clamp":[-4,4]}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_AUDIENCE_CALC_CHEER_LEVEL: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_AUDIENCE_CALC_CHEER_LEVEL: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
