#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "MainWrap":(0x002A8BCC,8,"d404b794b4ad8b202e0dfaadeceb6698bcd0a653b27f42d05efb6c60d3692ad4"),
 "MainMove":(0x002AD188,523,"2cf73d3b9e4f7c5d0e3e3bf24708c219538bab0e1dcac04dc076329b4002c98d"),
 "CpWrap":(0x002AD5EC,8,"42472ac9c0e12c47b372f848afebdd431149ffcf9d829a116b336d25e424ef29"),
 "CpMove":(0x002AE534,303,"c5fc6e292c2adf300eeda5ad44d8c2e0d0650a59e63eadf41213ea81f90e1d6d")
}
class E(RuntimeError):pass
def sh(p):
 h=hashlib.sha256()
 with open(p,"rb") as f:
  for x in iter(lambda:f.read(1<<20),b""):h.update(x)
 return h.hexdigest()
def secs(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\0\0":raise E("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
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
def i4(c,o,v,l):
 if c[o]!=0x20 or struct.unpack_from("<i",c,o+1)[0]!=v:raise E(l)
def verify(path):
 if sh(path)!=DLL_SHA:raise E("dll")
 pe=Path(path).read_bytes();ss=secs(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E(n+" body")
  cs[n]=c
 tok(cs["MainWrap"],0x0000,0x73,0x06007424,"Main iterator ctor")
 if cs["MainWrap"][0x0005:0x0008]!=bytes([0x0A,0x06,0x2A]):raise E("Main wrapper tail")
 tok(cs["CpWrap"],0x0000,0x73,0x06007442,"Cp iterator ctor")
 if cs["CpWrap"][0x0005:0x0008]!=bytes([0x0A,0x06,0x2A]):raise E("Cp wrapper tail")
 c=cs["MainMove"]
 tok(c,0x0026,0x7E,0x04002AD1,"GlobalWork.inst");tok(c,0x002B,0x7B,0x04002AD2,"MatchSetting")
 tok(c,0x003B,0x7B,0x040057D7,"RefereeID gate");tok(c,0x0051,0x6F,0x060050B5,"FACT-0066 CreateReferee")
 i4(c,0x0066,10000,"Main threshold #1");tok(c,0x0080,0x6F,0x060051A3,"Main edit lookup #1")
 tok(c,0x0093,0x7D,0x040057D7,"Main fallback RefereeID=0");i4(c,0x00A3,10000,"Main threshold #2")
 tok(c,0x00C3,0x6F,0x06001138,"Main preset param");tok(c,0x00DD,0x6F,0x0600113A,"Main costume filename")
 tok(c,0x00EA,0x6F,0x060010F3,"Main preset referee data");tok(c,0x0109,0x6F,0x060051A3,"Main edit lookup #2")
 tok(c,0x0156,0x6F,0x06005079,"Main Referee.Init");tok(c,0x016E,0x6F,0x06001F38,"Main texture async")
 tok(c,0x0198,0x6F,0x06001F20,"Main InitSprite");tok(c,0x01D2,0x28,0x0600528A,"Main voice async")
 i4(c,0x01F6,1106,"Main raw animation");tok(c,0x01FB,0x6F,0x06005096,"Main ReqRefereeAnm")
 c=cs["CpMove"]
 tok(c,0x0012,0x7E,0x04002AD1,"Cp GlobalWork.inst");tok(c,0x0017,0x7B,0x04002AD2,"Cp MatchSetting")
 tok(c,0x001E,0x7B,0x040057D7,"Cp RefereeID gate");tok(c,0x0033,0x6F,0x060050B5,"Cp FACT-0066 CreateReferee")
 i4(c,0x003F,10000,"Cp threshold #1");tok(c,0x0054,0x6F,0x060051A3,"Cp edit lookup #1")
 tok(c,0x0062,0x7D,0x040057D7,"Cp fallback RefereeID=0");i4(c,0x006D,10000,"Cp threshold #2")
 tok(c,0x0083,0x6F,0x06001138,"Cp preset param");tok(c,0x0098,0x6F,0x0600113A,"Cp costume filename")
 tok(c,0x00A6,0x6F,0x060010F3,"Cp preset referee data");tok(c,0x00BC,0x6F,0x060051A3,"Cp edit lookup #2")
 tok(c,0x00EB,0x6F,0x06005079,"Cp Referee.Init");i4(c,0x0106,1106,"Cp raw animation");tok(c,0x010B,0x6F,0x06005096,"Cp ReqRefereeAnm")
 tok(c,0x0111,0x7B,0x040062AB,"Cp Shadow read #1");tok(c,0x0117,0x28,0x0A00000F,"Cp Shadow inequality")
 tok(c,0x0122,0x7B,0x040062AB,"Cp Shadow read #2");tok(c,0x0128,0x6F,0x0A000103,"Cp Shadow.SetActive")
 return {"dll_sha256":DLL_SHA,"methods":{k:v[2] for k,v in M.items()},"raw_edit_threshold":10000,"raw_animation":1106}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_MATCH_INIT_REFEREE: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_MATCH_INIT_REFEREE: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
