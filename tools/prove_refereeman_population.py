#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "Ctor":(0x0030A469,19,"41af045848eb62f4e23c69e03c31ef3b97d03f719029ccc12ba8664223d8ad0f"),
 "Awake":(0x0030A484,7,"7f2f8b8a300d684c753bf13af8b5395f7de72f88526eeee171860bcef5004548"),
 "Start":(0x0030A48C,1,"684888c0ebb17f374298b65ee2807526c066094c701bcc7ebbe1c1095f494fc1"),
 "Create":(0x0030A490,39,"cbd7b30a0f79c0a5cb7c5459a6cb8462f5df1e30a023aefa52826ebce99fd7a6"),
 "GetInst":(0x0030A47D,6,"9520016c102a2a51bd00c0108de13b24734f1b686f000e2460083dd39da009ee"),
 "GetObj":(0x0030A4C3,9,"aa2a417db5ba1940541d91f5a98fe26ec59230af147fdb4dd2e768ca0dad1e4d")
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
def verify(path):
 if sh(path)!=DLL_SHA:raise E("dll")
 pe=Path(path).read_bytes();ss=secs(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise E(n+" body")
  cs[n]=c
 c=cs["Ctor"]
 if c[0:2]!=bytes([0x02,0x17]):raise E("ctor this/one")
 tok(c,0x0002,0x8D,0x02000A0E,"new Referee[1]")
 tok(c,0x0007,0x7D,0x040062DE,"RefereeObj store")
 if c[0x000C]!=0x02:raise E("ctor base this")
 tok(c,0x000D,0x28,0x0A00000E,"MonoBehaviour .ctor")
 if c[0x0012]!=0x2A:raise E("ctor ret")
 c=cs["Awake"]
 if c[0]!=0x02:raise E("Awake this")
 tok(c,0x0001,0x80,0x040062DC,"inst store")
 if c[0x0006]!=0x2A:raise E("Awake ret")
 if cs["Start"]!=bytes([0x2A]):raise E("Start")
 c=cs["Create"]
 if c[0:2]!=bytes([0x16,0x0A]):raise E("index zero")
 if c[0x0002]!=0x02:raise E("create this prefab")
 tok(c,0x0003,0x7B,0x040062DD,"Prefab_Referee")
 tok(c,0x0008,0x28,0x2B000051,"Instantiate<GameObject>")
 if c[0x000D]!=0x0B:raise E("stloc GameObject")
 if c[0x000E]!=0x02:raise E("create this array")
 tok(c,0x000F,0x7B,0x040062DE,"RefereeObj write")
 if c[0x0014:0x0016]!=bytes([0x06,0x07]):raise E("index/object")
 tok(c,0x0016,0x6F,0x2B0003B9,"GetComponent<Referee>")
 if c[0x001B]!=0xA2:raise E("stelem.ref")
 if c[0x001C]!=0x02:raise E("reload this")
 tok(c,0x001D,0x7B,0x040062DE,"RefereeObj reload")
 if c[0x0022:0x0027]!=bytes([0x06,0x9A,0x0C,0x08,0x2A]):raise E("return RefereeObj[0]")
 tok(cs["GetInst"],0x0000,0x7E,0x040062DC,"FACT-0065 inst read")
 tok(cs["GetObj"],0x0001,0x7B,0x040062DE,"FACT-0065 array read")
 return {"dll_sha256":DLL_SHA,"methods":{k:v[2] for k,v in M.items() if k in ("Ctor","Awake","Start","Create")},"raw_referee_index":0}
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--out");x=a.parse_args()
 try:
  r=verify(x.dll)
  if x.out:Path(x.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_REFEREEMAN_POPULATION: PASS");return 0
 except (OSError,ValueError,E) as e:
  print("PROVE_REFEREEMAN_POPULATION: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
