#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "ProcessPriorityAct":(0x002FD31C,431,"0db6da9710767a5629dec05b3a7521e0aa1cb83f55d6332a648e89fa5917afc1"),
 "Update":(0x002FFC68,984,"6cea6fc2585177a22c56446c0be26152eed5061fdb0239837f775cad0c2be6d9")
}
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
 fb=pe[o]
 if fb&3==2:h=1;n=fb>>2
 elif fb&3==3:
  fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 else:raise ProofError("bad IL header")
 return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise ProofError(l)
def br(c,o,op,t,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=t:raise ProofError(l)
def verify(path):
 got=sha_path(path)
 if got!=DLL_SHA:raise ProofError("DLL SHA "+got)
 pe=Path(path).read_bytes();ss=sections(pe);cs={}
 for n,(rva,size,sha) in M.items():
  c=code(pe,ss,rva)
  if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise ProofError(n+" body")
  cs[n]=c
 c=cs["ProcessPriorityAct"]
 for x in [
 (0x0001,0x7B,0x04006151,"currentPriAct"),(0x000F,0x7B,0x0400614A,"PlObj1"),(0x0014,0x7B,0x04005FB7,"State1"),
 (0x0025,0x7B,0x0400614A,"PlObj2"),(0x002A,0x7B,0x04005FB7,"State2"),(0x0038,0x7B,0x0400614A,"PlObj3"),(0x003D,0x7B,0x04005FEE,"Zone"),
 (0x004A,0x7B,0x0400614A,"PlObj4"),(0x004F,0x7B,0x0400600B,"weaponIdx"),(0x005D,0x7B,0x0400614A,"PlObj5"),(0x0062,0x7B,0x04006036,"lastSkill"),
 (0x006F,0x7E,0x040061FA,"PlayerMan.inst"),(0x0075,0x7B,0x0400614A,"PlObj6"),(0x007A,0x7B,0x04005FB1,"TargetPlIdx"),(0x007F,0x6F,0x06005065,"GetPlObj"),
 (0x0086,0x7B,0x0400614A,"PlObj7"),(0x008B,0x7B,0x04005FB3,"WresParam"),(0x0090,0x7B,0x040010AA,"aiParam"),
 (0x0097,0x7B,0x04006047,"target isKO"),(0x00A4,0x7B,0x04006046,"target isKOCount"),
 (0x00BA,0x7B,0x04006152,"checkedPriAct read"),(0x00CC,0x7B,0x04000D28,"priorityAct"),(0x00D2,0x8F,0x0200018B,"AIPriorityAct element"),(0x00D7,0x7B,0x04000CF9,"moveAct"),
 (0x00DE,0x7B,0x04005FBF,"target HP"),(0x00E3,0x28,0x06004F9B,"GetDamageLevel_LMH"),(0x00F3,0x7B,0x04000D27,"priorityAct_HDmg"),(0x0102,0x7B,0x04000D26,"priorityAct_LDmg"),
 (0x0119,0x7B,0x04000D28,"priorityAct2"),(0x011F,0x8F,0x0200018B,"AIPriorityAct element2"),(0x0124,0x7B,0x04000CF8,"triggerAct"),(0x012A,0x7B,0x0400614A,"PlObj trigger"),(0x012F,0x7B,0x04006036,"lastSkill trigger"),
 (0x013F,0x7B,0x0400614A,"PlObj hit"),(0x0144,0x7B,0x04006037,"lastSkillHit"),(0x0155,0x28,0x06005008,"IsLotPriorityAct"),
 (0x0165,0x7B,0x04006152,"checkedPriAct write"),(0x016F,0x28,0x06004955,"mRate100Check"),(0x0180,0x28,0x06005009,"TryToDoPriorityAct"),(0x0190,0x28,0x06004FD8,"Reset_HungUpCheck")]:tok(c,*x)
 for x in [
 (0x0007,0x3B,0x000E,"current=-1"),(0x001A,0x40,0x0024,"state!=6"),(0x001F,0x38,0x0049,"state6 bypass"),
 (0x0030,0x3E,0x0037,"state<=4"),(0x0042,0x39,0x0049,"zone0"),(0x0055,0x3F,0x005C,"weapon<0"),(0x0068,0x40,0x006F,"lastSkill!=-1"),
 (0x009C,0x39,0x00A3,"target notKO"),(0x00A9,0x39,0x00B0,"target notKOCount"),(0x00C1,0x39,0x00CB,"unchecked"),
 (0x00C6,0x38,0x01A1,"checked skip"),(0x00ED,0x40,0x0101,"damage level !=2"),(0x00FC,0x38,0x010B,"damage branch join"),
 (0x010E,0x3D,0x0118,"selected positive"),(0x0113,0x38,0x01A1,"nonpositive skip"),(0x0134,0x3B,0x013E,"trigger==lastSkill"),
 (0x0139,0x38,0x01A1,"trigger skip"),(0x0149,0x3A,0x0153,"lastSkillHit"),(0x014E,0x38,0x01A1,"hit skip"),
 (0x015A,0x3A,0x0164,"IsLot true"),(0x015F,0x38,0x01A1,"lot skip"),(0x0174,0x3A,0x017E,"rate true"),
 (0x0179,0x38,0x01A1,"rate skip"),(0x018A,0x3E,0x01A1,"try result <=0"),(0x0198,0x40,0x019F,"result !=1"),
 (0x01A8,0x3F,0x00B9,"index<12")]:br(c,*x)
 if c[0x00B0:0x00B4]!=bytes([0x16,0x0C,0x16,0x0C]):raise ProofError("loop init")
 if c[0x00C0]!=0x91:raise ProofError("checked read opcode")
 if c[0x016B:0x016D]!=bytes([0x17,0x9C]):raise ProofError("checked mark")
 if c[0x019D:0x01A1]!=bytes([0x16,0x2A,0x17,0x2A]):raise ProofError("result returns")
 if c[0x01A5:0x01A8]!=bytes([0x08,0x1F,0x0C]):raise ProofError("loop bound 12")
 if c[0x01AD:0x01AF]!=bytes([0x16,0x2A]):raise ProofError("final false")
 u=cs["Update"];tok(u,0x0208,0x28,0x0600500A,"Update call ProcessPriorityAct")
 if u[0x020D]!=0x26:raise ProofError("Update pop")
 return {"dll_sha256":got,"method":{"code_size":len(c),"code_sha256":M["ProcessPriorityAct"][2]},"caller":{"code_size":len(u),"code_sha256":M["Update"][2]}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_PROCESS_PRIORITY_ACT: PASS");return 0
 except (OSError,ValueError,ProofError) as e:
  print("PROVE_PROCESS_PRIORITY_ACT: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
