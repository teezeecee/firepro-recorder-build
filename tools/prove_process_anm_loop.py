#!/usr/bin/env python3
import argparse,hashlib,json,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x002DA7B4
CODE_SIZE=659
CODE_SHA="dde8322e75ac1a7d5e5eaa9aa4b92b23791040eda59a832fa26da62d75855602"
class ProofError(RuntimeError): pass
def sha_path(p):
 h=hashlib.sha256()
 with open(p,"rb") as f:
  for c in iter(lambda:f.read(1024*1024),b""): h.update(c)
 return h.hexdigest()
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\0\0": raise ProofError("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0]; osz=struct.unpack_from("<H",pe,q+20)[0]; s=q+24+osz; out=[]
 for i in range(n):
  o=s+i*40; vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); out.append((va,vs,rp,rs))
 return out
def rvaoff(pe,ss,rva):
 for va,vs,rp,rs in ss:
  if va<=rva<va+max(vs,rs): return rp+rva-va
 raise ProofError("RVA unmapped")
def mcode(pe,ss,rva):
 o=rvaoff(pe,ss,rva); b=pe[o]
 if b&3==2: h=1; n=b>>2
 elif b&3==3:
  fs=struct.unpack_from("<H",pe,o)[0]; h=(fs>>12)*4; n=struct.unpack_from("<I",pe,o+4)[0]
 else: raise ProofError("bad IL header")
 return pe[o+h:o+h+n]
def tok(code,off,op,t,label):
 if code[off]!=op or struct.unpack_from("<I",code,off+1)[0]!=t: raise ProofError(label)
def verify(path):
 got=sha_path(path)
 if got!=DLL_SHA: raise ProofError("DLL SHA "+got)
 pe=Path(path).read_bytes(); code=mcode(pe,sections(pe),RVA)
 if len(code)!=CODE_SIZE or hashlib.sha256(code).hexdigest()!=CODE_SHA: raise ProofError("ProcessAnmLoop body")
 checks=[
  (0x0014,0x7B,0x04007C94,"loopReturnPoint"),
  (0x0020,0x7B,0x04007C94,"loopReturnPoint second"),
  (0x0028,0x7B,0x04005ED5,"currentFormIdx"),
  (0x0043,0x6F,0x06005065,"GetPlObj"),
  (0x004A,0x7B,0x04005EE6,"isAnmLooped read"),
  (0x0056,0x7D,0x04005EE6,"isAnmLooped store"),
  (0x005C,0x7B,0x04007C96,"fallTiming"),
  (0x006D,0x7D,0x04006048,"isPinfallAtk"),
  (0x007F,0x7D,0x04006049,"isPinfallDef"),
  (0x0086,0x7D,0x0400605B,"isDecDownTime"),
  (0x008C,0x6F,0x06004F0C,"ForceSetDownTime #1"),
  (0x0092,0x7B,0x04006073,"isCriticalMoveRecieved"),
  (0x00AB,0x6F,0x06004ED8,"SetDownTime scaled"),
  (0x00B1,0x7B,0x04005FC1,"BP"),
  (0x00B6,0x28,0x06004975,"GetParamRate"),
  (0x00CB,0x6F,0x06004ED9,"AddDownTime 256"),
  (0x00DB,0x7B,0x04007C6C,"anmLoopTimes"),
  (0x00ED,0x7B,0x04005FBB,"Status3 read"),
  (0x00F4,0x7D,0x04005FBB,"Status3 store"),
  (0x0100,0x7B,0x04007C6C,"anmLoopTimes second"),
  (0x0105,0x7D,0x04005ED6,"LoopAnmCnt"),
  (0x0116,0x7D,0x0400604B,"isSubmissionAtk"),
  (0x0128,0x7D,0x0400604C,"isSubmissionDef"),
  (0x0135,0x6F,0x06004F0C,"ForceSetDownTime #2"),
  (0x0141,0x6F,0x06004ED9,"AddDownTime current"),
  (0x0181,0x7B,0x04005FA8,"target animator"),
  (0x0186,0x7B,0x04005EE5,"isReqAnmLoopEnd"),
  (0x01C4,0x7B,0x04005FCF,"DownTimeBK"),
  (0x01C9,0x6F,0x06004ED8,"SetDownTime restore"),
  (0x01D0,0x7D,0x04005FCF,"DownTimeBK clear"),
  (0x01DC,0x7B,0x04007C94,"rewind loopReturnPoint"),
  (0x01E4,0x7B,0x04007C95,"rewind loopReturnTo"),
  (0x01EC,0x7D,0x04005ED5,"host currentFormIdx"),
  (0x0213,0x7D,0x04005ED5,"target currentFormIdx"),
  (0x021F,0x7D,0x04005EE8,"target isAnmSync"),
  (0x022B,0x7D,0x04005ED4,"target FormDispDuration"),
  (0x0236,0x7B,0x04005FBB,"Status3 tail"),
  (0x0243,0x7B,0x04005ED6,"LoopAnmCnt tail"),
  (0x0257,0x7D,0x04005ED6,"LoopAnmCnt decrement store"),
  (0x026E,0x7B,0x04005FBB,"Status3 clear read"),
  (0x0276,0x7D,0x04005FBB,"Status3 clear store"),
  (0x0287,0x7B,0x04005FA8,"target animator tail"),
  (0x028D,0x7D,0x04005EE5,"target isReqAnmLoopEnd store")
 ]
 for x in checks: tok(code,*x)
 if code[0x00A4]!=0x22 or struct.unpack_from("<f",code,0x00A5)[0]!=0.8125: raise ProofError("0.8125 constant")
 if code[0x00BB]!=0x22 or struct.unpack_from("<f",code,0x00BC)[0]!=struct.unpack("<f",struct.pack("<f",1.1699999570846558))[0]: raise ProofError("1.17 constant")
 if code[0x00C6]!=0x20 or struct.unpack_from("<i",code,0x00C7)[0]!=256: raise ProofError("AddDownTime 256")
 if code[0x00F2]!=0x1E or code[0x00F3]!=0x60: raise ProofError("Status3 OR 8")
 if code[0x0273:0x0276]!=bytes([0x1F,0xF7,0x5F]): raise ProofError("Status3 AND -9")
 if code[0x0292]!=0x2A: raise ProofError("ret")
 return {"dll_sha256":got,"code_size":len(code),"code_sha256":CODE_SHA}
def main():
 ap=argparse.ArgumentParser(); ap.add_argument("--dll",required=True); ap.add_argument("--out"); a=ap.parse_args()
 try:
  r=verify(a.dll)
  if a.out: Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  print(json.dumps(r,indent=2,sort_keys=True)); print("PROVE_PROCESS_ANM_LOOP: PASS"); return 0
 except (OSError,ValueError,ProofError) as e:
  print("PROVE_PROCESS_ANM_LOOP: FAIL"); print(str(e)); return 1
if __name__=="__main__": raise SystemExit(main())
