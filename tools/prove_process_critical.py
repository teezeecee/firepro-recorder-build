#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x002E11B0
SIZE=277
CODE_SHA="95fcc98f9fe079ae95ecf2d72104145a28273b1030b2fc9db039abcfb330fd30"
class ProofError(RuntimeError): pass
def sha_path(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""): h.update(b)
    return h.hexdigest()
def sections(pe):
    q=struct.unpack_from("<I",pe,0x3c)[0]
    if pe[q:q+4]!=b"PE\0\0": raise ProofError("not PE")
    n=struct.unpack_from("<H",pe,q+6)[0];osz=struct.unpack_from("<H",pe,q+20)[0];s=q+24+osz;out=[]
    for i in range(n):
        o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,vs,rp,rs))
    return out
def rvaoff(pe,ss,rva):
    for va,vs,rp,rs in ss:
        if va<=rva<va+max(vs,rs): return rp+rva-va
    raise ProofError("RVA unmapped")
def mcode(pe,ss,rva):
    o=rvaoff(pe,ss,rva);b=pe[o]
    if b&3==2: h=1;n=b>>2
    elif b&3==3:
        fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
    else: raise ProofError("bad IL header")
    return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
    if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t: raise ProofError(l)
def bt(c,o): return o+5+struct.unpack_from("<i",c,o+1)[0]
def br(c,o,op,t,l):
    if c[o]!=op or bt(c,o)!=t: raise ProofError(l)
def f32(c,o,v,l):
    if c[o]!=0x22 or struct.unpack_from("<f",c,o+1)[0]!=struct.unpack("<f",struct.pack("<f",v))[0]: raise ProofError(l)
def i4(c,o,v,l):
    if c[o]!=0x20 or struct.unpack_from("<i",c,o+1)[0]!=v: raise ProofError(l)
def verify(path):
    got=sha_path(path)
    if got!=DLL_SHA: raise ProofError("DLL SHA "+got)
    pe=Path(path).read_bytes();c=mcode(pe,sections(pe),RVA)
    if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA: raise ProofError("ProcessCritical body")
    checks=[
      (0x0001,0x7B,0x04007C55,"SkillData.flags #1"),(0x0010,0x7D,0x04006047,"isKO"),(0x001B,0x7D,0x04005FD2,"KO_Return"),
      (0x0026,0x28,0x06004EDC,"SetLastDamage"),(0x0031,0x7D,0x04005FD6,"KoLastDamage"),
      (0x0037,0x7B,0x04007C5A,"atkPow_HP"),(0x0047,0x28,0x06004ECC,"SetHP"),
      (0x004D,0x7B,0x04007C5B,"atkPow_SP"),(0x005D,0x28,0x06004ED0,"SetSP"),
      (0x0063,0x7B,0x04007C5D,"atkPow_Neck"),(0x0073,0x7D,0x04005FC2,"HP_Neck"),
      (0x0079,0x7B,0x04007C5E,"atkPow_Arm"),(0x0089,0x7D,0x04005FC3,"HP_Arm"),
      (0x008F,0x7B,0x04007C5F,"atkPow_Waist"),(0x009F,0x7D,0x04005FC4,"HP_Waist"),
      (0x00A5,0x7B,0x04007C60,"atkPow_Leg"),(0x00B5,0x7D,0x04005FC5,"HP_Leg"),
      (0x00BB,0x7B,0x04007C5C,"atkPow_BP"),(0x00CB,0x28,0x06004ECE,"SetBP"),
      (0x00D1,0x7B,0x04007C55,"SkillData.flags #2"),(0x00E0,0x7D,0x04006071,"isWannaGiveUp"),
      (0x00E6,0x7B,0x04007C55,"SkillData.flags #3"),(0x00FA,0x7B,0x04005FA6,"PlIdx"),
      (0x00FF,0x28,0x06004970,"PlayMatchSE"),(0x0109,0x7E,0x04005899,"MatchUI.inst"),(0x010F,0x6F,0x060049F3,"Show_Critical")]
    for x in checks: tok(c,*x)
    branches=[
      (0x0009,0x3A,0x0020,"flags40 skip KO"),(0x003C,0x39,0x004C,"HP power"),(0x0052,0x39,0x0062,"SP power"),
      (0x0068,0x39,0x0078,"Neck power"),(0x007E,0x39,0x008E,"Arm power"),(0x0094,0x39,0x00A4,"Waist power"),
      (0x00AA,0x39,0x00BA,"Leg power"),(0x00C0,0x39,0x00D0,"BP power"),(0x00D9,0x39,0x00E5,"flags64"),
      (0x00ED,0x39,0x0109,"flags8 split"),(0x0104,0x38,0x0114,"SE join")]
    for x in branches: br(c,*x)
    if c[0x0006:0x0009]!=bytes([0x1F,0x28,0x5F]): raise ProofError("raw flags mask 40")
    i4(c,0x0016,320,"KO_Return 320")
    f32(c,0x0021,65535.0,"SetLastDamage 65535");f32(c,0x002C,65535.0,"KoLastDamage 65535")
    for o in [0x0042,0x0058,0x006E,0x0084,0x009A,0x00B0,0x00C6]: f32(c,o,0.0,"zero write/call")
    if c[0x00D6:0x00D9]!=bytes([0x1F,0x40,0x5F]): raise ProofError("raw flags mask 64")
    if c[0x00EB:0x00ED]!=bytes([0x1E,0x5F]): raise ProofError("raw flags mask 8")
    if c[0x00F2:0x00F4]!=bytes([0x1F,0x1E]): raise ProofError("PlayMatchSE arg 30")
    f32(c,0x00F4,1.0,"PlayMatchSE factor")
    if c[0x010E]!=0x17: raise ProofError("Show_Critical arg1")
    if c[0x0114]!=0x2A: raise ProofError("ret")
    return {"dll_sha256":got,"code_size":len(c),"code_sha256":CODE_SHA}
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
    try:
        r=verify(a.dll)
        if a.out: Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_PROCESS_CRITICAL: PASS");return 0
    except (OSError,ValueError,ProofError) as e:
        print("PROVE_PROCESS_CRITICAL: FAIL");print(str(e));return 1
if __name__=="__main__": raise SystemExit(main())
