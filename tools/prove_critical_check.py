#!/usr/bin/env python3
import argparse,hashlib,json,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x002AEC54
CODE_SIZE=678
CODE_SHA="8df067018ec4101a6f4861d7fe438f0ea51a2b50b1f698a9b908698e72352466"
class ProofError(RuntimeError): pass
def sha_path(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for c in iter(lambda:f.read(1024*1024),b""): h.update(c)
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
    if c[o]!=0x22: raise ProofError(l+" opcode")
    a=struct.unpack_from("<f",c,o+1)[0];b=struct.unpack("<f",struct.pack("<f",v))[0]
    if a!=b: raise ProofError(l)
def i4(c,o,v,l):
    if c[o]!=0x20 or struct.unpack_from("<i",c,o+1)[0]!=v: raise ProofError(l)
def verify(path):
    got=sha_path(path)
    if got!=DLL_SHA: raise ProofError("DLL SHA "+got)
    pe=Path(path).read_bytes();c=mcode(pe,sections(pe),RVA)
    if len(c)!=CODE_SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA: raise ProofError("CriticalCheck body")
    checks=[
      (0x0000,0x7E,0x04002AD1,"GlobalWork.inst"),(0x0005,0x7B,0x04002AD2,"MatchSetting"),(0x000C,0x7B,0x040057DB,"CriticalRate entry"),
      (0x0018,0x7E,0x040061FA,"PlayerMan atk"),(0x001E,0x6F,0x06005065,"atk GetPlObj"),(0x0024,0x7E,0x040061FA,"PlayerMan def"),(0x002A,0x6F,0x06005065,"def GetPlObj"),
      (0x0031,0x28,0x0A00002A,"atk implicit"),(0x003C,0x28,0x0A00002A,"def implicit"),(0x0049,0x7B,0x04006077,"atk intruder"),(0x0054,0x7B,0x04006077,"def intruder"),
      (0x0061,0x7B,0x04006044,"atk second"),(0x006C,0x7B,0x04006044,"def second"),(0x0079,0x7B,0x04005FA8,"animator"),(0x007E,0x7B,0x04005EE6,"looped"),
      (0x008B,0x7B,0x04005FB3,"WresParam critical"),(0x0090,0x7B,0x0400109E,"criticalType"),(0x009D,0x7B,0x04006058,"critical move zero path"),
      (0x00AA,0x7B,0x04005FA8,"animator zero"),(0x00AF,0x7B,0x04005ED0,"skill zero"),(0x00B4,0x7B,0x04007C55,"flags zero"),
      (0x00C8,0x7B,0x04005FA8,"animator nonzero"),(0x00CD,0x7B,0x04005ED0,"skill nonzero"),(0x00D2,0x7B,0x04007C55,"flags nonzero"),(0x00D7,0x7E,0x04005784,"Critical_CheckTbl eligibility"),
      (0x00E6,0x7E,0x04005658,"critical table1"),(0x00ED,0x7B,0x04005FB3,"def WresParam"),(0x00F2,0x7B,0x0400108C,"reversalType"),(0x00F7,0x28,0x0A000716,"table1 Get"),
      (0x0105,0x7E,0x04005659,"critical table2"),(0x010C,0x7B,0x04005FB3,"atk WresParam fight"),(0x0111,0x7B,0x0400108B,"fightStyle"),(0x0116,0x28,0x0A000716,"table2 Get"),
      (0x0124,0x7E,0x0400565A,"critical rate table"),(0x012B,0x7B,0x04005FBF,"def HP"),(0x0130,0x28,0x0600495C,"GetHealth"),(0x0135,0x28,0x0A000716,"rate table Get"),
      (0x0150,0x7E,0x04005784,"check table mask2"),(0x015E,0x7E,0x04005784,"check table mask8"),(0x016C,0x7E,0x04005784,"check table mask32"),
      (0x017C,0x7B,0x04005FBD,"def sp flags512"),(0x0199,0x7B,0x04005FBD,"def sp flags1024"),
      (0x01BE,0x7B,0x04005FBD,"atk sp flags4"),(0x01CB,0x7B,0x04005FBF,"atk HP"),(0x01DB,0x7B,0x04005FC0,"atk SP"),
      (0x01F5,0x7B,0x040057DB,"CriticalRate one"),(0x0210,0x7B,0x040057DB,"CriticalRate three"),(0x0226,0x7B,0x040057E6,"isS1Rule"),
      (0x0231,0x7B,0x04005FA8,"S1 animator"),(0x0236,0x7B,0x04005ED0,"S1 skill"),(0x023B,0x7B,0x04007C55,"S1 flags"),
      (0x025D,0x7B,0x04006058,"S1 critical move"),(0x0268,0x7B,0x04005FA8,"S1 animator #2"),(0x026D,0x7B,0x04005ED0,"S1 skill #2"),(0x0272,0x28,0x06005266,"IsS1Waza"),
      (0x0292,0x28,0x0600497C,"Range")
    ]
    for x in checks: tok(c,*x)
    branches=[
      (0x0011,0x3A,0x0018,"rate nonzero"),(0x0036,0x39,0x0046,"atk missing"),(0x0041,0x3A,0x0048,"def present"),(0x004E,0x3A,0x005E,"atk intruder"),(0x0059,0x39,0x0060,"def not intruder"),
      (0x0066,0x3A,0x0076,"atk second"),(0x0071,0x39,0x0078,"def not second"),(0x0083,0x39,0x008A,"not looped"),(0x0097,0x3A,0x00C7,"critical type split"),
      (0x00A2,0x3A,0x00A9,"critical move"),(0x00BB,0x3A,0x00C2,"flags1"),(0x00C2,0x38,0x00E6,"zero gate join"),(0x00DF,0x3A,0x00E6,"nonzero gate join"),
      (0x014B,0x39,0x01B0,"fourth factor skip"),(0x0159,0x3A,0x017B,"check mask2"),(0x0167,0x3A,0x017B,"check mask8"),(0x0176,0x39,0x0198,"check mask32"),
      (0x0187,0x39,0x0193,"def mask512"),(0x0193,0x38,0x01B0,"factor join"),(0x01A4,0x39,0x01B0,"def mask1024"),
      (0x01C5,0x39,0x01F4,"atk mask4"),(0x01D5,0x41,0x01F4,"HP gate"),(0x01E5,0x43,0x01F4,"SP gate"),(0x01FB,0x40,0x020F,"rate1"),(0x020A,0x38,0x0225,"rate1 join"),
      (0x0216,0x40,0x0225,"rate3"),(0x022B,0x39,0x0288,"not S1"),(0x0242,0x39,0x0256,"S1 mask2"),(0x0251,0x38,0x0288,"S1 mask2 join"),
      (0x0257,0x3A,0x0281,"S1 criticalType"),(0x0262,0x39,0x0281,"S1 critical move"),(0x0277,0x39,0x0281,"S1 waza"),(0x027C,0x38,0x0288,"S1 waza join"),
      (0x029D,0x42,0x02A4,"random compare")
    ]
    for x in branches: br(c,*x)
    if c[0x00B9]!=0x17: raise ProofError("raw flags mask1")
    if c[0x0157]!=0x18 or c[0x0165]!=0x1E or c[0x0173:0x0175]!=bytes([0x1F,0x20]): raise ProofError("Critical_CheckTbl masks")
    i4(c,0x0181,512,"def mask512");i4(c,0x019E,1024,"def mask1024")
    if c[0x01C3]!=0x1A: raise ProofError("atk mask4")
    if c[0x0240]!=0x18: raise ProofError("S1 flags mask2")
    for o,v,l in [
      (0x00FD,100.0,"table1 divisor"),(0x011C,100.0,"table2 divisor"),(0x013B,100.0,"rate divisor"),(0x0143,1.0,"factor initial"),
      (0x018C,0.5,"mask512 factor"),(0x01A9,0.25,"mask1024 factor"),(0x01D0,6400.0,"HP threshold"),(0x01E0,19456.0,"SP threshold"),
      (0x01EC,2.0,"mask4 factor"),(0x0202,2.0,"rate1 divisor"),(0x021D,2.0,"rate3 factor"),(0x0249,2.0,"S1 mask2 factor"),
      (0x0281,0.0,"S1 zero"),(0x0288,0.0,"Range min"),(0x028D,1.0,"Range max")
    ]: f32(c,o,v,l)
    if c[0x0016:0x0018]!=bytes([0x16,0x2A]) or c[0x0046:0x0048]!=bytes([0x16,0x2A]) or c[0x005E:0x0060]!=bytes([0x16,0x2A]) or c[0x0076:0x0078]!=bytes([0x16,0x2A]) or c[0x0088:0x008A]!=bytes([0x16,0x2A]): raise ProofError("early false return")
    if c[0x02A2:0x02A4]!=bytes([0x17,0x2A]) or c[0x02A4:0x02A6]!=bytes([0x16,0x2A]): raise ProofError("final bool returns")
    return {"dll_sha256":got,"code_size":len(c),"code_sha256":CODE_SHA}
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
    try:
        r=verify(a.dll)
        if a.out: Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_CRITICAL_CHECK: PASS");return 0
    except (OSError,ValueError,ProofError) as e:
        print("PROVE_CRITICAL_CHECK: FAIL");print(str(e));return 1
if __name__=="__main__": raise SystemExit(main())
