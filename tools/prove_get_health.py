#!/usr/bin/env python3
import argparse,hashlib,json,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x002B0270
CODE_SIZE=204
CODE_SHA="54a177d606676d55511eb6a20680babd8298b5f520b47aa6109a77df9eac50ec"
THRESH=[4096.0,8192.0,12288.0,16384.0,20480.0,24576.0,28672.0,32768.0,36864.0,40960.0,45056.0,49152.0,53248.0,57344.0,61440.0]
FLOAT_OFF=[0x0001,0x000E,0x001B,0x0028,0x0035,0x0042,0x004F,0x005C,0x0069,0x0076,0x0084,0x0092,0x00A0,0x00AE,0x00BC]
BR_OFF=[0x0006,0x0013,0x0020,0x002D,0x003A,0x0047,0x0054,0x0061,0x006E,0x007B,0x0089,0x0097,0x00A5,0x00B3,0x00C1]
TARGETS=[0x000D,0x001A,0x0027,0x0034,0x0041,0x004E,0x005B,0x0068,0x0075,0x0083,0x0091,0x009F,0x00AD,0x00BB,0x00C9]
RETVAL_OFF=[0x000B,0x0018,0x0025,0x0032,0x003F,0x004C,0x0059,0x0066,0x0073,0x0080,0x008E,0x009C,0x00AA,0x00B8,0x00C6]
RET_OFF=[0x000C,0x0019,0x0026,0x0033,0x0040,0x004D,0x005A,0x0067,0x0074,0x0082,0x0090,0x009E,0x00AC,0x00BA,0x00C8]
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
def bt(c,o): return o+5+struct.unpack_from("<i",c,o+1)[0]
def f32(c,o,v):
    if c[o]!=0x22 or struct.unpack_from("<f",c,o+1)[0]!=struct.unpack("<f",struct.pack("<f",v))[0]: raise ProofError(f"float at {o:#x}")
def retval(c,o,v):
    if 0<=v<=8:
        if c[o]!=(0x16+v): raise ProofError(f"return value {v}")
    else:
        if c[o]!=0x1F or struct.unpack_from("<b",c,o+1)[0]!=v: raise ProofError(f"return value {v}")
def verify(path):
    got=sha_path(path)
    if got!=DLL_SHA: raise ProofError("DLL SHA "+got)
    pe=Path(path).read_bytes();c=mcode(pe,sections(pe),RVA)
    if len(c)!=CODE_SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA: raise ProofError("GetHealth body")
    for i,v in enumerate(THRESH):
        if c[FLOAT_OFF[i]-1]!=0x02: raise ProofError(f"ldarg.0 rung {i}")
        f32(c,FLOAT_OFF[i],v)
        if c[BR_OFF[i]]!=0x41 or bt(c,BR_OFF[i])!=TARGETS[i]: raise ProofError(f"bge.un rung {i}")
        retval(c,RETVAL_OFF[i],i)
        if c[RET_OFF[i]]!=0x2A: raise ProofError(f"ret rung {i}")
    if c[0x00C9]!=0x1F or struct.unpack_from("<b",c,0x00CA)[0]!=15 or c[0x00CB]!=0x2A: raise ProofError("final return 15")
    return {"dll_sha256":got,"code_size":len(c),"code_sha256":CODE_SHA}
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
    try:
        r=verify(a.dll)
        if a.out: Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_GET_HEALTH: PASS");return 0
    except (OSError,ValueError,ProofError) as e:
        print("PROVE_GET_HEALTH: FAIL");print(str(e));return 1
if __name__=="__main__": raise SystemExit(main())
