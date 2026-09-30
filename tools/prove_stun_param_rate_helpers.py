#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "SetStunTime":(0x002E193F,27,"f1cf347336997ae6ca3fc68973801bfad9697cf43326c86143a6cfa7cbb96074"),
 "GetParamRate":(0x002B0D74,16,"60de3a243171244b6e09508e9a73f00d82aa76207ad3e8dd046322bc7b849e6c"),
 "CalcDownTime":(0x002E6CD0,422,"f02235b113abcab029951822052639084b3692e7924ae6c3b9ac85e4c86a3a88")
}
class ProofError(RuntimeError): pass
def sha_path(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for x in iter(lambda:f.read(1024*1024),b""): h.update(x)
    return h.hexdigest()
def sections(pe):
    q=struct.unpack_from("<I",pe,0x3c)[0]
    if pe[q:q+4]!=b"PE\0\0": raise ProofError("not PE")
    n=struct.unpack_from("<H",pe,q+6)[0];osz=struct.unpack_from("<H",pe,q+20)[0];s=q+24+osz;out=[]
    for i in range(n):
        o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
    return out
def rvaoff(ss,rva):
    for va,sz,rp in ss:
        if va<=rva<va+sz:return rp+rva-va
    raise ProofError("RVA unmapped")
def mcode(pe,ss,rva):
    o=rvaoff(ss,rva);fb=pe[o]
    if fb&3==2:h=1;n=fb>>2
    elif fb&3==3:
        fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
    else: raise ProofError("bad IL header")
    return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
    if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise ProofError(l)
def br(c,o,op,t,l):
    if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=t:raise ProofError(l)
def f32(c,o,v,l):
    if c[o]!=0x22 or struct.unpack_from("<f",c,o+1)[0]!=struct.unpack("<f",struct.pack("<f",v))[0]:raise ProofError(l)
def i4(c,o,v,l):
    if c[o]!=0x20 or struct.unpack_from("<i",c,o+1)[0]!=v:raise ProofError(l)
def verify(path):
    got=sha_path(path)
    if got!=DLL_SHA:raise ProofError("DLL SHA "+got)
    pe=Path(path).read_bytes();ss=sections(pe);cs={}
    for n,(rva,size,sha) in M.items():
        c=mcode(pe,ss,rva)
        if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise ProofError(n+" body")
        cs[n]=c
    c=cs["SetStunTime"]
    if c[0:2]!=bytes([0x02,0x03]):raise ProofError("SetStunTime args")
    tok(c,0x0002,0x7D,0x04005FD0,"StunTime initial store")
    if c[0x0007]!=0x02:raise ProofError("SetStunTime this reload")
    tok(c,0x0008,0x7B,0x04005FD0,"StunTime load")
    if c[0x000D]!=0x16:raise ProofError("StunTime zero compare")
    br(c,0x000E,0x3C,0x001A,"signed bge return")
    if c[0x0013:0x0015]!=bytes([0x02,0x16]):raise ProofError("StunTime zero store args")
    tok(c,0x0015,0x7D,0x04005FD0,"StunTime zero store")
    if c[0x001A]!=0x2A:raise ProofError("SetStunTime ret")
    c=cs["GetParamRate"]
    if c[0]!=0x02:raise ProofError("GetParamRate arg")
    f32(c,0x0001,65535.0,"GetParamRate divisor")
    if c[0x0006]!=0x5B:raise ProofError("GetParamRate div")
    f32(c,0x0007,100.0,"GetParamRate multiplier")
    if c[0x000C:0x0010]!=bytes([0x5A,0x0A,0x06,0x2A]):raise ProofError("GetParamRate mul/store/return")
    c=cs["CalcDownTime"]
    for off,t in [(0x0018,0x06004EDA),(0x0079,0x06004EDA),(0x00F1,0x06004EDA),(0x00BC,0x06004975),(0x00D1,0x06004975)]:
        tok(c,off,0x28,t,"CalcDownTime helper call "+hex(off))
    if c[0x0017]!=0x16:raise ProofError("SetStunTime raw 0 caller")
    if c[0x0078]!=0x08:raise ProofError("SetStunTime local2 caller")
    i4(c,0x00EC,960,"SetStunTime raw 960 caller")
    if c[0x00B6]!=0x02:raise ProofError("HP caller this")
    tok(c,0x00B7,0x7B,0x04005FBF,"GetParamRate HP caller")
    if c[0x00CB]!=0x02:raise ProofError("SP caller this")
    tok(c,0x00CC,0x7B,0x04005FC0,"GetParamRate SP caller")
    return {"dll_sha256":got,"methods":{
      "SetStunTime":{"code_size":len(cs["SetStunTime"]),"code_sha256":M["SetStunTime"][2]},
      "GetParamRate":{"code_size":len(cs["GetParamRate"]),"code_sha256":M["GetParamRate"][2]},
      "CalcDownTime_bridge":{"code_size":len(cs["CalcDownTime"]),"code_sha256":M["CalcDownTime"][2]}
    }}
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
    try:
        r=verify(a.dll)
        if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_STUN_PARAM_RATE_HELPERS: PASS");return 0
    except (OSError,ValueError,ProofError) as e:
        print("PROVE_STUN_PARAM_RATE_HELPERS: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
