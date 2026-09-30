#!/usr/bin/env python3
import argparse,hashlib,json,struct
from pathlib import Path

DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
METHODS={
 "slot":(0x002AEFFC,132,"224619b3628e2141649f4c24f24196c0d810edf2b2bbfeccd289e0822fb98012"),
 "exchange":(0x002AF08C,239,"2a91e3b19f7438eefaf7e3b85aa6f4cfb3c8c8a35ab64fdd1aefb71c2e7456b1")
}
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

def verify(path):
    got=sha_path(path)
    if got!=DLL_SHA: raise ProofError("DLL SHA "+got)
    pe=Path(path).read_bytes();ss=sections(pe)
    slot=mcode(pe,ss,METHODS["slot"][0]);ex=mcode(pe,ss,METHODS["exchange"][0])
    if len(slot)!=132 or hashlib.sha256(slot).hexdigest()!=METHODS["slot"][2]: raise ProofError("slot body")
    if len(ex)!=239 or hashlib.sha256(ex).hexdigest()!=METHODS["exchange"][2]: raise ProofError("exchange body")

    tok(slot,0x000E,0x28,0x0600116D,"GetSkillSlotData")
    tok(slot,0x0015,0x7B,0x04000EE5,"slotDamageMdf #1")
    tok(slot,0x0026,0x7B,0x04000EE4,"slotStrength")
    tok(slot,0x002C,0x7B,0x04007C79,"primarySkillStrength")
    tok(slot,0x0041,0x7B,0x04000EE5,"slotDamageMdf #2")
    tok(slot,0x0060,0x7B,0x04000EE5,"slotDamageMdf #3")
    for x in [
      (0x0002,0x40,0x000D,"slot -1"),(0x001A,0x3A,0x0025,"mode nonzero"),
      (0x0035,0x3D,0x0040,"diff positive"),(0x0047,0x40,0x005F,"mode1"),
      (0x004E,0x40,0x0059,"mode1 diff1"),(0x0066,0x40,0x007E,"mode2"),
      (0x006D,0x40,0x0078,"mode2 diff1")
    ]: br(slot,*x)
    for o,v,l in [
      (0x0007,1.0,"slot baseline1"),(0x001F,1.0,"mode0 baseline"),(0x003A,1.0,"diff baseline"),
      (0x0053,1.2000000476837158,"mode1 diff1"),(0x0059,1.5,"mode1 other"),
      (0x0072,1.100000023841858,"mode2 diff1"),(0x0078,1.2000000476837158,"mode2 other"),
      (0x007E,1.0,"slot final")
    ]: f32(slot,o,v,l)

    for x in [
      (0x0000,0x7E,0x040061FA,"PlayerMan atk"),(0x0006,0x6F,0x06005065,"atk GetPlObj"),
      (0x000C,0x7E,0x040061FA,"PlayerMan def"),(0x0012,0x6F,0x06005065,"def GetPlObj"),
      (0x0019,0x28,0x0A00002A,"atk implicit"),(0x002A,0x28,0x0A00002A,"def implicit"),
      (0x003B,0x7B,0x04005FBF,"atk HP"),(0x0048,0x7B,0x04005FBF,"def HP"),
      (0x0057,0x28,0x0A000045,"Abs")
    ]: tok(ex,*x)
    for x in [
      (0x001E,0x3A,0x0029,"atk present"),(0x002F,0x3A,0x003A,"def present"),
      (0x0065,0x41,0x0070,"diff floor"),(0x0072,0x44,0x00B3,"direction"),
      (0x007E,0x44,0x0089,"high .8"),(0x0090,0x44,0x009B,"high .6"),
      (0x00A2,0x44,0x00AD,"high .4"),(0x00BA,0x44,0x00C5,"low .8"),
      (0x00CC,0x44,0x00D7,"low .6"),(0x00DE,0x44,0x00E9,"low .4")
    ]: br(ex,*x)
    for o,v,l in [
      (0x0023,1.0,"atk absent"),(0x0034,1.0,"def absent"),
      (0x0040,65535.0,"atk divisor"),(0x004D,65535.0,"def divisor"),
      (0x0060,0.20000000298023224,"floor"),(0x006A,1.0,"floor return"),
      (0x0079,0.800000011920929,"high th .8"),(0x0083,0.25,"high r .25"),
      (0x008B,0.6000000238418579,"high th .6"),(0x0095,0.33000001311302185,"high r .33"),
      (0x009D,0.4000000059604645,"high th .4"),(0x00A7,0.5,"high r .5"),
      (0x00AD,0.800000011920929,"high r .8"),
      (0x00B5,0.800000011920929,"low th .8"),(0x00BF,4.0,"low r4"),
      (0x00C7,0.6000000238418579,"low th .6"),(0x00D1,3.0,"low r3"),
      (0x00D9,0.4000000059604645,"low th .4"),(0x00E3,2.0,"low r2"),
      (0x00E9,1.2000000476837158,"low r1.2")
    ]: f32(ex,o,v,l)

    return {
      "dll_sha256":got,
      "methods":{
        "GetSkillSlotDamageMdf":{"code_size":len(slot),"code_sha256":METHODS["slot"][2]},
        "GetExchangeOfStrikingDamageMdf":{"code_size":len(ex),"code_sha256":METHODS["exchange"][2]}
      }
    }

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
    try:
        r=verify(a.dll)
        if a.out: Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_APPLY_DAMAGE_MODIFIERS: PASS");return 0
    except (OSError,ValueError,ProofError) as e:
        print("PROVE_APPLY_DAMAGE_MODIFIERS: FAIL");print(str(e));return 1
if __name__=="__main__": raise SystemExit(main())
