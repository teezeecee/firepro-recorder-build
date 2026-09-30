#!/usr/bin/env python3
import argparse,hashlib,json,struct
from pathlib import Path

DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x002AF188
CODE_SIZE=1641
CODE_SHA="6ecc8c9b5e71235fcbde51d1ca3d8baafd5b4d713abc298947b6848627d419b5"

class ProofError(RuntimeError): pass

def sha_path(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for c in iter(lambda:f.read(1024*1024),b""): h.update(c)
    return h.hexdigest()

def sections(pe):
    q=struct.unpack_from("<I",pe,0x3c)[0]
    if pe[q:q+4]!=b"PE\0\0": raise ProofError("not PE")
    n=struct.unpack_from("<H",pe,q+6)[0]; osz=struct.unpack_from("<H",pe,q+20)[0]; s=q+24+osz
    out=[]
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

def branch_target(code,off):
    return off+5+struct.unpack_from("<i",code,off+1)[0]

def br(code,off,op,target,label):
    if code[off]!=op or branch_target(code,off)!=target: raise ProofError(label)

def f32(code,off,value,label):
    if code[off]!=0x22: raise ProofError(label+" opcode")
    got=struct.unpack_from("<f",code,off+1)[0]
    want=struct.unpack("<f",struct.pack("<f",value))[0]
    if got!=want: raise ProofError(label+f" {got}")

def verify(path):
    got=sha_path(path)
    if got!=DLL_SHA: raise ProofError("DLL SHA "+got)
    pe=Path(path).read_bytes(); code=mcode(pe,sections(pe),RVA)
    if len(code)!=CODE_SIZE or hashlib.sha256(code).hexdigest()!=CODE_SHA: raise ProofError("ApplyDamage body")

    checks=[
      (0x0000,0x28,0x06004907,"MatchMain.GetInst"),(0x0013,0x7B,0x04005753,"isMatchEnd"),
      (0x0024,0x6F,0x06005065,"atk GetPlObj"),(0x0030,0x6F,0x06005065,"def GetPlObj"),
      (0x0053,0x7B,0x04002AD2,"MatchSetting"),(0x005E,0x7B,0x0400637A,"venueSetting"),
      (0x006E,0x7B,0x04005ECF,"AnmReqType"),(0x007F,0x7B,0x04005ED9,"SkillSlotID"),(0x008C,0x7B,0x04005ED0,"CurrentSkill"),
      (0x0097,0x28,0x0600494B,"GetSkillSlotDamageMdf"),(0x00B9,0x28,0x0600494C,"GetExchangeOfStrikingDamageMdf"),
      (0x00D2,0x7B,0x04007C7A,"anmData"),(0x00D9,0x7B,0x04007C9C,"cheerLevel"),(0x0190,0x6F,0x060047DE,"Play_Despair"),
      (0x01B7,0x7B,0x04005706,"OutDamageCnt read"),(0x01BE,0x7D,0x04005706,"OutDamageCnt write"),
      (0x01C5,0x28,0x06004949,"CriticalCheck"),(0x01D2,0x6F,0x06004ECA,"ProcessCritical"),
      (0x01E8,0x28,0x06004948,"CalcDamage HP"),(0x01F9,0x6F,0x06004ECB,"AddHP"),(0x023A,0x6F,0x06004EDC,"SetLastDamage"),(0x0254,0x6F,0x06004EB1,"SetLastSkill"),
      (0x029A,0x28,0x06004948,"CalcDamage BP"),(0x02AB,0x6F,0x06004ECD,"AddBP"),
      (0x02B9,0x28,0x06004948,"CalcDamage Neck"),(0x02DC,0x6F,0x06004ED4,"AddHP_Neck"),
      (0x02FD,0x28,0x06004948,"CalcDamage Arm"),(0x0320,0x6F,0x06004ED5,"AddHP_Arm"),
      (0x0341,0x28,0x06004948,"CalcDamage Waist"),(0x0364,0x6F,0x06004ED6,"AddHP_Waist"),
      (0x0385,0x28,0x06004948,"CalcDamage Leg"),(0x03A8,0x6F,0x06004ED7,"AddHP_Leg"),
      (0x03C9,0x28,0x06004948,"CalcDamage SP"),(0x03E0,0x6F,0x06004ECF,"AddSP primary"),(0x044F,0x6F,0x06004ECF,"AddSP followup"),
      (0x0465,0x6F,0x06004ED3,"InvokeUkeBonus"),(0x0498,0x28,0x06004955,"mRate100Check giveup"),
      (0x04FE,0x28,0x06004955,"mRate100Check bleeding"),(0x0509,0x6F,0x06004F1F,"Bleeding"),
      (0x0531,0x6F,0x06004ED1,"ConsumeSP"),(0x053E,0x6F,0x06004ED2,"RecoverSP blood"),
      (0x0557,0x7D,0x04006053,"isFoul"),(0x057D,0x6F,0x06004ED2,"RecoverSP special"),(0x0593,0x6F,0x06004ED2,"RecoverSP critical"),
      (0x05B1,0x7B,0x040056DC,"weaponAtkHitCnt read"),(0x05B8,0x7D,0x040056DC,"weaponAtkHitCnt write"),
      (0x05CD,0x6F,0x060048D2,"finish Set #1"),(0x05E0,0x6F,0x060048D2,"finish Set #2"),(0x060A,0x6F,0x060048D1,"finish Clear"),
      (0x0635,0x7D,0x04006073,"critical received clear"),(0x0647,0x7D,0x04006073,"critical received set"),(0x0655,0x7D,0x04005FE8,"CriticalMoveHitCnt write"),
      (0x065C,0x7D,0x0400606F,"atk star clear"),(0x0663,0x7D,0x0400606F,"def star clear")
    ]
    for x in checks: tok(code,*x)

    branches=[
      (0x000C,0x3A,0x0012,"MatchMain present"),(0x0018,0x39,0x001E,"match end false"),(0x003C,0x3A,0x0042,"atk Player present"),(0x0048,0x3A,0x004E,"def Player present"),
      (0x0074,0x40,0x0086,"AnmReqType branch"),(0x00A9,0x3B,0x00B7,"slot 24"),(0x00B2,0x40,0x00C0,"slot 25"),
      (0x00CB,0x3A,0x0195,"looped audience skip"),(0x00DE,0x39,0x0195,"cheer zero audience skip"),
      (0x019C,0x40,0x01C3,"zone branch"),(0x01AC,0x3A,0x01C3,"looped counter skip"),
      (0x01CA,0x39,0x01DC,"critical false"),(0x01D7,0x38,0x04EA,"critical true join"),
      (0x03E7,0x39,0x0454,"local11 followup"),(0x0475,0x42,0x04C9,"SP positive"),
      (0x0484,0x39,0x04B5,"flags64"),(0x0492,0x39,0x04AE,"spSkillFlags16"),(0x049D,0x39,0x04A9,"rate5 false"),
      (0x04BD,0x40,0x04C9,"ringKind1"),(0x04CF,0x39,0x04EA,"isKO false"),(0x04DE,0x39,0x04EA,"post KO flags64"),
      (0x04F2,0x3E,0x0543,"bleedingRate positive"),(0x0503,0x39,0x0543,"bleeding rate check"),(0x0550,0x39,0x055C,"flags128"),
      (0x0567,0x3A,0x0598,"looped recovery skip"),(0x059F,0x3F,0x05BD,"weapon index"),(0x05FD,0x3B,0x060F,"finish wrestler id"),(0x0640,0x39,0x065A,"critical receipt")
    ]
    for x in branches: br(code,*x)

    for off,val,label in [
      (0x009E,1.0,"modifier 1"),(0x0101,2.0,"audience divisor"),(0x010B,61440.0,"threshold 61440"),(0x011A,57344.0,"threshold 57344"),(0x0129,53248.0,"threshold 53248"),(0x0138,49152.0,"threshold 49152"),
      (0x0204,0.0,"HP zero"),(0x022D,0.0,"atkPow HP zero"),(0x03D4,1.375,"SP factor"),(0x03F2,3.0,"followup factor 3"),(0x03F8,2.0,"followup divisor 2"),(0x040D,2048.0,"followup cap 2048"),(0x0430,4.0,"loop divisor 4"),(0x043A,8192.0,"followup cap 8192"),(0x0578,256.0,"special recovery"),(0x058E,1024.0,"critical recovery")
    ]: f32(code,off,val,label)

    if code[0x0481:0x0484]!=bytes([0x1F,0x40,0x5F]): raise ProofError("raw flags mask 64")
    if code[0x048F:0x0492]!=bytes([0x1F,0x10,0x5F]): raise ProofError("raw spSkillFlags mask 16")
    if code[0x0497]!=0x1B: raise ProofError("raw rate argument 5")
    if code[0x054A]!=0x20 or struct.unpack_from('<i',code,0x054B)[0]!=128 or code[0x054F]!=0x5F: raise ProofError("raw flags mask 128")
    if code[0x0668]!=0x2A: raise ProofError("ret")
    return {"dll_sha256":got,"code_size":len(code),"code_sha256":CODE_SHA}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--dll",required=True); ap.add_argument("--out"); a=ap.parse_args()
    try:
        r=verify(a.dll)
        if a.out: Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps(r,indent=2,sort_keys=True)); print("PROVE_APPLY_DAMAGE: PASS"); return 0
    except (OSError,ValueError,ProofError) as e:
        print("PROVE_APPLY_DAMAGE: FAIL"); print(str(e)); return 1
if __name__=="__main__": raise SystemExit(main())
