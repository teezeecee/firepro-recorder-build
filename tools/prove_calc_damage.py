#!/usr/bin/env python3
import argparse,hashlib,json,struct
from pathlib import Path

DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x002AE858
CODE_SIZE=1007
CODE_SHA="058a61f95c9c59f9e5d3079b2c08a1420599dcec208152325c520e26a5983d04"

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

def branch_target(code,off): return off+5+struct.unpack_from("<i",code,off+1)[0]

def br(code,off,op,target,label):
    if code[off]!=op or branch_target(code,off)!=target: raise ProofError(label)

def f32(code,off,value,label):
    if code[off]!=0x22: raise ProofError(label+" opcode")
    got=struct.unpack_from("<f",code,off+1)[0]; want=struct.unpack("<f",struct.pack("<f",value))[0]
    if got!=want: raise ProofError(label+f" {got}")

def i4(code,off,value,label):
    if code[off]!=0x20 or struct.unpack_from("<i",code,off+1)[0]!=value: raise ProofError(label)

def verify(path):
    got=sha_path(path)
    if got!=DLL_SHA: raise ProofError("DLL SHA "+got)
    pe=Path(path).read_bytes(); code=mcode(pe,sections(pe),RVA)
    if len(code)!=CODE_SIZE or hashlib.sha256(code).hexdigest()!=CODE_SHA: raise ProofError("CalcDamage body")

    checks=[
      (0x0000,0x7E,0x04002AD1,"GlobalWork.inst"),(0x0005,0x7B,0x04002AD2,"MatchSetting"),
      (0x0011,0x6F,0x06005065,"atk GetPlObj"),(0x001D,0x6F,0x06005065,"def GetPlObj"),
      (0x0025,0x28,0x0A000006,"atk null equality"),(0x0031,0x28,0x0A000006,"def null equality"),
      (0x0042,0x7B,0x04005FA8,"animator"),(0x0047,0x7B,0x04005ED0,"CurrentSkill"),
      (0x005F,0x7B,0x040010A4,"atkParam main"),(0x0065,0x7B,0x04007C61,"atk selector main"),
      (0x0073,0x7B,0x040010A4,"atkParam sub"),(0x0079,0x7B,0x04007C62,"atk selector sub"),
      (0x0087,0x7B,0x040010A5,"defParam main"),(0x008D,0x7B,0x04007C63,"def selector main"),
      (0x009B,0x7B,0x040010A5,"defParam sub"),(0x00A1,0x7B,0x04007C64,"def selector sub"),
      (0x00C2,0x7B,0x04006058,"critical"),(0x00D9,0x7B,0x04006059,"special"),
      (0x00F0,0x7B,0x04005FBD,"spSkillFlags 8"),(0x00FD,0x7B,0x04005FBF,"HP high"),
      (0x0119,0x7B,0x04005FBD,"spSkillFlags 32"),(0x0127,0x7B,0x04005FBF,"HP low"),
      (0x0143,0x7B,0x0400600B,"weaponIdx"),(0x014F,0x7B,0x04005FBD,"atk flags 256"),(0x016C,0x7B,0x04005FBD,"def flags 256"),
      (0x01BA,0x7E,0x04005633,"mHpDamageTbl"),(0x01C0,0x7B,0x04005FBF,"def HP"),(0x01C5,0x28,0x0600495C,"GetHealth HP"),
      (0x01D2,0x7E,0x04005634,"mBpDamageTbl"),(0x01D8,0x7B,0x04005FC1,"atk BP"),(0x01DD,0x28,0x0600495C,"GetHealth BP"),
      (0x01FB,0x7E,0x04005635,"mDamageDecTbl leg"),(0x0201,0x7B,0x04005FC5,"HP_Leg"),(0x0206,0x28,0x0600495C,"GetHealth leg"),
      (0x0224,0x7E,0x04005635,"mDamageDecTbl waist"),(0x022A,0x7B,0x04005FC4,"HP_Waist"),(0x022F,0x28,0x0600495C,"GetHealth waist"),
      (0x024D,0x7E,0x04005635,"mDamageDecTbl arm"),(0x0253,0x7B,0x04005FC3,"HP_Arm"),(0x0258,0x28,0x0600495C,"GetHealth arm"),
      (0x0276,0x7E,0x04005635,"mDamageDecTbl neck"),(0x027C,0x7B,0x04005FC2,"HP_Neck"),(0x0281,0x28,0x0600495C,"GetHealth neck"),
      (0x028E,0x7E,0x04005637,"mDamageSizeTbl"),(0x0294,0x7B,0x04005FCA,"atk formSize"),(0x029A,0x7B,0x04005FCA,"def formSize"),(0x029F,0x28,0x0A0006E3,"size Get"),
      (0x02A8,0x7B,0x04007C63,"defPrm main #1"),(0x02B4,0x7B,0x04007C63,"defPrm main #2"),(0x02C0,0x7B,0x04005FEE,"Zone"),
      (0x02D5,0x7B,0x04005FC9,"UkeBonusTime"),(0x02EB,0x7B,0x04005FBD,"flags128"),(0x02FC,0x7B,0x0400605A,"isBleeding"),
      (0x0311,0x7B,0x04005FBD,"flags1"),(0x031E,0x7B,0x0400606F,"isStarPeformance"),(0x0329,0x7B,0x04005FBF,"HP star"),
      (0x0343,0x7B,0x04005FBD,"flags64"),(0x0351,0x7B,0x04005FE8,"CriticalMoveHitCnt"),(0x035D,0x7B,0x04006058,"isCriticalMove #2"),
      (0x0371,0x28,0x06004907,"MatchMain.GetInst"),(0x0377,0x28,0x0A00000F,"MatchMain inequality"),(0x0383,0x7E,0x0400576C,"MatchMain.inst"),(0x0388,0x7B,0x0400573F,"TagDamageRate"),
      (0x0391,0x7B,0x040057E6,"isS1Rule"),(0x039D,0x6F,0x06004ED8,"SetDownTime"),(0x03AD,0x28,0x06005266,"IsS1Waza"),
      (0x03B9,0x7D,0x04006074,"isS1MoveRecieved true"),(0x03C0,0x7E,0x04005657,"FightStyleParam"),(0x03CB,0x7B,0x0400108B,"fightStyle"),(0x03D1,0x7B,0x0400566F,"S1Correct"),(0x03E0,0x7D,0x04006074,"isS1MoveRecieved false")
    ]
    for x in checks: tok(code,*x)

    branches=[
      (0x002A,0x3A,0x003B,"atk null"),(0x0036,0x39,0x0041,"def present"),(0x004E,0x3A,0x0059,"skill present"),
      (0x00C7,0x39,0x00D8,"critical false"),(0x00DE,0x39,0x00EF,"special false"),(0x00F7,0x39,0x0118,"mask8"),(0x0107,0x43,0x0118,"HP high gate"),
      (0x0121,0x39,0x0142,"mask32"),(0x0131,0x41,0x0142,"HP low gate"),(0x0149,0x3F,0x0188,"weapon index"),(0x015A,0x39,0x016B,"atk mask256"),(0x0177,0x39,0x0188,"def mask256"),
      (0x01F4,0x39,0x0211,"mask512"),(0x021D,0x39,0x023A,"mask1024"),(0x0246,0x39,0x0263,"mask2048"),(0x026F,0x39,0x028C,"mask4096"),
      (0x02AE,0x3B,0x02BF,"defPrm 2"),(0x02BA,0x40,0x02D4,"defPrm 5"),(0x02C5,0x39,0x02D4,"zone"),(0x02DB,0x3E,0x02EA,"uke time"),
      (0x02F6,0x39,0x0310,"mask128"),(0x0301,0x39,0x0310,"bleeding"),(0x0318,0x39,0x0342,"mask1"),(0x0323,0x39,0x0342,"star"),(0x0333,0x41,0x0342,"star HP"),
      (0x034B,0x39,0x0371,"mask64"),(0x0357,0x3C,0x0371,"critical count"),(0x0362,0x39,0x0371,"critical state"),(0x037C,0x39,0x0390,"MatchMain absent"),
      (0x0396,0x39,0x03EC,"S1 false"),(0x03B2,0x39,0x03DE,"S1Waza false"),(0x03D9,0x38,0x03EC,"S1 true join")
    ]
    for x in branches: br(code,*x)

    if code[0x00AB]!=0x19 or code[0x00B1]!=0x19 or code[0x00B7]!=0x19 or code[0x00BD]!=0x19: raise ProofError("base +3")
    if code[0x00CE]!=0x18 or code[0x00D4]!=0x18: raise ProofError("critical +2")
    if code[0x00E5]!=0x17 or code[0x00EB]!=0x17: raise ProofError("special +1")
    if code[0x00F5]!=0x1E: raise ProofError("mask 8")
    if code[0x011E:0x0120]!=bytes([0x1F,0x20]): raise ProofError("mask 32")
    i4(code,0x0154,256,"atk mask 256"); i4(code,0x0171,256,"def mask 256")
    i4(code,0x01EE,512,"mask 512"); i4(code,0x0217,1024,"mask 1024"); i4(code,0x0240,2048,"mask 2048"); i4(code,0x0269,4096,"mask 4096")
    i4(code,0x02F0,128,"mask 128")
    if code[0x0316]!=0x17: raise ProofError("mask 1")
    if code[0x0348:0x034A]!=bytes([0x1F,0x40]): raise ProofError("mask 64")

    for off,val,label in [
      (0x0102,45875.0,"HP threshold high"),(0x012C,1280.0,"HP threshold low"),
      (0x018B,3.0,"atk main factor"),(0x0198,3.0,"def main factor"),(0x01A3,64.0,"base plus64"),(0x01A9,4.0,"base times4"),
      (0x02CC,1.125,"zone factor"),(0x02E2,1.2000000476837158,"uke factor"),(0x0308,1.100000023841858,"bleeding factor"),
      (0x032E,2560.0,"star HP threshold"),(0x033A,1.2000000476837158,"star factor"),(0x0369,2.5,"critical factor"),(0x03E5,0.0,"S1 false zero")
    ]: f32(code,off,val,label)

    if code[0x003B]!=0x22 or struct.unpack_from("<f",code,0x003C)[0]!=0.0 or code[0x0040]!=0x2A: raise ProofError("null return zero")
    if code[0x0053]!=0x22 or struct.unpack_from("<f",code,0x0054)[0]!=0.0 or code[0x0058]!=0x2A: raise ProofError("skill return zero")
    if code[0x03EE]!=0x2A: raise ProofError("ret")
    return {"dll_sha256":got,"code_size":len(code),"code_sha256":CODE_SHA}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--dll",required=True); ap.add_argument("--out"); a=ap.parse_args()
    try:
        r=verify(a.dll)
        if a.out: Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps(r,indent=2,sort_keys=True)); print("PROVE_CALC_DAMAGE: PASS"); return 0
    except (OSError,ValueError,ProofError) as e:
        print("PROVE_CALC_DAMAGE: FAIL"); print(str(e)); return 1
if __name__=="__main__": raise SystemExit(main())
