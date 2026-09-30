#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from collections import Counter
from pathlib import Path

DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
R6_SHA="93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d"
EVENT_SHA="79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd"
RVA=0x002D9FB8
CODE_SIZE=722
CODE_SHA="c4c109776883423823725f70612e1a7cd7e61367d7680c206bcc838470cf88ef"
WITNESS_SHA="788630dfe7eaf98e3dfab73ba07c0e9591f9f9a4b97d842614a2b9327fc69f04"

class ProofError(RuntimeError): pass

def sha_path(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for c in iter(lambda:f.read(1024*1024),b""): h.update(c)
    return h.hexdigest()

def sha_stream(f):
    h=hashlib.sha256()
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

def verify_dll(path):
    got=sha_path(path)
    if got!=DLL_SHA: raise ProofError("DLL SHA "+got)
    pe=Path(path).read_bytes(); ss=sections(pe); code=mcode(pe,ss,RVA)
    if len(code)!=CODE_SIZE or hashlib.sha256(code).hexdigest()!=CODE_SHA: raise ProofError("ReqSlotAnm body")
    checks=[
        (0x0000,0x28,0x06004907,"MatchMain.GetInst"),
        (0x0025,0x28,0x0600116D,"SkillSlotDataMan.GetSkillSlotData"),
        (0x004D,0x28,0x06004963,"direction reverse host"),
        (0x005D,0x6F,0x06005065,"PlayerMan.GetPlObj"),
        (0x0079,0x28,0x06004963,"direction reverse def"),
        (0x00CB,0x6F,0x06004EAE,"Player.ChangeState"),
        (0x00FD,0x6F,0x06006AC8,"WeaponMan.GetWeaponObj"),
        (0x0121,0x6F,0x06006ACF,"WeaponMan.GetWeaponAnm"),
        (0x012D,0x28,0x06004E6F,"ReqBasicAnm"),
        (0x0158,0x7D,0x04005ECF,"AnmReqType"),
        (0x015F,0x7D,0x04005ED9,"SkillSlotID"),
        (0x0165,0x28,0x06004E6C,"InitAnmWork"),
        (0x0184,0x6F,0x06004F18,"ConsumeBreath_SlotSkill"),
        (0x01FE,0x6F,0x06004EB7,"PreserveAttackMove_OkiteYaburi"),
        (0x021A,0x6F,0x06004EB6,"PreserveAttackMove_EquippedSkill"),
        (0x0226,0x6F,0x06004EB1,"SetLastSkill"),
        (0x025A,0x6F,0x06004EB2,"GetSkillData_Equip"),
        (0x0289,0x6F,0x060048DE,"MatchEvaluation.EvaluateSkill"),
        (0x02B0,0x6F,0x06004EDC,"SetLastDamage"),
        (0x02CC,0x6F,0x06004ED8,"SetDownTime"),
    ]
    for x in checks: tok(code,*x)
    if code[0x00C9:0x00CB]!=bytes([0x1F,10]): raise ProofError("ChangeState literal")
    if code[0x012B]!=0x16 or code[0x012C]!=0x15: raise ProofError("weapon ReqBasic constants")
    if code[0x0157]!=0x17: raise ProofError("AnmReqType literal")
    return {"dll_sha256":got,"code_size":len(code),"code_sha256":CODE_SHA}

def verify_r6(path):
    got=sha_path(path)
    if got!=R6_SHA: raise ProofError("R6 SHA "+got)
    with zipfile.ZipFile(path) as z:
        bad=z.testzip()
        if bad: raise ProofError("ZIP CRC "+bad)
        names=[n for n in z.namelist() if Path(n).name=="event_trace.tsv"]
        if len(names)!=1: raise ProofError("event_trace count")
        name=names[0]
        with z.open(name) as f: esha=sha_stream(f)
        if esha!=EVENT_SHA: raise ProofError("event SHA "+esha)
        stack=[]; records=[]; pre=post=0; parents=Counter(); rev=Counter(); defs=Counter(); atk=Counter()
        weapon=0; nonweapon=0; root_weapon=0; nonweapon_widx_nonneg=0
        relations=Counter()
        with z.open(name) as raw:
            rd=csv.DictReader(io.TextIOWrapper(raw,encoding="utf-8-sig",newline=""),delimiter="\t")
            for line,row in enumerate(rd,start=2):
                ph=row["phase"]
                if ph=="PRE":
                    node={"line":line,"row":dict(row),"children":[],"parent":stack[-1] if stack else None,"post":None,"post_line":None}
                    if stack: stack[-1]["children"].append(node)
                    stack.append(node)
                    if row["method"]=="FormAnimator.ReqSlotAnm": pre+=1
                elif ph=="POST":
                    if not stack: raise ProofError("POST without PRE")
                    node=stack.pop()
                    if node["row"]["method"]!=row["method"] or node["row"]["instance"]!=row["instance"]: raise ProofError("non-LIFO")
                    node["post"]=dict(row); node["post_line"]=line
                    if row["method"]!="FormAnimator.ReqSlotAnm": continue
                    post+=1; r=node["row"]; p=node["parent"]; pm=p["row"]["method"] if p else "ROOT"; pl=p["line"] if p else 0
                    parents[pm]+=1
                    a=[x.strip() for x in r["args"].split("|")]
                    if len(a)!=4: raise ProofError("args")
                    rev[a[1]]+=1; defs[a[2]]+=1; atk[a[3]]+=1
                    ch=[x for x in node["children"] if x["row"]["method"]=="Player.ChangeState"]
                    rb=[x for x in node["children"] if x["row"]["method"]=="FormAnimator.ReqBasicAnm"]
                    if len(ch)!=1 or len(rb)>1: raise ProofError("children")
                    c=ch[0]
                    if c["row"]["args"]!="NormalAnm" or c["row"]["owner_slot"]!=r["owner_slot"]: raise ProofError("ChangeState relation")
                    q=rb[0] if rb else None
                    if q:
                        weapon+=1
                        if pm=="ROOT": root_weapon+=1
                        qa=[x.strip() for x in q["row"]["args"].split("|")]
                        if len(qa)!=3 or qa[1]!="False" or qa[2]!="-1" or q["row"]["owner_slot"]!=r["owner_slot"]: raise ProofError("weapon ReqBasic")
                        if int(r["weaponIdx"])<0: raise ProofError("weaponIdx negative on weapon branch")
                        if row["SkillSlotID"]==a[0]: raise ProofError("weapon branch unexpectedly wrote SkillSlotID")
                    else:
                        nonweapon+=1
                        if row["SkillSlotID"]!=a[0]: raise ProofError("ordinary SkillSlotID")
                        if int(r["weaponIdx"])>=0: nonweapon_widx_nonneg+=1
                    if a[1]=="False":
                        if a[2]!="-1": raise ProofError("rev false def")
                    else:
                        if a[2]!=r["target"]: raise ProofError("rev true def")
                    if pm=="FormAnimator.StartOpponentAnm" and (a[1],a[2],a[3])!=("False","-1","False"): raise ProofError("StartOpponent pattern")
                    if pm=="FormAnimator.StartSlotAnm_Immediately" and not (a[1]=="True" and a[2]==r["target"] and a[3]=="True"): raise ProofError("StartSlot pattern")
                    if pm=="ROOT" and a[3]!="True": raise ProofError("ROOT atk_side")
                    records.append((node["line"],line,pm,pl,c["line"],c["post_line"],q["line"] if q else 0,q["post_line"] if q else 0,*a,r["owner_slot"],r["target"],r["weaponIdx"],row["SkillSlotID"],row["ResolvedSkillID"],row["ResolvedSkillSource"]))
        if stack: raise ProofError("unterminated trace")
    if pre!=717 or post!=717 or len(records)!=717: raise ProofError("call count")
    if parents!=Counter({"ROOT":419,"FormAnimator.StartOpponentAnm":262,"FormAnimator.StartSlotAnm_Immediately":36}): raise ProofError("parents")
    if rev!=Counter({"False":578,"True":139}) or atk!=Counter({"True":455,"False":262}): raise ProofError("arg counts")
    if weapon!=14 or nonweapon!=703 or root_weapon!=14 or nonweapon_widx_nonneg!=2: raise ProofError("weapon split")
    witness="".join("\t".join(map(str,r))+"\n" for r in records).encode("ascii")
    wsha=hashlib.sha256(witness).hexdigest()
    if len(witness)!=89986 or wsha!=WITNESS_SHA: raise ProofError(f"witness {len(witness)} {wsha}")
    return {"r6_sha256":got,"event_trace_sha256":esha,"record_count":len(records),"weapon_override_count":weapon,"witness_byte_count":len(witness),"witness_sha256":wsha}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--dll",required=True); ap.add_argument("--r6",required=True); ap.add_argument("--out"); a=ap.parse_args()
    try:
        result={"dll":verify_dll(a.dll),"r6":verify_r6(a.r6)}
        if a.out: Path(a.out).write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps(result,indent=2,sort_keys=True)); print("PROVE_REQ_SLOT_ANM_CLOSURE: PASS"); return 0
    except (OSError,ValueError,KeyError,zipfile.BadZipFile,ProofError) as e:
        print("PROVE_REQ_SLOT_ANM_CLOSURE: FAIL"); print(str(e)); return 1
if __name__=="__main__": raise SystemExit(main())
