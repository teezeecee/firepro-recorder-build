#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from collections import Counter
from pathlib import Path

DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
R6_SHA="93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d"
EVENT_SHA="79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd"
RVA=0x002DB718
CODE_SIZE=364
CODE_SHA="ba7c6da321b3f5632756459a8a788abd92609da056981078f5fc7bbe04824085"
WITNESS_SHA="269d9efa1f0bb19e53a398b53c395033084ddc30b8ea6718514911e45697f692"

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

def branch_target(code,off):
    return off+5+struct.unpack_from("<i",code,off+1)[0]

def verify_dll(path):
    got=sha_path(path)
    if got!=DLL_SHA: raise ProofError("DLL SHA "+got)
    pe=Path(path).read_bytes(); code=mcode(pe,sections(pe),RVA)
    if len(code)!=CODE_SIZE or hashlib.sha256(code).hexdigest()!=CODE_SHA: raise ProofError("PlayAnimationSE body")

    checks=[
      (0x0001,0x28,0x06004E7C,"GetCurrentFormDispInfo"),
      (0x0008,0x7B,0x04007CE2,"seID"),
      (0x0016,0x28,0x06005273,"GetMatchSEParam"),
      (0x001D,0x7B,0x04008668,"shakeMatLevel"),
      (0x0051,0x6F,0x060050E2,"ShakeMat"),
      (0x008E,0x6F,0x06004EB4,"PlayWrestlerVoice"),
      (0x0098,0x28,0x06006AC0,"WeaponMan.GetInst"),
      (0x00D2,0x6F,0x06006ACB,"FindWeapon"),
      (0x00E9,0x6F,0x06004EE0,"EquipWeapon"),
      (0x00F4,0x7B,0x0400602F,"plCont_AI"),
      (0x00FA,0x6F,0x06004FAC,"SetAIActCounter"),
      (0x0110,0x6F,0x06004F32,"ReqRopeAction"),
      (0x0120,0x6F,0x06004F0A,"Process_ShakeCage"),
      (0x012A,0x6F,0x0600510A,"ShakeCage"),
      (0x013A,0x6F,0x06004EDE,"ThrowInWeapon"),
      (0x014A,0x6F,0x06004EB5,"PlayStepSE"),
      (0x0161,0x28,0x06004970,"PlayMatchSE")
    ]
    for x in checks: tok(code,*x)

    if code[0x0060]!=0x45: raise ProofError("switch opcode")
    n=struct.unpack_from("<I",code,0x0061)[0]
    if n!=4: raise ProofError("switch count")
    base=0x0065+4*n
    ds=struct.unpack_from("<iiii",code,0x0065)
    targets=[base+d for d in ds]
    if targets!=[0x0134,0x011A,0x0104,0x0098]: raise ProofError("switch targets")
    if branch_target(code,0x0077)!=0x0088 or branch_target(code,0x007E)!=0x0144:
        raise ProofError("1/6 dispatch")
    if code[0x0056]!=0x22 or struct.unpack_from("<f",code,0x0057)[0]!=1.0: raise ProofError("volume constant")
    if code[0x00CD]!=0x22 or struct.unpack_from("<f",code,0x00CE)[0]!=1.0: raise ProofError("FindWeapon radius")
    if code[0x010A]!=0x1A or code[0x010B]!=0x22 or struct.unpack_from("<f",code,0x010C)[0]!=0.5:
        raise ProofError("ReqRopeAction constants")
    needle=bytes([0x6F])+struct.pack("<I",0x06004EE0)
    if code.count(needle)!=1: raise ProofError("EquipWeapon callsite count")
    if code[0x016B]!=0x2A: raise ProofError("ret")
    return {"dll_sha256":got,"code_size":len(code),"code_sha256":CODE_SHA,"switch_targets":targets}

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
        stack=[]; records=[]; pre=post=0; parents=Counter(); owners=Counter(); direct=Counter(); rel=Counter(); argcounts=Counter()
        with z.open(name) as raw:
            rd=csv.DictReader(io.TextIOWrapper(raw,encoding="utf-8-sig",newline=""),delimiter="\t")
            for line,row in enumerate(rd,start=2):
                ph=row["phase"]
                if ph=="MARK": continue
                if ph=="PRE":
                    parent=stack[-1] if stack else None
                    node={"line":line,"row":dict(row),"children":[],"parent":parent,"post":None,"post_line":None}
                    if parent: parent["children"].append(node)
                    stack.append(node)
                    if row["method"]=="FormAnimator.PlayAnimationSE":
                        pre+=1; parents[parent["row"]["method"] if parent else "ROOT"]+=1
                elif ph=="POST":
                    if not stack: raise ProofError("POST without PRE")
                    node=stack.pop()
                    if node["row"]["method"]!=row["method"] or node["row"]["instance"]!=row["instance"]: raise ProofError("non-LIFO")
                    node["post"]=dict(row); node["post_line"]=line
                    if row["method"]!="FormAnimator.PlayAnimationSE": continue
                    post+=1; owners[row["owner_slot"]]+=1
                    for ch in node["children"]: direct[ch["row"]["method"]]+=1
                    eq=[x for x in node["children"] if x["row"]["method"]=="Player.EquipWeapon"]
                    if len(eq)>1: raise ProofError("multiple EquipWeapon children")
                    if eq:
                        e=eq[0]
                        rel["parent_pre_weapon_minus1"]+=node["row"]["weaponIdx"]=="-1"
                        rel["child_pre_weapon_minus1"]+=e["row"]["weaponIdx"]=="-1"
                        rel["child_owner_same"]+=e["row"]["owner_slot"]==node["row"]["owner_slot"]
                        rel["child_arg_post_weapon"]+=e["row"]["args"]==e["post"]["weaponIdx"]
                        rel["parent_post_weapon_child_arg"]+=row["weaponIdx"]==e["row"]["args"]
                        argcounts[e["row"]["args"]]+=1
                        opt=(e["line"],e["post_line"],e["row"]["args"],e["row"]["weaponIdx"],e["post"]["weaponIdx"])
                    else:
                        opt=(0,0,"","","")
                    records.append((node["line"],line,node["row"]["owner_slot"],node["row"]["instance"],node["row"]["state"],node["row"]["BasicSkillID"],node["row"]["SkillSlotID"],node["row"]["ResolvedSkillID"],node["row"]["bank"],node["row"]["AnmHostPlayer"],node["row"]["weaponIdx"],row["weaponIdx"],*opt))
        if stack: raise ProofError("unterminated trace")

    if pre!=45458 or post!=45458 or len(records)!=45458: raise ProofError("PlayAnimationSE count")
    if parents!=Counter({"ROOT":45458}): raise ProofError("parent counts")
    if owners!=Counter({"7":6596,"3":6287,"5":5703,"2":5481,"4":5453,"0":5354,"6":5307,"1":5277}): raise ProofError("owner counts")
    if direct!=Counter({"Player.EquipWeapon":11}): raise ProofError("direct children")
    for k in ("parent_pre_weapon_minus1","child_pre_weapon_minus1","child_owner_same","child_arg_post_weapon","parent_post_weapon_child_arg"):
        if rel[k]!=11: raise ProofError(f"{k}: {rel[k]}")
    if argcounts!=Counter({"3":3,"7":2,"5":2,"2":2,"0":1,"6":1}): raise ProofError("EquipWeapon args")
    witness="".join("\t".join(map(str,r))+"\n" for r in records).encode("utf-8")
    wsha=hashlib.sha256(witness).hexdigest()
    if len(witness)!=4314316 or wsha!=WITNESS_SHA: raise ProofError(f"witness {len(witness)} {wsha}")
    return {"r6_sha256":got,"event_trace_sha256":esha,"record_count":len(records),"equip_weapon_child_count":11,"witness_byte_count":len(witness),"witness_sha256":wsha}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--dll",required=True); ap.add_argument("--r6",required=True); ap.add_argument("--out"); a=ap.parse_args()
    try:
        result={"dll":verify_dll(a.dll),"r6":verify_r6(a.r6)}
        if a.out: Path(a.out).write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps(result,indent=2,sort_keys=True)); print("PROVE_PLAY_ANIMATION_SE: PASS"); return 0
    except (OSError,ValueError,KeyError,zipfile.BadZipFile,ProofError) as e:
        print("PROVE_PLAY_ANIMATION_SE: FAIL"); print(str(e)); return 1
if __name__=="__main__": raise SystemExit(main())
