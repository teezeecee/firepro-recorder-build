#!/usr/bin/env python3
import argparse
import csv
import hashlib
import io
import json
import struct
import zipfile
from collections import Counter
from pathlib import Path

DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
R6_SHA="93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d"
EVENT_SHA="79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd"
START_RVA=0x002DAA54
START_SIZE=328
START_SHA="aa80c075f247570daf6d74d8d5d7140022160f98a0d3b6233cd7268236a69c94"
SLOT_RVA=0x002DA296
SLOT_SIZE=38
SLOT_SHA="091053ea365ad855884dd6f93314dd5e1de23bda1c848c291fd2df4d8776d0b2"
WITNESS_SHA="bdc1ebb858f74602c3c364ce5ca695f7663380703770237421e50e872783f048"

class ProofError(RuntimeError):
    pass

def sha_path(path):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()

def sha_stream(f):
    h=hashlib.sha256()
    for chunk in iter(lambda:f.read(1024*1024),b""):
        h.update(chunk)
    return h.hexdigest()

def sections(pe):
    peoff=struct.unpack_from("<I",pe,0x3C)[0]
    if pe[peoff:peoff+4]!=b"PE\0\0":
        raise ProofError("not PE")
    nsec=struct.unpack_from("<H",pe,peoff+6)[0]
    optsz=struct.unpack_from("<H",pe,peoff+20)[0]
    base=peoff+24+optsz
    out=[]
    for i in range(nsec):
        o=base+i*40
        vsize,va,rawsize,rawptr=struct.unpack_from("<IIII",pe,o+8)
        out.append((va,vsize,rawptr,rawsize))
    return out

def rva_off(pe,ss,rva):
    for va,vsize,rawptr,rawsize in ss:
        if va<=rva<va+max(vsize,rawsize):
            return rawptr+rva-va
    raise ProofError(f"RVA not mapped: {rva:#x}")

def method_code(pe,ss,rva):
    off=rva_off(pe,ss,rva)
    b=pe[off]
    if b&3==2:
        header=1; size=b>>2
    elif b&3==3:
        flags_size=struct.unpack_from("<H",pe,off)[0]
        header=(flags_size>>12)*4
        size=struct.unpack_from("<I",pe,off+4)[0]
    else:
        raise ProofError("bad IL header")
    return pe[off+header:off+header+size]

def token(code,off,opcode,value,label):
    if code[off]!=opcode or struct.unpack_from("<I",code,off+1)[0]!=value:
        raise ProofError(label)

def branch_target(code,off):
    return off+5+struct.unpack_from("<i",code,off+1)[0]

def verify_dll(path):
    got=sha_path(path)
    if got!=DLL_SHA:
        raise ProofError("DLL SHA "+got)
    pe=Path(path).read_bytes()
    ss=sections(pe)
    start=method_code(pe,ss,START_RVA)
    slot=method_code(pe,ss,SLOT_RVA)
    if len(start)!=START_SIZE or hashlib.sha256(start).hexdigest()!=START_SHA:
        raise ProofError("StartAnm body")
    if len(slot)!=SLOT_SIZE or hashlib.sha256(slot).hexdigest()!=SLOT_SHA:
        raise ProofError("StartSlotAnm_Immediately body")

    checks=[
        (0x000D,0x7D,0x04005ED1,"CurrentAnmIdx"),
        (0x0014,0x7D,0x04005EEC,"reqAnmInit"),
        (0x001B,0x7D,0x04005EEA,"isAnmBoot"),
        (0x0022,0x7D,0x04005ED5,"currentFormIdx"),
        (0x002E,0x7B,0x04005FA6,"PlIdx"),
        (0x0033,0x7D,0x04005ED7,"AnmHostPlayer"),
        (0x003F,0x7B,0x04007C53,"SkillData.anmType"),
        (0x0044,0x7D,0x04005EDC,"FormAnimator.anmType"),
        (0x0055,0x7B,0x04007C7A,"SkillData.anmData"),
        (0x0061,0x7B,0x04007C97,"terrainColType"),
        (0x0066,0x7D,0x04006004,"TerrainColType"),
        (0x007E,0x7B,0x04007C9E,"anmEndState"),
        (0x0083,0x7D,0x04005EE2,"AnimeEnd"),
        (0x0089,0x7B,0x04006468,"ringKind"),
        (0x00C3,0x7B,0x04005FEE,"Zone"),
        (0x013C,0x7D,0x0400604F,"isIgnoreTerrainCol"),
        (0x0142,0x28,0x06004E78,"PreprocessEachAnm"),
    ]
    for c in checks:
        token(start,*c)

    if start[0x000C]!=0x03 or start[0x0013]!=0x16 or start[0x001A]!=0x17 or start[0x0021]!=0x15:
        raise ProofError("StartAnm initial constants/arg")
    branches=[
        (0x008E,0x17,0x008F,0x3B,0x00A0),
        (0x009A,0x19,0x009B,0x40,0x00AC),
        (0x00B7,0x1A,0x00B8,0x3B,0x0125),
        (0x00C8,0x19,0x00C9,0x3B,0x00DF),
        (0x00D9,0x17,0x00DA,0x40,0x00EB),
        (0x00F1,0x18,0x00F2,0x40,0x0125),
        (0x0102,0x17,0x0103,0x3B,0x0119),
        (0x0113,0x19,0x0114,0x40,0x0125),
    ]
    for const_off,const_op,br_off,br_op,target in branches:
        if start[const_off]!=const_op or start[br_off]!=br_op or branch_target(start,br_off)!=target:
            raise ProofError(f"numeric filter branch {br_off:#x}")
    if start[0x0130]!=0x39 or branch_target(start,0x0130)!=0x0141 or start[0x013B]!=0x17:
        raise ProofError("final terrain/isIgnore branch")

    if slot[0x001E]!=0x02 or slot[0x001F]!=0x04:
        raise ProofError("StartSlot receiver/arg2")
    token(slot,0x0020,0x28,0x06004E75,"StartSlot->StartAnm")
    return {"dll_sha256":got,"start_anm_code_sha256":START_SHA,"start_slot_code_sha256":SLOT_SHA}

def verify_r6(path):
    got=sha_path(path)
    if got!=R6_SHA:
        raise ProofError("R6 SHA "+got)
    with zipfile.ZipFile(path,"r") as zf:
        bad=zf.testzip()
        if bad is not None:
            raise ProofError("ZIP CRC "+bad)
        names=[n for n in zf.namelist() if Path(n).name=="event_trace.tsv"]
        if len(names)!=1:
            raise ProofError("event_trace count")
        name=names[0]
        with zf.open(name) as f:
            esha=sha_stream(f)
        if esha!=EVENT_SHA:
            raise ProofError("event SHA "+esha)

        stack=[]
        records=[]
        pre_count=post_count=0
        parents=Counter()
        args=Counter()
        by_parent={}
        pre_host_eq=post_host_eq=changed_host=0
        slot_bridge=0
        direct_children=Counter()

        with zf.open(name) as raw:
            rd=csv.DictReader(io.TextIOWrapper(raw,encoding="utf-8-sig",newline=""),delimiter="\t")
            for line,row in enumerate(rd,start=2):
                if row["phase"]=="PRE":
                    node={"line":line,"row":dict(row),"children":[],"parent":stack[-1] if stack else None}
                    if stack:
                        stack[-1]["children"].append(node)
                    stack.append(node)
                    if row["method"]=="FormAnimator.StartAnm":
                        pre_count+=1
                elif row["phase"]=="POST":
                    if not stack:
                        raise ProofError("POST without PRE")
                    node=stack.pop()
                    if node["row"]["method"]!=row["method"] or node["row"]["instance"]!=row["instance"]:
                        raise ProofError("non-LIFO trace")
                    if row["method"]!="FormAnimator.StartAnm":
                        continue
                    post_count+=1
                    pre=node["row"]
                    parent=node["parent"]
                    pm=parent["row"]["method"] if parent else "ROOT"
                    pline=parent["line"] if parent else 0
                    parents[pm]+=1
                    args[pre["args"]]+=1
                    by_parent.setdefault(pm,Counter())[pre["args"]]+=1
                    pre_host_eq+=int(pre["AnmHostPlayer"]==pre["owner_slot"])
                    post_host_eq+=int(row["AnmHostPlayer"]==row["owner_slot"])
                    changed_host+=int(pre["AnmHostPlayer"]!=row["AnmHostPlayer"])
                    if pm=="FormAnimator.StartSlotAnm_Immediately":
                        pargs=[x.strip() for x in parent["row"]["args"].split("|")]
                        if len(pargs)!=4 or pargs[1]!=pre["args"]:
                            raise ProofError("StartSlot raw bridge")
                        slot_bridge+=1
                    change_line=0
                    for child in node["children"]:
                        direct_children[child["row"]["method"]]+=1
                        if child["row"]["method"]=="Player.ChangeState":
                            if change_line:
                                raise ProofError("multiple ChangeState children")
                            change_line=child["line"]
                    records.append((node["line"],line,pm,pline,pre["args"],pre["owner_slot"],pre["AnmHostPlayer"],row["AnmHostPlayer"],change_line))
        if stack:
            raise ProofError("unterminated trace")

    if pre_count!=5333 or post_count!=5333 or len(records)!=5333:
        raise ProofError("StartAnm count")
    if parents!=Counter({"FormAnimator.InitAnimation":5288,"FormAnimator.StartSlotAnm_Immediately":36,"ROOT":9}):
        raise ProofError("parent counts")
    if args!=Counter({"0":5292,"4":26,"1":9,"8":4,"2":2}):
        raise ProofError("arg counts")
    expected={
        "FormAnimator.InitAnimation":Counter({"0":5288}),
        "FormAnimator.StartSlotAnm_Immediately":Counter({"4":26,"8":4,"2":2,"0":4}),
        "ROOT":Counter({"1":9}),
    }
    if by_parent!=expected:
        raise ProofError("args by parent")
    if (pre_host_eq,post_host_eq,changed_host)!=(5089,5333,244):
        raise ProofError("host-field counts")
    if slot_bridge!=36:
        raise ProofError("StartSlot bridge count")
    if direct_children!=Counter({"Player.ChangeState":2}):
        raise ProofError("direct child counts")

    witness="".join("\t".join(map(str,r))+"\n" for r in records).encode("ascii")
    wsha=hashlib.sha256(witness).hexdigest()
    if len(witness)!=307108 or wsha!=WITNESS_SHA:
        raise ProofError(f"witness {len(witness)} {wsha}")
    return {"r6_sha256":got,"event_trace_sha256":EVENT_SHA,"record_count":len(records),"witness_byte_count":len(witness),"witness_sha256":wsha}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--dll",required=True)
    ap.add_argument("--r6",required=True)
    ap.add_argument("--out")
    a=ap.parse_args()
    try:
        result={"dll":verify_dll(a.dll),"r6":verify_r6(a.r6)}
        if a.out:
            Path(a.out).write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps(result,indent=2,sort_keys=True))
        print("PROVE_START_ANM_CLOSURE: PASS")
        return 0
    except (OSError,ValueError,KeyError,zipfile.BadZipFile,ProofError) as e:
        print("PROVE_START_ANM_CLOSURE: FAIL")
        print(str(e))
        return 1

if __name__=="__main__":
    raise SystemExit(main())
