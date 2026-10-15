#!/usr/bin/env python3
"""FACT-0339: original ResourceManager 65,218 dependency-reference records. Read-only.

No Unity/game binaries are stored in Git. Requires the user-owned exact original
extensionless globalgamemanagers. No runtime/asset semantics are inferred.
"""
import argparse
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
WITNESS=ROOT/"canonical/witnesses/GGM-001/resource_manager_dependency_65218.summary.json"
def sha(data):return hashlib.sha256(data).hexdigest()
def ck(value,message):
    if not value:raise AssertionError(message)

def prove(path,w,lookup=None):
    source=Path(path).read_bytes()
    s=w["original_file"]
    ck(len(source)==s["bytes"] and sha(source)==s["sha256"],"GGM-001 original whole file identity")
    o=w["object"];obj=source[o["absolute_offset"]:o["absolute_offset"]+o["bytes"]]
    ck(len(obj)==o["bytes"] and sha(obj)==o["sha256"],"ResourceManager original whole object identity")
    pre=w["preceding_container"];ck(pre["start"]==0 and pre["end"]==2138488,"prior source table interval")
    ck(sha(obj[:pre["end"]])==pre["sha256"],"FACT-0338 index source SHA")
    p=4;named={}
    ck(struct.unpack_from("<I",obj,0)[0]==pre["rows"]==43941,"source name table count")
    for i in range(pre["rows"]):
        length=struct.unpack_from("<I",obj,p)[0];p+=4
        ck(length<=2048 and p+length<=pre["end"],"source name bounds")
        name=obj[p:p+length].decode("utf8");end=p+length;p=(end+3)&~3
        ck(obj[end:p]==bytes(p-end),"source name padding")
        fid,pid=struct.unpack_from("<iq",obj,p);p+=12
        ck(fid in (4,5) and pid>0,"source named reference values")
        named[(fid,pid)]=name
    ck(p==pre["end"] and len(named)==43941,"exact FACT-0338 table source boundary")
    d=w["dependent_records"]
    ck((d["start"],d["end"],d["bytes"])==(p,len(obj),len(obj)-p),"dependency region bounds")
    raw=obj[p:]
    ck(sha(raw)==d["sha256"],"original entire dependency region SHA")
    count=struct.unpack_from("<I",raw,0)[0]
    ck(count==d["record_count"]==65218,"dependency parent count")
    pos=d["first_record_offset"];ck(pos==4,"dependency initial offset")
    parents=set();dep_pairs=set();pc=Counter();dc=Counter();arity=Counter()
    named_parent=0;named_child=0;self_count=0;dep_total=0
    anchors={v["index"]:v for v in d["anchors"]}
    found=None
    for i in range(count):
        ck(pos+16<=len(raw),"parent record bounds")
        fid,pid,n=struct.unpack_from("<iqI",raw,pos);pos+=16
        parent=(fid,pid)
        ck(1<=fid<=5 and pid>0 and n>0,"source parent values and dependency arity")
        ck(pos+n*12<=len(raw),"dependency child array bounds")
        parents.add(parent);pc[str(fid)]+=1;arity[str(n)]+=1
        if parent in named:named_parent+=1
        first=[];is_self=False
        for j in range(n):
            cfi,cid=struct.unpack_from("<iq",raw,pos);pos+=12
            ck(1<=cfi<=5 and cid>0,"source child reference values")
            child=(cfi,cid)
            dc[str(cfi)]+=1;dep_pairs.add(child)
            if child in named:named_child+=1
            if child==parent:is_self=True
            if j<4:first.append([cfi,cid])
        self_count+=int(is_self)
        dep_total+=n
        if i in anchors:
            a=anchors[i]
            ck(a["parent"]==[fid,pid] and a["dependency_count"]==n and a["first_dependencies"]==first,
               "original anchored dependency "+str(i))
            if "resource_name" in a:ck(named.get(parent)==a["resource_name"],"FACT-0338 name joined anchor "+str(i))
        if lookup==parent:found={"index":i,"parent":[fid,pid],"resource_name":named.get(parent),"dependency_count":n,
                                 "note":"For full dependency enumeration use the original file; this lookup returns only the first four",
                                 "first_dependencies":first}
    ck(pos==len(raw)==d["parsed_to_end_offset"],"no unexplained original bytes")
    ck(dep_total==d["total_dependency_references"]==140029,"child occurrence count")
    ck(len(parents)==d["unique_parent_pairs"]==65218,"parent uniqueness")
    ck(len(dep_pairs)==d["unique_dependency_pairs"]==67564,"distinct child references")
    ck(dict(pc)==d["parent_file_id_counts"],"exact parent fileID counts")
    ck(dict(dc)==d["dependency_file_id_counts"],"exact child fileID counts")
    for k,v in d["arity_counts_selected"].items():ck(arity[k]==v,"source arity "+k)
    ck(max(map(int,arity))==d["maximum_dependency_count"]==168,"maximum dependency count")
    ck(named_parent==d["resource_index_parent_matches"]==19731,"source index parent join count")
    ck(named_child==d["resource_index_dependency_occurrence_matches"]==22107,"source index child join count")
    ck(self_count==d["self_reference_parent_records"]==9,"source self-reference records")
    return {"fact":"FACT-0339","source_proof":"PASS","parent_records":count,"dependency_occurrences":dep_total,
            "end_offset":pos,"named_parent_joins":named_parent,"named_child_occurrence_joins":named_child,
            "runtime_eligible":False},found

if __name__=="__main__":
    a=argparse.ArgumentParser()
    a.add_argument("--globalgamemanagers",required=True)
    a.add_argument("--lookup-parent",type=int,nargs=2,metavar=("FILE_ID","PATH_ID"))
    args=a.parse_args()
    w=json.loads(WITNESS.read_text(encoding="utf8"))
    ck(w["dataset_id"]=="UNITY_GGM_RESOURCE_MANAGER_DEPENDENCY_REFERENCES_65218_SOURCE_V1","witness identity")
    report,match=prove(args.globalgamemanagers,w,tuple(args.lookup_parent) if args.lookup_parent else None)
    print(json.dumps(report,sort_keys=True))
    if args.lookup_parent:print(json.dumps(match))
    print("PROVE_GGM_RESOURCE_MANAGER_DEPENDENCIES: PASS")
