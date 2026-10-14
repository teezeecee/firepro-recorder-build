#!/usr/bin/env python3
"""FACT-0328: original Unity v17 ClassID126 PathID16 NavMeshAreas source proof."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/GGM-001/navmesh_areas_full.summary.json"
def digest(b): return hashlib.sha256(b).hexdigest()
def ck(cond,msg):
    if not cond: raise AssertionError(msg)
def prove(source,w):
    b=Path(source).read_bytes();f=w["original_file"];o=w["object"];a=w["areas"];tail=w["remaining_raw"]
    ck((len(b),digest(b))==(f["bytes"],f["sha256"]),"full original binary")
    ck(struct.unpack_from(">IIIII",b,0)==(1379,len(b),17,4096,0),"Unity original header")
    p=20;e=b.index(b"\0",p);ck(b[p:e]==b"5.6.5p3","engine version");p=e+1
    platform,tree,nt=struct.unpack_from("<iBI",b,p);p+=9
    ck((platform,tree,nt)==(5,0,20),"Unity type count")
    types=[]
    for i in range(nt):
        cls,removed,script=struct.unpack_from("<iBh",b,p);p+=23
        ck((removed,script)==(0,-1),"type metadata")
        types.append(cls)
    ck(types[o["type_index"]]==o["class_id"]==126,"ClassID126")
    n=struct.unpack_from("<I",b,p)[0];p=(p+4+3)&~3;ck(n==20,"object table count")
    rows={}
    for i in range(n):
        pathid,offset,size,index=struct.unpack_from("<qIII",b,p);p+=20
        ck(index<nt and 4096+offset+size<=len(b),"object bounds")
        rows[pathid]=(offset,size,index)
    ck(rows[o["path_id"]]==(o["relative_offset"],o["bytes"],o["type_index"]),"original object info")
    start=4096+o["relative_offset"];end=start+o["bytes"]
    ck(start==o["absolute_offset"]==0x4C51D8 and end==0x4C5340,"absolute span")
    data=b[start:end];ck((len(data),digest(data))==(360,o["sha256"]),"full object hash")
    p=0;count=struct.unpack_from("<I",data,p)[0];p+=4
    ck(count==a["count"]==32 and len(a["entries"])==32,"area slot count")
    for i,item in enumerate(a["entries"]):
        ck(p==item["start_offset"] and i==item["index"],"area entry start/index")
        length=struct.unpack_from("<I",data,p)[0];p+=4
        ck(length==item["name_length"],"area string byte length")
        name=data[p:p+length].decode("utf-8");p=(p+length+3)&~3
        cost=struct.unpack_from("<f",data,p)[0];p+=4
        ck(name==item["name"] and cost==item["cost"] and p==item["end_offset"],"area name/cost/end")
    ck(p==a["rows_end_offset"]==284,"area region end")
    ck(digest(data[:p])==a["array_region_sha256"],"area region sha")
    ck((tail["start_offset"],tail["bytes"],digest(data[p:]))==(284,76,tail["sha256"]),"trailing uninterpreted bytes")
    ck(data[352:360]==tail["literal_at_offset_352"].encode("ascii")==b"Humanoid","terminal literal")
    ck(p+tail["bytes"]==360,"complete object coverage")
    return {"fact":"FACT-0328","source_proof":"PASS","area_count":count,"object_bytes":360,"unlabelled_bytes":76,"runtime_eligible":False}
if __name__=="__main__":
    ap=argparse.ArgumentParser();ap.add_argument("--globalgamemanagers",required=True);args=ap.parse_args()
    try:
        witness=json.loads(W.read_text())
        ck(witness["dataset_id"]=="UNITY_GGM_NAVMESH_AREA_SLOTS_SOURCE_V1","witness id")
        print(json.dumps(prove(args.globalgamemanagers,witness),sort_keys=True))
        print("PROVE_GLOBALGAMEMANAGERS_NAVMESH_AREAS: PASS")
    except Exception as exc:
        print("PROVE_GLOBALGAMEMANAGERS_NAVMESH_AREAS: FAIL",str(exc))
        raise SystemExit(1)
