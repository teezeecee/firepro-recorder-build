#!/usr/bin/env python3
"""FACT-0327: check full original GGM source, object table and raw AudioManager record."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
W = ROOT/"canonical/witnesses/GGM-001/audio_manager_40_bytes.summary.json"
def check(ok, why):
    if not ok: raise AssertionError(why)
def hash256(d): return hashlib.sha256(d).hexdigest()
def prove(path, w):
    b=Path(path).read_bytes(); s=w["original_file"]; o=w["object"]
    check((len(b),hash256(b))==(s["bytes"],s["sha256"]),"exact original raw file")
    check(struct.unpack_from(">IIIII",b,0)==(1379,len(b),17,4096,0),"original Unity header")
    p=20; e=b.index(b"\x00",p)
    check(b[p:e]==b"5.6.5p3","original engine version")
    p=e+1
    platform,tt,nt=struct.unpack_from("<iBI",b,p);p+=9
    check((platform,tt,nt)==(5,0,20),"original type count")
    types=[]
    for i in range(nt):
        cid,deleted,script=struct.unpack_from("<iBh",b,p)
        check((deleted,script)==(0,-1),"original type row")
        types.append(cid);p+=23
    check(types[o["type_index"]]==o["class_id"]==11,"class id")
    n=struct.unpack_from("<I",b,p)[0];p=(p+4+3)&~3
    check(n==20,"original object count")
    rows={}
    for i in range(n):
        pid,rel,size,idx=struct.unpack_from("<qIII",b,p);p+=20
        check(idx<nt and s["data_offset"]+rel+size<=len(b),"object bounds")
        rows[pid]=(rel,size,idx)
    check(rows[o["path_id"]]==(o["relative_offset"],o["bytes"],o["type_index"]),"object index")
    off=s["data_offset"]+o["relative_offset"];check(off==o["absolute_offset"]==0x9080,"original offset")
    d=b[off:off+o["bytes"]]
    check((len(d),hash256(d),d.hex())==(40,o["sha256"],o["hex"]),"all original object bytes")
    for i,x in enumerate(w["scalar_prefix"]):
        check(x["offset"]==i*4,"scalar offset")
        v=struct.unpack_from("<"+x["struct_type"],d,i*4)[0]
        check(v==x["value"],"scalar "+x["field"])
    check(len(w["scalar_prefix"])==8,"eight slots")
    tail=w["unnamed_tail"]
    check((tail["offset"],tail["bytes"],tail["hex"])==(32,8,d[32:].hex()),"uninterpreted tail")
    check(list(struct.unpack_from("<II",d,32))==tail["as_raw_uint32"],"raw u32 tail")
    return {"fact":"FACT-0327","source_proof":"PASS","object_bytes":40,"prefix_slots":8,"unlabelled_tail_bytes":8,"runtime_eligible":False}
if __name__=="__main__":
    a=argparse.ArgumentParser();a.add_argument("--globalgamemanagers",required=True);v=a.parse_args()
    try:
        w=json.loads(W.read_text())
        check(w["dataset_id"]=="UNITY_GGM_AUDIOMANAGER_40B_SOURCE_V1","witness name")
        print(json.dumps(prove(v.globalgamemanagers,w),sort_keys=True))
        print("PROVE_GLOBALGAMEMANAGERS_AUDIO_MANAGER: PASS")
    except Exception as e:
        print("PROVE_GLOBALGAMEMANAGERS_AUDIO_MANAGER: FAIL",str(e))
        raise SystemExit(1)
