#!/usr/bin/env python3
"""FACT-0330 source prover: exact original Unity 5.6 GGM Physics2DSettings."""
import argparse
import hashlib
import json
import math
import struct
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/GGM-001/physics2d_settings_208_bytes.summary.json"
def sha(raw): return hashlib.sha256(raw).hexdigest()
def ck(ok, msg):
    if not ok: raise AssertionError(msg)
def prove(path,w):
    raw=Path(path).read_bytes();src=w["original_file"];obj=w["object"]
    ck((len(raw),sha(raw))==(src["bytes"],src["sha256"]),"original raw GGM")
    ck(struct.unpack_from(">5I",raw,0)==(1379,len(raw),17,4096,0),"source header")
    p=20;v=raw.index(b"\x00",p)
    ck(raw[p:v]==b"5.6.5p3","source Unity engine version")
    p=v+1
    platform,tree,n_types=struct.unpack_from("<iBI",raw,p);p+=9
    ck((platform,tree,n_types)==(5,0,20),"original type count")
    types=[]
    for i in range(n_types):
        class_id,deleted,script=struct.unpack_from("<iBh",raw,p);p+=23
        ck((deleted,script)==(0,-1),"original TypeDef flags")
        types.append(class_id)
    ck(types[obj["type_index"]]==obj["class_id"]==19,"Physics2DSettings type")
    n=struct.unpack_from("<I",raw,p)[0];p=(p+4+3)&~3
    ck(n==src["object_count"]==20,"original object count")
    rows={}
    for i in range(n):
        path_id,rel,size,type_idx=struct.unpack_from("<qIII",raw,p);p+=20
        ck(type_idx<n_types and src["data_offset"]+rel+size<=len(raw),"original object bounds")
        rows[path_id]=(rel,size,type_idx)
    ck(rows[obj["path_id"]]==(obj["relative_offset"],obj["bytes"],obj["type_index"]),"original object table identity")
    begin=src["data_offset"]+obj["relative_offset"];end=begin+obj["bytes"]
    ck((begin,end)==(obj["absolute_offset"],0x4C5410),"object absolute span")
    data=raw[begin:end]
    ck((len(data),sha(data))==(208,obj["sha256"]),"complete original body SHA")
    gravity=w["gravity_2d"]
    ck(gravity["offset"]==0 and gravity["bytes"]==8 and sha(data[:8])==gravity["region_sha256"],"original 2D gravity raw span")
    ck([data[i:i+4].hex() for i in (0,4)]==gravity["words_hex"],"original exact 2D float words")
    ck(all(math.isclose(a,b,rel_tol=0,abs_tol=0.000001) for a,b in zip(struct.unpack_from("<ff",data),gravity["components_f32_approx"])),"2D gravity floats")
    rest=w["remaining_settings"]
    ck((rest["offset"],rest["bytes"],rest["exact_hex"],rest["sha256"])==(8,72,data[8:80].hex(),sha(data[8:80])),"middle configuration source exact")
    ck(struct.unpack_from("<I",data,76)[0]==rest["source_u32_at_offset_76"]==32,"source marker u32")
    matrix=w["layer_collision_matrix"]
    ck((matrix["offset"],matrix["bytes"],matrix["entry_count"],matrix["entry_width"],matrix["exact_sha256"])==(80,128,32,4,sha(data[80:208])),"matrix source SHA and boundary")
    ck(len(matrix["entries"])==32,"matrix witness row count")
    for i,entry in enumerate(matrix["entries"]):
        val=struct.unpack_from("<I",data,80+i*4)[0]
        ck((entry["index"],entry["offset"],entry["hex"],entry["unsigned_le"],val)==(i,80+i*4,"ffffffff",4294967295,4294967295),"row "+str(i))
    ck(8+72+128==len(data),"no uncovered object bytes")
    return {"fact":"FACT-0330","source_proof":"PASS","bytes":208,"layers":32,"opaque_configuration_bytes":72,"runtime_eligible":False}
if __name__=="__main__":
    ap=argparse.ArgumentParser();ap.add_argument("--globalgamemanagers",required=True);a=ap.parse_args()
    try:
        w=json.loads(W.read_text())
        ck(w["dataset_id"]=="UNITY_GGM_PHYSICS2DSETTINGS_208B_SOURCE_V1","witness id")
        print(json.dumps(prove(a.globalgamemanagers,w),sort_keys=True))
        print("PROVE_GGM_PHYSICS2DSETTINGS: PASS")
    except Exception as exc:
        print("PROVE_GGM_PHYSICS2DSETTINGS: FAIL",str(exc))
        raise SystemExit(1)
