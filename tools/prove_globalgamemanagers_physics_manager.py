#!/usr/bin/env python3
"""FACT-0329: exact Unity PhysicsManager object and original full-source provenance."""
import argparse
import hashlib
import json
import math
import struct
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/GGM-001/physics_manager_180_bytes.summary.json"
def sha(data): return hashlib.sha256(data).hexdigest()
def ck(x,message):
    if not x: raise AssertionError(message)
def prove(path,w):
    data=Path(path).read_bytes();src=w["original_file"];ob=w["object"]
    ck((len(data),sha(data))==(src["bytes"],src["sha256"]),"full original GGM identity")
    ck(struct.unpack_from(">IIIII",data,0)==(1379,len(data),17,4096,0),"Unity header")
    p=20;end=data.index(b"\0",p)
    ck(data[p:end]==b"5.6.5p3","original engine")
    p=end+1
    platform,typetree,nt=struct.unpack_from("<iBI",data,p);p+=9
    ck((platform,typetree,nt)==(5,0,20),"metadata types")
    types=[]
    for i in range(nt):
        cls,removed,script=struct.unpack_from("<iBh",data,p);p+=23
        ck((removed,script)==(0,-1),"type row")
        types.append(cls)
    ck(types[ob["type_index"]]==ob["class_id"]==55,"PhysicsManager class")
    n=struct.unpack_from("<I",data,p)[0];p=(p+4+3)&~3
    ck(n==src["object_count"]==20,"original object count")
    objects={}
    for i in range(n):
        pid,relative,size,type_index=struct.unpack_from("<qIII",data,p);p+=20
        ck(type_index<nt and src["data_offset"]+relative+size<=len(data),"ObjectInfo bounds")
        objects[pid]=(relative,size,type_index)
    ck(objects[ob["path_id"]]==(ob["relative_offset"],ob["bytes"],ob["type_index"]),"original ObjectInfo")
    off=src["data_offset"]+ob["relative_offset"]
    ck(off==ob["absolute_offset"]==0x10528,"absolute source offset")
    d=data[off:off+ob["bytes"]]
    ck((len(d),sha(d))==(180,ob["sha256"]),"full object bytes")
    pref=w["prefix"];extra=w["other_configuration"];g=w["gravity"];m=w["layer_collision_matrix"]
    ck((pref["offset"],pref["bytes"],sha(d[:52]),d[:52].hex())==(0,52,pref["sha256"],pref["hex"]),"52-byte prefix")
    ck((g["offset"],g["bytes"],g["words_hex"])==(0,12,[d[i:i+4].hex() for i in (0,4,8)]),"exact raw gravity")
    vals=struct.unpack_from("<fff",d,0)
    ck(all(math.isclose(v,e,rel_tol=0,abs_tol=0.000001) for v,e in zip(vals,g["components_f32_round6"])),"gravity numeric")
    ck((extra["offset"],extra["bytes"],extra["hex"])==(12,40,d[12:52].hex()),"40 unlabelled configuration bytes")
    ck((m["offset"],m["bytes"],m["rows"],m["per_row_bytes"],sha(d[52:]))==(52,128,32,4,m["sha256"]),"collision matrix source boundary")
    entries=m["entries"]
    ck(len(entries)==32 and m["word_unsigned"]==4294967295,"matrix width")
    for i,row in enumerate(entries):
        value=struct.unpack_from("<I",d,52+i*4)[0]
        ck((row["layer"],row["offset"],row["unsigned_le"],row["hex"],value)==(i,52+i*4,4294967295,"ffffffff",4294967295),"layer mask entry")
    ck(52+128==len(d),"complete source object coverage")
    return {"fact":"FACT-0329","source_proof":"PASS","bytes":180,"layer_rows":32,"raw_configuration_bytes":40,"runtime_eligible":False}

if __name__=="__main__":
    arg=argparse.ArgumentParser();arg.add_argument("--globalgamemanagers",required=True);a=arg.parse_args()
    try:
        w=json.loads(W.read_text())
        ck(w["dataset_id"]=="UNITY_GGM_PHYSICSMANAGER_FULL_180_BYTES_V1","witness ID")
        print(json.dumps(prove(a.globalgamemanagers,w),sort_keys=True))
        print("PROVE_GGM_PHYSICS_MANAGER: PASS")
    except Exception as e:
        print("PROVE_GGM_PHYSICS_MANAGER: FAIL",str(e))
        raise SystemExit(1)
