#!/usr/bin/env python3
"""FACT-0324 read-only original 16-byte Unity 5.6 TimeManager source proof."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/GGM-001/time_manager_four_timestep_fields.summary.json"

def ck(condition,message):
    if not condition: raise AssertionError(message)

def verify(source,record):
    data=Path(source).read_bytes()
    f=record["source_file"];obj=record["object"]
    ck((len(data),hashlib.sha256(data).hexdigest())==(f["bytes"],f["sha256"]),"original entire file identity")
    ck(struct.unpack_from(">IIIII",data,0)==(1379,len(data),17,4096,0),"Unity v17 declared file header")
    p=20;end=data.index(bytes((0,)),p)
    ck(data[p:end]==b"5.6.5p3","original engine version")
    p=end+1
    platform=struct.unpack_from("<i",data,p)[0];p+=4
    hastree=data[p];p+=1
    n=struct.unpack_from("<i",data,p)[0];p+=4
    ck((platform,hastree,n)==(5,0,20),"original platform and type count")
    cls=[]
    for _ in range(n):
        cid,stripped,script=struct.unpack_from("<iBh",data,p)
        ck(stripped==0 and script==-1,"original type metadata")
        cls.append(cid);p+=23
    ck(cls[obj["type_index"]]==obj["class_id"]==5,"original TimeManager class")
    obj_count=struct.unpack_from("<I",data,p)[0];p+=4;p=(p+3)&~3
    ck(obj_count==20,"original number of objects")
    objects={}
    for _ in range(obj_count):
        pathid,start,size,tidx=struct.unpack_from("<qIII",data,p);p+=20
        ck(tidx<len(cls) and 4096+start+size<=len(data),"bounded object table row")
        objects[pathid]=(start,size,tidx)
    start,size,ti=objects[obj["path_id"]]
    ck((start,size,ti)==(obj["relative_offset"],obj["bytes"],obj["type_index"]),"TimeManager exact object info")
    ck(4096+start==obj["absolute_offset"],"TimeManager file position")
    source_bytes=data[4096+start:4096+start+size]
    ck(source_bytes.hex()==obj["hex"] and hashlib.sha256(source_bytes).hexdigest()==obj["sha256"],"complete original source bytes hash")
    fields=record["fields"]
    ck(len(fields)==4 and [x["offset"] for x in fields]==[0,4,8,12],"four source float slots")
    for field in fields:
        pos=field["offset"]
        ck(source_bytes[pos:pos+4].hex()==field["raw_hex"],"exact slot source bytes")
        ck(struct.unpack_from("<f",source_bytes,pos)[0]==field["float32"],"exact original IEEE754 float32")
    ck(len(source_bytes)==16,"no trailing unparsed source bytes")
    return {"fact":"FACT-0324","source_proof":"PASS","field_count":4,"raw_hex":obj["hex"],"runtime_eligible":False}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--globalgamemanagers",required=True)
    args=parser.parse_args()
    try:
        r=json.loads(W.read_text(encoding="utf8"))
        ck(r["dataset_id"]=="UNITY_TIMEMANAGER_FOUR_TIMESTEP_SOURCE_V1","witness identity")
        print(json.dumps(verify(args.globalgamemanagers,r),sort_keys=True))
        print("PROVE_GLOBALGAMEMANAGERS_TIME_MANAGER: PASS")
        return 0
    except Exception as exc:
        print("PROVE_GLOBALGAMEMANAGERS_TIME_MANAGER: FAIL",str(exc))
        return 1
if __name__=="__main__": raise SystemExit(main())
