#!/usr/bin/env python3
"""FACT-0331: original Unity TagManager entire source object and all table rows."""
import argparse
import hashlib
import json
import struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/GGM-001/tag_manager_full.summary.json"
def sha(b): return hashlib.sha256(b).hexdigest()
def ck(x,s):
    if not x: raise AssertionError(s)
def prove(filename,w):
    b=Path(filename).read_bytes();src=w["original_file"];o=w["object"]
    ck((len(b),sha(b))==(src["bytes"],src["sha256"]),"whole original source")
    ck(struct.unpack_from(">IIIII",b,0)==(1379,len(b),17,4096,0),"Unity original header")
    p=20;q=b.index(b"\0",p);ck(b[p:q]==b"5.6.5p3","Unity source version");p=q+1
    platform,tt,nt=struct.unpack_from("<iBI",b,p);p+=9
    ck((platform,tt,nt)==(5,0,20),"original type table header")
    classes=[]
    for _ in range(nt):
        cls,deleted,script=struct.unpack_from("<iBh",b,p);p+=23
        ck((deleted,script)==(0,-1),"source type row")
        classes.append(cls)
    ck(classes[o["type_index"]]==o["class_id"]==78,"original TagManager class")
    n=struct.unpack_from("<I",b,p)[0];p=(p+4+3)&~3;ck(n==20,"object count")
    indexed={}
    for _ in range(n):
        pid,rel,size,idx=struct.unpack_from("<qIII",b,p);p+=20
        ck(idx<nt and src["data_offset"]+rel+size<=len(b),"original object bounds")
        indexed[pid]=(rel,size,idx)
    ck(indexed[o["path_id"]]==(o["relative_offset"],o["bytes"],o["type_index"]),"original ObjectInfo")
    st=src["data_offset"]+o["relative_offset"]
    ck(st==o["absolute_offset"]==0x8CD8,"absolute source offset")
    d=b[st:st+o["bytes"]]
    ck((len(d),sha(d))==(932,o["sha256"]),"complete source body")
    p=0
    for key in ("tags","layers","sorting_layers"):
        t=w[key];start=p
        ck(p==t["count_offset"],"count offset "+key)
        n=struct.unpack_from("<I",d,p)[0];p+=4
        ck(n==t["count"]==len(t["entries"]),"count "+key)
        ck(p==t["first_row_offset"],"first row "+key)
        for i,row in enumerate(t["entries"]):
            ck((row["index"],row["start_offset"])==(i,p),"entry start "+key+str(i))
            length=struct.unpack_from("<I",d,p)[0];p+=4
            ck(length==row["name_byte_length"],"string length "+key+str(i))
            name=d[p:p+length].decode("utf-8");p=(p+length+3)&~3
            ck(name==row["name"],"source string "+key+str(i))
            if key=="sorting_layers":
                uid=struct.unpack_from("<I",d,p)[0];p+=4
                ck(uid==row["unique_id"],"sorting ID "+str(i))
            ck(p==row["end_offset"],"row end "+key+str(i))
        ck(p==t["end_offset"] and sha(d[start:p])==t["sha256"],"table full SHA "+key)
    ck(p==len(d)==932,"complete source body coverage")
    return {"fact":"FACT-0331","source_proof":"PASS","tags":18,"layers":32,"sorting_layers":4,"bytes":932,"runtime_eligible":False}
if __name__=="__main__":
    ap=argparse.ArgumentParser();ap.add_argument("--globalgamemanagers",required=True);a=ap.parse_args()
    try:
        w=json.loads(W.read_text())
        ck(w["dataset_id"]=="UNITY_GGM_TAGMANAGER_COMPLETE_TABLES_V1","witness identity")
        print(json.dumps(prove(a.globalgamemanagers,w),sort_keys=True))
        print("PROVE_GGM_TAGMANAGER: PASS")
    except Exception as e:
        print("PROVE_GGM_TAGMANAGER: FAIL",str(e))
        raise SystemExit(1)
