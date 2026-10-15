#!/usr/bin/env python3
"""FACT-0336: entire original 164-byte RuntimeInitializeOnLoadManager source."""
import argparse,hashlib,json,struct
from pathlib import Path
R=Path(__file__).resolve().parents[1]
W=R/"canonical/witnesses/GGM-001/runtime_initialize_164_bytes.summary.json"
def sha(b): return hashlib.sha256(b).hexdigest()
def ck(v,m):
    if not v: raise AssertionError(m)
def prove(path,w):
    b=Path(path).read_bytes();src=w["original_file"];obj=w["object"]
    ck((len(b),sha(b))==(src["bytes"],src["sha256"]),"original whole file")
    ck(struct.unpack_from(">IIIII",b,0)==(1379,len(b),17,4096,0),"Unity serialized header")
    p=20;q=b.index(bytes((0,)),p);ck(b[p:q]==b"5.6.5p3","original Unity version");p=q+1
    platform,has_tree,nt=struct.unpack_from("<iBI",b,p);p+=9
    ck((platform,has_tree,nt)==(5,0,20),"original type metadata header")
    classes=[]
    for _ in range(nt):
        cl,deleted,script=struct.unpack_from("<iBh",b,p);p+=23
        ck((deleted,script)==(0,-1),"source type row")
        classes.append(cl)
    ck(classes[obj["type_index"]]==obj["class_id"]==300,"Unity class type mapping")
    n=struct.unpack_from("<I",b,p)[0];p=(p+7)&~3
    ck(n==20,"original ObjectInfo rows count")
    objs={}
    for _ in range(n):
        pid,rel,sz,idx=struct.unpack_from("<qIII",b,p);p+=20
        ck(idx<len(classes) and src["data_offset"]+rel+sz<=len(b),"original ObjectInfo bounds")
        objs[pid]=(rel,sz,idx)
    ck(objs[obj["path_id"]]==(obj["relative_offset"],obj["bytes"],obj["type_index"]),"source ObjectInfo identity")
    start=src["data_offset"]+obj["relative_offset"]
    ck(start==obj["absolute_offset"]==0x4C5410,"absolute object offset")
    d=b[start:start+obj["bytes"]]
    ck((len(d),sha(d))==(164,obj["sha256"]),"original complete source object")
    prev=0;parts={}
    for region in w["regions"]:
        a,z=region["start_offset"],region["end_offset"]
        ck(a==prev and z>a and z<=len(d),"contiguous source region "+region["name"])
        buf=d[a:z]
        ck(len(buf)==region["bytes"] and sha(buf)==region["sha256"],"original SHA256 region "+region["name"])
        if "u32_values" in region:
            ck(len(buf)%4==0 and list(struct.unpack("<"+"I"*(len(buf)//4),buf))==region["u32_values"],"original unlabelled numeric bytes "+region["name"])
        parts[region["name"]]=(a,z)
        prev=z
    ck(prev==len(d)==164 and len(parts)==9,"complete original object byte partition")
    ck(len(w["strings"])==4,"four original name slots")
    for item in w["strings"]:
        start=item["offset"]
        n=struct.unpack_from("<I",d,start)[0]
        ck(n==item["byte_length"],"source string length")
        name=d[start+4:start+4+n].decode("utf8")
        end=(start+4+n+3)&~3
        ck(parts[item["region"]]==(start,end) and name==item["value"],"original source aligned name "+item["region"])
        ck(all(x==0 for x in d[start+4+n:end]),"source string padding")
    ck([x["value"] for x in w["strings"]]==["UnityEditor.Advertisements","UnityEditor.Advertisements","UnityAdsEditor","EditorOnLoad"],"original source name list")
    return {"fact":"FACT-0336","source_proof":"PASS","source_object_bytes":164,"regions":9,"string_rows":4,"runtime_eligible":False}
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--globalgamemanagers",required=True);a=p.parse_args()
    try:
        w=json.loads(W.read_text())
        ck(w["dataset_id"]=="UNITY_GGM_RUNTIME_INITIALIZE_ON_LOAD_164_SOURCE_V1","witness identity")
        print(json.dumps(prove(a.globalgamemanagers,w),sort_keys=True))
        print("PROVE_GGM_RUNTIME_INITIALIZE: PASS")
    except Exception as e:
        print("PROVE_GGM_RUNTIME_INITIALIZE: FAIL",str(e))
        raise SystemExit(1)
