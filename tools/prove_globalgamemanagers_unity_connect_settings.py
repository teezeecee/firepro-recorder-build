#!/usr/bin/env python3
"""FACT-0337: prove original UnityConnectSettings 116-byte source/object and sections."""
import argparse,hashlib,json,struct
from pathlib import Path
R=Path(__file__).resolve().parents[1]
W=R/"canonical/witnesses/GGM-001/unity_connect_settings_116_bytes.summary.json"
def sha(b):return hashlib.sha256(b).hexdigest()
def ck(ok,msg):
    if not ok:raise AssertionError(msg)
def prove(path,w):
    b=Path(path).read_bytes();src=w["original_file"];o=w["object"]
    ck((len(b),sha(b))==(src["bytes"],src["sha256"]),"original complete Unity source file")
    ck(struct.unpack_from(">IIIII",b,0)==(1379,len(b),17,4096,0),"original Unity file header")
    p=20;q=b.index(bytes((0,)),p);ck(b[p:q]==b"5.6.5p3","original Unity version");p=q+1
    platform,tree,nt=struct.unpack_from("<iBI",b,p);p+=9
    ck((platform,tree,nt)==(5,0,20),"original type count and platform")
    classes=[]
    for _ in range(nt):
        cid,deleted,script=struct.unpack_from("<iBh",b,p);p+=23
        ck((deleted,script)==(0,-1),"original type row")
        classes.append(cid)
    ck(classes[o["type_index"]]==o["class_id"]==310,"original UnityConnectSettings ClassID")
    n=struct.unpack_from("<I",b,p)[0];p=(p+7)&~7
    ck(n==20,"original ObjectInfo count")
    objs={}
    for _ in range(n):
        pid,rel,sz,idx=struct.unpack_from("<qIII",b,p);p+=20
        ck(idx<len(classes) and src["data_offset"]+rel+sz<=len(b),"source ObjectInfo bounds")
        objs[pid]=(rel,sz,idx)
    ck(objs[o["path_id"]]==(o["relative_offset"],o["bytes"],o["type_index"]),"exact original ObjectInfo")
    start=src["data_offset"]+o["relative_offset"]
    ck(start==o["absolute_offset"]==0x4C54B8,"source offset")
    d=b[start:start+o["bytes"]]
    ck((len(d),sha(d))==(116,o["sha256"]),"full UnityConnectSettings original object hash")
    last=0
    for item in w["regions"]:
        a,z=item["start_offset"],item["end_offset"];v=d[a:z]
        ck(a==last and z>a and z<=len(d),"contiguous source region "+item["name"])
        ck(len(v)==item["bytes"] and sha(v)==item["sha256"],"source region SHA "+item["name"])
        if "unlabelled_u32" in item:
            vals=list(struct.unpack("<"+"I"*(len(v)//4),v))
            ck(vals==item["unlabelled_u32"],"source numeric word identity "+item["name"])
        last=z
    ck(last==len(d)==116 and len(w["regions"])==4,"complete source byte partition")
    s=w["embedded_url"];p=s["object_offset"]
    n=struct.unpack_from("<I",d,p)[0]
    ck(n==s["length_prefix_u32"]==56,"source UTF8 byte length")
    ck(s["bytes_start"]==p+4 and s["bytes_end"]==p+4+n==76,"URL source bounds")
    url=d[p+4:p+4+n].decode("utf8")
    ck(url==s["value"]=="https://perf-events.cloud.unity3d.com/api/events/crashes","source URL")
    return {"fact":"FACT-0337","source_proof":"PASS","source_bytes":116,"segments":4,"runtime_eligible":False}
if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--globalgamemanagers",required=True)
    args=parser.parse_args()
    try:
        w=json.loads(W.read_text())
        ck(w["dataset_id"]=="UNITY_GGM_UNITY_CONNECT_SETTINGS_116_BYTE_SOURCE_V1","source witness ID")
        print(json.dumps(prove(args.globalgamemanagers,w),sort_keys=True))
        print("PROVE_GGM_UNITY_CONNECT_SETTINGS: PASS")
    except Exception as err:
        print("PROVE_GGM_UNITY_CONNECT_SETTINGS: FAIL",str(err))
        raise SystemExit(1)
