#!/usr/bin/env python3
"""FACT-0335: original Unity PlayerSettings entire source SHA and bounded regions."""
import argparse,hashlib,json,struct
from pathlib import Path
R=Path(__file__).resolve().parents[1]
W=R/"canonical/witnesses/GGM-001/player_settings_546_bytes.summary.json"
def sha(b):return hashlib.sha256(b).hexdigest()
def ck(condition,message):
    if not condition:raise AssertionError(message)
def prove(path,w):
    b=Path(path).read_bytes();src=w["original_file"];o=w["object"]
    ck((len(b),sha(b))==(src["bytes"],src["sha256"]),"original whole-file identity")
    ck(struct.unpack_from(">IIIII",b,0)==(1379,len(b),17,4096,0),"original serialized file header")
    p=20;q=b.index(bytes((0,)),p);ck(b[p:q]==b"5.6.5p3","original Unity version");p=q+1
    platform,tree,nt=struct.unpack_from("<iBI",b,p);p+=9
    ck((platform,tree,nt)==(5,0,20),"original class table header")
    classes=[]
    for _ in range(nt):
        cid,deleted,script=struct.unpack_from("<iBh",b,p);p+=23
        ck((deleted,script)==(0,-1),"original class table row")
        classes.append(cid)
    ck(classes[o["type_index"]]==o["class_id"]==129,"original PlayerSettings class")
    n=struct.unpack_from("<I",b,p)[0];p=(p+7)&~3
    ck(n==20,"original ObjectInfo row count")
    obj={}
    for _ in range(n):
        pid,rel,size,idx=struct.unpack_from("<qIII",b,p);p+=20
        ck(idx<nt and 4096+rel+size<=len(b),"original ObjectInfo bounds")
        obj[pid]=(rel,size,idx)
    ck(obj[o["path_id"]]==(o["relative_offset"],o["bytes"],o["type_index"]),"exact original ObjectInfo")
    offset=4096+o["relative_offset"]
    ck(offset==o["absolute_offset"]==0x1000,"original absolute offset")
    d=b[offset:offset+o["bytes"]]
    ck((len(d),sha(d))==(546,o["sha256"]),"full original PlayerSettings bytes")
    last=0
    for seg in w["regions"]:
        a,z=seg["start_offset"],seg["end_offset"]
        ck(a==last and z>a and z<=len(d),"non-overlapping contiguous region")
        chunk=d[a:z]
        ck(len(chunk)==seg["bytes"] and sha(chunk)==seg["sha256"],"full region digest "+seg["name"])
        last=z
    ck(last==546,"all original source bytes covered by regions")
    byname={x["name"]:x for x in w["regions"]}
    ck(len(byname)==len(w["regions"])==10,"source region count/identity")
    for item in w["strings"]:
        st=item["offset"];length=struct.unpack_from("<I",d,st)[0]
        ck(length==item["byte_length"],"source string byte length")
        name=d[st+4:st+4+length].decode("utf8")
        ed=(st+4+length+3)&~3
        section=byname[item["region"]]
        ck((st,ed)==(section["start_offset"],section["end_offset"]),"padded string region closure")
        ck(name==item["value"],"original source string bytes")
    q=w["numeric_quad"]
    ck(q["offset"]==byname[q["region"]]["start_offset"]==240,"numeric region location")
    ck(list(struct.unpack_from("<IIII",d,240))==q["values"]==[1280,720,960,600],"exact original four unsigned words")
    return {"fact":"FACT-0335","original_source_proof":"PASS","object_bytes":546,"regions":10,"strings":4,"runtime_eligible":False}
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--globalgamemanagers",required=True);args=p.parse_args()
    try:
        w=json.loads(W.read_text())
        ck(w["dataset_id"]=="UNITY_GGM_PLAYER_SETTINGS_COMPLETE_546_BYTE_SOURCE_V1","witness identity")
        print(json.dumps(prove(args.globalgamemanagers,w),sort_keys=True))
        print("PROVE_GGM_PLAYER_SETTINGS: PASS")
    except Exception as e:
        print("PROVE_GGM_PLAYER_SETTINGS: FAIL",str(e))
        raise SystemExit(1)
