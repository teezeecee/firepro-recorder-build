#!/usr/bin/env python3
"""FACT-0332 original GGM ShaderNameRegistry full-source/206-row verifier."""
import argparse,base64,hashlib,json,struct,zlib
from collections import Counter
from pathlib import Path
R=Path(__file__).resolve().parents[1]
W=R/"canonical/witnesses/GGM-001/shader_name_registry_206.summary.json"
def sha(b):return hashlib.sha256(b).hexdigest()
def ck(ok,msg):
    if not ok:raise AssertionError(msg)
def prove(path,w):
    b=Path(path).read_bytes();src=w["original_file"];o=w["object"];t=w["table"]
    ck((len(b),sha(b))==(src["bytes"],src["sha256"]),"original complete file")
    ck(struct.unpack_from(">IIIII",b)==(1379,len(b),17,4096,0),"original Unity header")
    p=20;q=b.index(bytes((0,)),p);ck(b[p:q]==b"5.6.5p3","original Unity version");p=q+1
    platform,tree,nt=struct.unpack_from("<iBI",b,p);p+=9
    ck((platform,tree,nt)==(5,0,20),"original type count")
    classes=[]
    for i in range(nt):
        c,de,sc=struct.unpack_from("<iBh",b,p);p+=23
        ck((de,sc)==(0,-1),"class row")
        classes.append(c)
    ck(classes[o["type_index"]]==o["class_id"]==94,"original ShaderNameRegistry class")
    n=struct.unpack_from("<I",b,p)[0];p=(p+7)&~3
    ck(n==20,"original object count")
    objects={}
    for i in range(n):
        pid,rel,sz,ti=struct.unpack_from("<qIII",b,p);p+=20
        ck(ti<nt and 4096+rel+sz<=len(b),"original ObjectInfo bounds")
        objects[pid]=(rel,sz,ti)
    ck(objects[o["path_id"]]==(o["relative_offset"],o["bytes"],o["type_index"]),"original ObjectInfo")
    ck(4096+o["relative_offset"]==o["absolute_offset"]==0x90A8,"source offset")
    d=b[o["absolute_offset"]:o["absolute_offset"]+o["bytes"]]
    ck((len(d),sha(d))==(9561,o["sha256"]),"whole ShaderNameRegistry object")
    ck(struct.unpack_from("<I",d,0)[0]==t["count"]==206,"source row count")
    ck(sha(d[4:t["rows_end_offset"]])==t["rows_raw_sha256"],"all source row bytes")
    p=t["first_row_offset"];rows=[]
    for i in range(206):
        ck(p+16<=len(d),"row bounds")
        fid,pid,nchars=struct.unpack_from("<iqI",d,p);p+=16
        ck(nchars<=len(d)-p,"name bounds")
        name=d[p:p+nchars].decode("utf-8");p=(p+nchars+3)&~3
        ck(p<=t["rows_end_offset"],"alignment bounds")
        rows.append([fid,pid,name])
    ck(p==t["rows_end_offset"]==9560,"206 row byte coverage")
    ck((len(d),d[p])==(p+1,t["terminal_byte"]),"terminal source byte")
    a=w["rows_archive"];arch=zlib.decompress(base64.b64decode(a["data"]))
    ck((len(arch),sha(arch))==(a["decoded_bytes"],a["decoded_sha256"]),"archived rows identity")
    ck(json.loads(arch)==rows,"every source fileID, pathID and name equals archived witness")
    ck(dict(sorted(Counter(str(row[0]) for row in rows).items()))==w["file_id_counts"],"source fileID distribution")
    fi=[dict(index=i,file_id=fid,path_id=pid,name=name) for i,(fid,pid,name) in enumerate(rows) if name.startswith("FiPro/")]
    ck(len(fi)==11==len(w["fipro_names"]),"FiPro row count")
    for a,b in zip(fi,w["fipro_names"]):
        ck(all(a[k]==b[k] for k in a),"FiPro source triple")
    ck(w["external_reference_join"]=={"1":"globalgamemanagers.assets","5":"resources.assets"},"earlier verified FACT-0326 dependency join")
    return {"fact":"FACT-0332","source_proof":"PASS","registry_rows":206,"fipro_rows":11,"runtime_eligible":False}
if __name__=="__main__":
    a=argparse.ArgumentParser();a.add_argument("--globalgamemanagers",required=True)
    arg=a.parse_args()
    try:
        w=json.loads(W.read_text())
        ck(w["dataset_id"]=="UNITY_GGM_SHADER_NAME_REGISTRY_206_REFERENCES_V1","dataset")
        print(json.dumps(prove(arg.globalgamemanagers,w),sort_keys=True))
        print("PROVE_GGM_SHADER_NAME_REGISTRY: PASS")
    except Exception as exc:
        print("PROVE_GGM_SHADER_NAME_REGISTRY: FAIL",str(exc))
        raise SystemExit(1)
