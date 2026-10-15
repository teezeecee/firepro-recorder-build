#!/usr/bin/env python3
"""FACT-0333 original Unity InputManager 437 full axis rows source proof."""
import argparse,base64,hashlib,json,struct,zlib
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/GGM-001/input_manager_437_rows.summary.json"
def sha(b):return hashlib.sha256(b).hexdigest()
def ck(cond,msg):
    if not cond:raise AssertionError(msg)
def prove(path,w):
    b=Path(path).read_bytes();src=w["original_file"];o=w["object"];t=w["table"]
    ck((len(b),sha(b))==(src["bytes"],src["sha256"]),"whole original Unity file")
    ck(struct.unpack_from(">IIIII",b,0)==(1379,len(b),17,4096,0),"original Unity file header")
    p=20;q=b.index(bytes((0,)),p);ck(b[p:q]==b"5.6.5p3","source Unity version");p=q+1
    platform,tree,nt=struct.unpack_from("<iBI",b,p);p+=9
    ck((platform,tree,nt)==(5,0,20),"source platform and type count")
    classes=[]
    for i in range(nt):
        cl,deleted,script=struct.unpack_from("<iBh",b,p);p+=23
        ck((deleted,script)==(0,-1),"Unity original type row")
        classes.append(cl)
    ck(classes[o["type_index"]]==o["class_id"]==13,"InputManager TypeDef")
    n=struct.unpack_from("<I",b,p)[0];p+=4;p=(p+3)&~3
    ck(n==20,"original ObjectInfo count")
    obj={}
    for i in range(n):
        pid,rel,sz,idx=struct.unpack_from("<qIII",b,p);p+=20
        ck(idx<nt and 4096+rel+sz<=len(b),"all object bounds")
        obj[pid]=(rel,sz,idx)
    ck(obj[o["path_id"]]==(o["relative_offset"],o["bytes"],o["type_index"]),"original InputManager ObjectInfo")
    start=4096+o["relative_offset"]
    ck(start==o["absolute_offset"]==0x1228,"original absolute offset")
    d=b[start:start+o["bytes"]]
    ck((len(d),sha(d))==(31408,o["sha256"]),"whole original 31,408-byte object")
    p=0;n=struct.unpack_from("<I",d,p)[0];p+=4
    ck(n==t["count"]==437 and p==t["first_row_offset"],"original entry count")
    rows=[];samples={x["index"]:x for x in w["samples"]}
    for i in range(n):
        start=p;ss=[]
        for j in range(7):
            ck(p+4<=len(d),"string length bounds")
            sz=struct.unpack_from("<I",d,p)[0];p+=4
            ck(sz<=len(d)-p,"source UTF8 bounds")
            ss.append(d[p:p+sz].decode("utf-8"))
            p=(p+sz+3)&~3
        ck(p+28<=len(d),"row numerics bounds")
        bits=list(struct.unpack_from("<III",d,p));p+=12
        raw=list(d[p:p+4]);p+=4
        tail=list(struct.unpack_from("<iii",d,p));p+=12
        row=ss+bits+raw+tail;rows.append(row)
        if i in samples:
            sample=samples[i]
            ck((start,p,ss,bits,raw,tail)==(sample["start_offset"],sample["end_offset"],sample["strings"],sample["float32_u32_bits"],sample["four_bytes"],sample["int32_tail"]),"sample row "+str(i))
    ck(p==t["end_offset"]==len(d)==31408,"complete source byte coverage")
    ck(sha(d[4:p])==t["raw_rows_sha256"],"original full row region hash")
    a=w["rows_archive"];packed=zlib.decompress(base64.b64decode(a["data"]))
    ck((len(packed),sha(packed))==(a["decoded_bytes"],a["decoded_sha256"]),"lossless witness text identity")
    ck(json.loads(packed)==rows,"437 complete source row equality")
    cc=w["counts"]
    ck(len({row[0] for row in rows})==cc["distinct_primary_names"]==436,"name count")
    ck(sum(bool(x) for row in rows for x in row[:7])==cc["nonempty_string_slots"]==525,"string slots")
    ck(sum(any(row[j] for j in range(3,7)) for row in rows)==cc["rows_with_nonempty_binding_slots_3_to_6"]==72,"binding text slots")
    ck(dict(sorted(Counter(str(row[-3]) for row in rows).items()))==cc["first_tail_code_counts"],"original first integer counts")
    ck(dict(sorted(Counter(bytes(row[10:14]).hex() for row in rows).items()))==cc["four_byte_region_hex_counts"],"original raw four-byte counts")
    return {"fact":"FACT-0333","source_proof":"PASS","axis_rows":437,"source_bytes":len(d),"runtime_eligible":False}
if __name__=="__main__":
    a=argparse.ArgumentParser();a.add_argument("--globalgamemanagers",required=True);arg=a.parse_args()
    try:
        w=json.loads(W.read_text())
        ck(w["dataset_id"]=="UNITY_GGM_INPUT_MANAGER_COMPLETE_437_AXIS_ROWS_V1","witness identity")
        print(json.dumps(prove(arg.globalgamemanagers,w),sort_keys=True))
        print("PROVE_GGM_INPUT_MANAGER: PASS")
    except Exception as e:
        print("PROVE_GGM_INPUT_MANAGER: FAIL",str(e))
        raise SystemExit(1)
