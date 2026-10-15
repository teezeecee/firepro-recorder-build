#!/usr/bin/env python3
"""FACT-0338 original Unity ResourceManager complete 43,941 name/reference table.

Offline and read-only except explicitly requested --export-json. No Unity original
file bytes are checked into Git. Original file SHA/ObjectInfo/region SHA required.
"""
import argparse,hashlib,json,struct
from collections import Counter
from pathlib import Path
R=Path(__file__).resolve().parents[1]
W=R/"canonical/witnesses/GGM-001/resource_manager_container_43941.summary.json"
def sha(b):return hashlib.sha256(b).hexdigest()
def ck(v,m):
    if not v:raise AssertionError(m)
def prove(path,w):
    data=Path(path).read_bytes();src=w["original_file"];o=w["object"];c=w["container"];tail=w["unparsed_tail"]
    ck((len(data),sha(data))==(src["bytes"],src["sha256"]),"original GGM-001 entire file SHA")
    ck(struct.unpack_from(">IIIII",data,0)==(1379,len(data),17,4096,0),"original serialized header")
    p=20;q=data.index(bytes((0,)),p);ck(data[p:q]==b"5.6.5p3","Unity version");p=q+1
    platform,type_tree,n=struct.unpack_from("<iBI",data,p);p+=9
    ck((platform,type_tree,n)==(5,0,20),"original type metadata")
    classes=[]
    for _ in range(n):
        cid,deleted,script=struct.unpack_from("<iBh",data,p);p+=23
        ck((deleted,script)==(0,-1),"source type row")
        classes.append(cid)
    ck(classes[o["type_index"]]==o["class_id"]==147,"ResourceManager original class")
    n=struct.unpack_from("<I",data,p)[0];p=(p+7)&~7
    ck(n==20,"original ObjectInfo count")
    objs={}
    for _ in range(n):
        pid,rel,sz,idx=struct.unpack_from("<qIII",data,p);p+=20
        ck(idx<len(classes) and 4096+rel+sz<=len(data),"source ObjectInfo bounds")
        objs[pid]=(rel,sz,idx)
    ck(objs[o["path_id"]]==(o["relative_offset"],o["bytes"],o["type_index"]),"exact ResourceManager ObjectInfo")
    start=src["data_offset"]+o["relative_offset"]
    ck(start==o["absolute_offset"]==122824,"absolute source offset")
    d=data[start:start+o["bytes"]]
    ck((len(d),sha(d))==(4862328,o["sha256"]),"whole 4,862,328-byte ResourceManager source")
    count=struct.unpack_from("<I",d,0)[0]
    ck(count==c["count"]==43941,"original ResourceManager m_Container count")
    p=c["first_row_offset"];ck(p==4,"original entry start")
    rows=[];names=set();ids=Counter();cats=Counter();maxlen=0
    anchor={x["index"]:x for x in c["anchors"]}
    for i in range(count):
        ck(p+4<=len(d),"source string length bounds")
        n=struct.unpack_from("<I",d,p)[0];p+=4
        ck(0<=n<=2048 and p+n<=len(d),"source UTF8 length bounds")
        name=d[p:p+n].decode("utf8")
        ending=p+n;aligned=(ending+3)&~3
        ck(aligned+12<=len(d) and d[ending:aligned]==bytes(aligned-ending),"original zero padding")
        p=aligned
        file_id,path_id=struct.unpack_from("<iq",d,p);p+=12
        ck(file_id in (4,5) and path_id>0,"original source PPtr values")
        row=[name,file_id,path_id];rows.append(row)
        ids[str(file_id)]+=1;cats[name.split("/")[0]]+=1;names.add(name);maxlen=max(maxlen,n)
        if i in anchor:
            ck(row==[anchor[i]["name"],anchor[i]["file_id"],anchor[i]["path_id"]],"original anchored resource "+str(i))
    ck(p==c["end_offset"]==2138488,"complete original m_Container bytes")
    ck(sha(d[:p])==c["raw_count_and_rows_sha256"],"original full container table SHA")
    ck(sha(d[4:p])==c["raw_rows_sha256"],"original container rows-only SHA")
    ck(len(names)==c["distinct_names"]==24973,"original unique UTF8 names")
    ck(len({(r[1],r[2]) for r in rows})==c["distinct_numeric_reference_pairs"]==43941,"numeric PPtr uniqueness")
    ck(maxlen==c["longest_utf8_name_bytes"]==76,"max source name UTF8 bytes")
    ck(dict(sorted(ids.items()))==c["file_id_counts"]=={"4":11,"5":43930},"source fileID distribution")
    ck(dict(sorted(cats.items()))==c["category_counts"],"original 26 category histogram")
    ck(rows[:4]==c["first_rows"] and rows[-4:]==c["last_rows"],"original ordered row boundaries")
    ck((len(d)-p,sha(d[p:]))==(tail["bytes"],tail["sha256"]),"opaque original tail bytes identity")
    ck((p,len(d))==(tail["start_offset"],tail["end_offset"]),"full source byte partition")
    ck(struct.unpack_from("<I",d,p)[0]==tail["first_u32_raw_value"]==65218,"uninterpreted source tail initial word")
    return {"fact":"FACT-0338","source_proof":"PASS","resource_rows":count,"unique_names":len(names),"table_bytes":p,"opaque_tail_bytes":len(d)-p,"runtime_eligible":False},rows
if __name__=="__main__":
    a=argparse.ArgumentParser()
    a.add_argument("--globalgamemanagers",required=True)
    a.add_argument("--export-json",type=Path,help="Write all source [name,fileID,pathID] rows as JSON locally, only if requested")
    a.add_argument("--lookup",type=int,nargs=2,metavar=("FILE_ID","PATH_ID"),help="Query the exact resource entries for a source PPtr")
    args=a.parse_args()
    try:
        w=json.loads(W.read_text())
        ck(w["dataset_id"]=="UNITY_GGM_RESOURCE_MANAGER_CONTAINER_43941_SOURCE_V1","witness ID")
        report,rows=prove(args.globalgamemanagers,w)
        print(json.dumps(report,sort_keys=True))
        if args.lookup is not None:
            print(json.dumps([{"index":i,"name":r[0],"file_id":r[1],"path_id":r[2]} for i,r in enumerate(rows) if r[1:]==args.lookup],ensure_ascii=False))
        if args.export_json:
            args.export_json.write_text(json.dumps(rows,ensure_ascii=False,separators=(",",":"))+"\n",encoding="utf8")
            print("Source name/PPtr index written:",args.export_json)
        print("PROVE_GGM_RESOURCE_MANAGER_CONTAINER: PASS")
    except Exception as e:
        print("PROVE_GGM_RESOURCE_MANAGER_CONTAINER: FAIL",str(e))
        raise SystemExit(1)
