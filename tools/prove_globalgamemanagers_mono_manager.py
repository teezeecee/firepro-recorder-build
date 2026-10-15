#!/usr/bin/env python3
"""FACT-0334 original Unity MonoManager full 1613 pointers and 13 assembly rows."""
import argparse,base64,bz2,hashlib,json,struct
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/GGM-001/mono_manager_1613_scripts_13_assemblies.summary.json"
def sha(b): return hashlib.sha256(b).hexdigest()
def ck(ok,msg):
    if not ok: raise AssertionError(msg)
def prove(path,w):
    b=Path(path).read_bytes();src=w["original_file"];o=w["object"];ptr=w["script_reference_table"];asm=w["assembly_name_table"]
    ck((len(b),sha(b))==(src["bytes"],src["sha256"]),"complete original Unity file")
    ck(struct.unpack_from(">IIIII",b,0)==(1379,len(b),17,4096,0),"original serialized header")
    p=20;q=b.index(bytes((0,)),p)
    ck(b[p:q]==b"5.6.5p3","original Unity version");p=q+1
    platform,has_tree,nt=struct.unpack_from("<iBI",b,p);p+=9
    ck((platform,has_tree,nt)==(5,0,20),"original type table header")
    classes=[]
    for _ in range(nt):
        cid,deleted,script=struct.unpack_from("<iBh",b,p);p+=23
        ck((deleted,script)==(0,-1),"original type row")
        classes.append(cid)
    ck(classes[o["type_index"]]==o["class_id"]==116,"source MonoManager ClassID")
    n=struct.unpack_from("<I",b,p)[0];p=(p+7)&~3
    ck(n==20,"original ObjectInfo count")
    objs={}
    for _ in range(n):
        pid,rel,sz,idx=struct.unpack_from("<qIII",b,p);p+=20
        ck(idx<nt and 4096+rel+sz<=len(b),"source object table bounds")
        objs[pid]=(rel,sz,idx)
    ck(objs[o["path_id"]]==(o["relative_offset"],o["bytes"],o["type_index"]),"original exact ObjectInfo")
    st=4096+o["relative_offset"];ck(st==o["absolute_offset"]==0xB608,"source absolute offset")
    d=b[st:st+o["bytes"]]
    ck((len(d),sha(d))==(19672,o["sha256"]),"whole source object digest")
    count=struct.unpack_from("<I",d,0)[0]
    ck(count==ptr["count"]==1613,"original script count")
    ed=4+count*12
    ck(ed==ptr["end_offset"]==asm["count_offset"]==19360,"script table boundary")
    ck(sha(d[:ed])==ptr["count_and_rows_sha256"] and sha(d[4:ed])==ptr["rows_sha256"],"all pointer region hashes")
    rows=[list(struct.unpack_from("<iq",d,4+i*12)) for i in range(count)]
    a=w["script_references_archive"]
    packed=bz2.decompress(base64.b64decode(a["data"]))
    ck((len(packed),sha(packed))==(a["decoded_bytes"],a["decoded_sha256"]),"compressed witness identity")
    ck(json.loads(packed)==rows,"all 1613 ordered original pointer references equal archived text")
    ck(len(set(map(tuple,rows)))==ptr["unique_numeric_reference_pairs"]==1613,"numeric pair uniqueness")
    ck(rows[:6]==ptr["first_rows"] and rows[-6:]==ptr["last_rows"],"original boundary rows")
    ck(dict(sorted(Counter(str(r[0]) for r in rows).items()))==ptr["file_id_counts"],"original fileID distribution")
    pos=ed;n=struct.unpack_from("<I",d,pos)[0];pos+=4
    ck(n==asm["count"]==13 and pos==asm["first_row_offset"],"assembly count and alignment")
    names=[]
    for i,item in enumerate(asm["entries"]):
        st=pos;nb=struct.unpack_from("<I",d,pos)[0];pos+=4
        ck(nb==item["utf8_byte_length"] and nb<=len(d)-pos,"name length bounds")
        name=d[pos:pos+nb].decode("utf8");pos=(pos+nb+3)&~3
        ck((i,st,pos,name)==(item["index"],item["start_offset"],item["end_offset"],item["name"]),"source assembly row "+str(i))
        names.append(name)
    ck(names==asm["names"],"exact 13 authored assembly names")
    ck(pos==asm["end_offset"]==len(d) and sha(d[ed:pos])==asm["sha256"],"complete source bytes and assembly table digest")
    return {"fact":"FACT-0334","source_proof":"PASS","script_pointers":count,"assembly_names":n,"runtime_eligible":False}
if __name__=="__main__":
    a=argparse.ArgumentParser();a.add_argument("--globalgamemanagers",required=True);args=a.parse_args()
    try:
        w=json.loads(W.read_text())
        ck(w["dataset_id"]=="UNITY_GGM_MONOMANAGER_SCRIPTS_ASSEMBLIES_V1","witness identity")
        print(json.dumps(prove(args.globalgamemanagers,w),sort_keys=True))
        print("PROVE_GGM_MONO_MANAGER: PASS")
    except Exception as e:
        print("PROVE_GGM_MONO_MANAGER: FAIL",str(e))
        raise SystemExit(1)
