#!/usr/bin/env python3
"""FACT-0322 read-only original Unity globalgamemanagers BuildSettings API-order validator."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
WITNESS=ROOT/"canonical/witnesses/GGM-001/buildsettings_graphics_apis.summary.json"

def ck(ok,message):
    if not ok:
        raise AssertionError(message)

def verify(path,w):
    raw=Path(path).read_bytes()
    f=w["file"]; bs=w["build_settings"]
    ck((len(raw),hashlib.sha256(raw).hexdigest())==(f["size_bytes"],f["sha256"]),"exact raw file identity")
    metadata_size,file_size,version,data_offset,reserved=struct.unpack_from(">IIIII",raw,0)
    ck((metadata_size,file_size,version,data_offset,reserved)==(1379,len(raw),17,4096,0),"original v17 file header")
    o=20; stop=raw.index(b"\\x00",o)
    unity_version=raw[o:stop].decode("ascii")
    o=stop+1
    platform=struct.unpack_from("<i",raw,o)[0];o+=4
    has_tree=raw[o];o+=1
    types=struct.unpack_from("<i",raw,o)[0];o+=4
    ck((unity_version,platform,has_tree,types)==("5.6.5p3",5,0,20),"metadata version/platform/type array")
    classes=[]
    for _ in range(types):
        cid=struct.unpack_from("<i",raw,o)[0]
        stripped=raw[o+4]
        script_idx=struct.unpack_from("<h",raw,o+5)[0]
        ck(stripped==0 and script_idx==-1,"original class metadata")
        classes.append(cid);o+=23
    ck((o,classes[10])==(0x1F1,141),"BuildSettings ClassID")
    objects=struct.unpack_from("<I",raw,o)[0];o+=4
    o=(o+3)&~3
    ck(objects==20,"ObjectInfo count")
    by_path={}
    for _ in range(objects):
        pathid,start,size,ix=struct.unpack_from("<qIII",raw,o);o+=20
        ck(ix<len(classes) and data_offset+start+size<=len(raw),"ObjectInfo bounds")
        by_path[pathid]=(start,size,ix)
    start,size,ix=by_path[11]
    ck((start,size,ix,classes[ix])==(62944,55660,10,141),"original BuildSettings descriptor")
    d=raw[data_offset+start:data_offset+start+size]
    ck(hashlib.sha256(d).hexdigest()==bs["sha256"],"BuildSettings body hash")
    p=0
    samples=[]
    for expected in (bs["scenes"],len(bs["preloaded_plugins"]),bs["enabled_vr_devices"],bs["build_tags"]):
        count=struct.unpack_from("<I",d,p)[0];p+=4
        ck(count==expected,"BuildSettings string-vector cardinality")
        a=[]
        for _ in range(count):
            n=struct.unpack_from("<I",d,p)[0];p+=4
            ck(0<=n<=len(d)-p,"bounded vector string")
            a.append(d[p:p+n].decode("utf-8"));p+=n;p=(p+3)&~3
        samples.append(a)
    ck(samples[0][0]==bs["first_scene"] and samples[0][-1]==bs["last_scene"],"first/last scene identity")
    ck(samples[1]==bs["preloaded_plugins"],"preloaded plugin names")
    ck(p==3344,"array boundary before build GUID")
    p+=16+16
    def string():
        nonlocal p
        n=struct.unpack_from("<I",d,p)[0];p+=4
        ck(0<=n<=len(d)-p,"bounded metadata string")
        s=d[p:p+n].decode("utf-8");p=(p+n+3)&~3
        return s
    ck(string()==bs["version"],"original build version")
    auth=string()
    ck(len(auth)==80 and p==3472,"aligned original auth token slot")
    for key in ("runtime_class_hashes","script_hashes"):
        item=bs[key]
        ck(p==item["offset"],"hash-map source offset")
        count=struct.unpack_from("<I",d,p)[0]
        ck(count==item["count"],"hash-map source count")
        p+=4+count*item["record_bytes"]
    field=bs["graphics_api_field"]
    ck(p==field["offset"],"m_GraphicsAPIs offset after both complete maps")
    n=struct.unpack_from("<I",d,p)[0]
    ck(n==field["count"],"graphics API array count")
    apis=list(struct.unpack_from("<"+"i"*n,d,p+4))
    ck(apis==field["ordered_numeric_values"],"source ordered API values")
    ck(d[p:p+4+4*n].hex()==field["field_hex"],"exact raw API field")
    ck(p+4+4*n==size,"graphics API field ends exactly at BuildSettings object boundary")
    return {"source_proof":"PASS","fact":"FACT-0322","unity_version":unity_version,"graphics_api_values":apis,"runtime_eligible":False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--globalgamemanagers",required=True)
    args=p.parse_args()
    try:
        result=verify(args.globalgamemanagers,json.loads(WITNESS.read_text(encoding="utf-8")))
        print(json.dumps(result,sort_keys=True))
        print("PROVE_GLOBALGAMEMANAGERS_BUILDSETTINGS_APIS: PASS")
        return 0
    except Exception as exc:
        print("PROVE_GLOBALGAMEMANAGERS_BUILDSETTINGS_APIS: FAIL",exc)
        return 1

if __name__=="__main__":
    raise SystemExit(main())
