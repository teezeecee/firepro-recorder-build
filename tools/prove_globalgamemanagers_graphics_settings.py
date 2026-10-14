#!/usr/bin/env python3
"""FACT-0325 original complete 562-byte Unity GraphicsSettings source validator."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/GGM-001/graphics_settings_full_object.summary.json"
def ck(value,msg):
    if not value: raise AssertionError(msg)
def prove(path,w):
    data=Path(path).read_bytes();src=w["original_file"];obj=w["object"]
    ck((len(data),hashlib.sha256(data).hexdigest())==(src["bytes"],src["sha256"]),"raw original source identity")
    ck(struct.unpack_from(">IIIII",data,0)==(1379,len(data),17,4096,0),"original Unity serialized file header")
    p=20;end=data.index(bytes((0,)),p)
    ck(data[p:end]==b"5.6.5p3","original Unity version")
    p=end+1;platform=struct.unpack_from("<i",data,p)[0];p+=4;has_tree=data[p];p+=1
    count=struct.unpack_from("<I",data,p)[0];p+=4
    ck((platform,has_tree,count)==(5,0,20),"original metadata type count")
    classes=[]
    for _ in range(count):
        cl,removed,script=struct.unpack_from("<iBh",data,p)
        ck(removed==0 and script==-1,"original type metadata row")
        classes.append(cl);p+=23
    ck(classes[obj["type_index"]]==obj["class_id"]==30,"original GraphicsSettings class")
    objects=struct.unpack_from("<I",data,p)[0];p=(p+4+3)&~3
    ck(objects==20,"original object count")
    rows={}
    for _ in range(objects):
        path_id,start,size,typeidx=struct.unpack_from("<qIII",data,p);p+=20
        ck(typeidx<len(classes) and 4096+start+size<=len(data),"all object boundaries")
        rows[path_id]=(start,size,typeidx)
    start,size,idx=rows[obj["path_id"]]
    ck((start,size,idx)==(obj["relative_offset"],obj["bytes"],obj["type_index"]),"GraphicsSettings original object row")
    offset=4096+start
    ck(offset==obj["absolute_offset"],"original absolute offset")
    d=data[offset:offset+size]
    ck(hashlib.sha256(d).hexdigest()==obj["sha256"],"complete original object SHA256")
    pos=0
    for shader in w["builtin_shader_settings"]:
        ck(pos==shader["offset"],"builtin shader offset")
        val=list(struct.unpack_from("<iiq",d,pos));pos+=16
        ck(val==[shader["mode"],shader["file_id"],shader["path_id"]],"builtin shader numeric pointer")
    group=w["always_included_shaders"]
    ck(pos==group["count_field_offset"],"always-included source array offset")
    n=struct.unpack_from("<I",d,pos)[0];pos+=4
    ck(n==group["count"]==len(group["pointers"])==28,"original always-included shader count")
    for item in group["pointers"]:
        ck(pos==item["offset"],"always included pointer offset")
        ck(list(struct.unpack_from("<iq",d,pos))==[item["file_id"],item["path_id"]],"always-included numeric pointer")
        pos+=12
    pre=w["preloaded_shaders"]
    ck(pos==pre["count_field_offset"],"preloaded count offset")
    ck(struct.unpack_from("<I",d,pos)[0]==pre["count"]==0,"original zero preloaded variants")
    pos+=4
    for name in ("sprite_default_material","custom_render_pipeline"):
        o=w[name]
        ck(pos==o["offset"],name+" original offset")
        ck(list(struct.unpack_from("<iq",d,pos))==[o["file_id"],o["path_id"]],name+" numeric reference")
        pos+=12
    trans=w["transparency"]
    ck(pos==trans["mode_offset"],"transparency mode offset")
    ck(struct.unpack_from("<i",d,pos)[0]==trans["mode"],"transparency sort mode")
    pos+=4
    ck(pos==trans["axis_offset"],"transparency axis offset")
    ck(list(struct.unpack_from("<fff",d,pos))==trans["axis_float32"],"transparency axis")
    pos+=12
    for tier in w["tiers"]:
        ck(pos==tier["offset"],"graphics tier source offset")
        vals=list(struct.unpack_from("<iii",d,pos))+list(d[pos+12:pos+16])
        expected=[tier["renderingPath"],tier["hdrMode"],tier["realtimeGICPUUsage"],tier["useCascadedShadowMaps"],tier["enableLPPV"],tier["useHDR"],tier["padding"]]
        ck(vals==expected,"original graphics tier fields")
        pos+=16
    flags=w["lighting"]
    ck(pos==flags["offset"],"final lighting fields offset")
    ck(list(d[pos:pos+2])==[flags["m_LightsUseLinearIntensity"],flags["m_LightsUseColorTemperature"]],"final lighting fields")
    pos+=2
    ck(pos==size==562,"no missing GraphicsSettings source fields or trailing data")
    return {"fact":"FACT-0325","source_proof":"PASS","shader_slots":8,"always_included_shaders":28,"preloaded_shaders":0,"tiers":3,"runtime_eligible":False}
def main():
    a=argparse.ArgumentParser()
    a.add_argument("--globalgamemanagers",required=True)
    args=a.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"))
        ck(w["dataset_id"]=="UNITY_GRAPHICSSETTINGS_SHADER_POINTERS_TIERS_SOURCE_V1","witness identity")
        print(json.dumps(prove(args.globalgamemanagers,w),sort_keys=True))
        print("PROVE_GLOBALGAMEMANAGERS_GRAPHICS_SETTINGS: PASS")
        return 0
    except Exception as exc:
        print("PROVE_GLOBALGAMEMANAGERS_GRAPHICS_SETTINGS: FAIL",str(exc))
        return 1
if __name__=="__main__":raise SystemExit(main())
