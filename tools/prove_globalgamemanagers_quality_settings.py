#!/usr/bin/env python3
"""FACT-0323 verify original Unity 5.6 QualitySettings class 47, one profile, exact 116 bytes."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/GGM-001/quality_settings_fantastic.summary.json"

def ck(ok,msg):
    if not ok: raise AssertionError(msg)

def verify(path,w):
    raw=Path(path).read_bytes()
    doc=w["original_file"]; q=w["quality_settings"]
    ck((len(raw),hashlib.sha256(raw).hexdigest())==(doc["size_bytes"],doc["sha256"]),"original raw SHA/length")
    hdr=struct.unpack_from(">IIIII",raw,0)
    ck(hdr==(1379,len(raw),17,4096,0),"original full Unity v17 header")
    p=20;stop=raw.index(bytes((0,)),p);engine=raw[p:stop].decode("ascii");p=stop+1
    platform=struct.unpack_from("<i",raw,p)[0];p+=4
    tree=raw[p];p+=1
    count=struct.unpack_from("<i",raw,p)[0];p+=4
    ck((engine,platform,tree,count)==("5.6.5p3",5,0,20),"native Unity type metadata")
    classes=[]
    for _ in range(count):
        c,strip,script=struct.unpack_from("<iBh",raw,p)
        ck(strip==0 and script==-1,"serialized type descriptor")
        classes.append(c);p+=23
    ck(classes[q["type_index"]]==47,"QualitySettings class identity")
    num=struct.unpack_from("<I",raw,p)[0];p+=4;p=(p+3)&~3
    ck(num==20,"object count")
    objs={}
    for _ in range(num):
        pid,start,size,idx=struct.unpack_from("<qIII",raw,p);p+=20
        ck(idx<len(classes) and 4096+start+size<=len(raw),"all object bounds")
        objs[pid]=(start,size,idx)
    start,size,idx=objs[q["path_id"]]
    ck((start,size,idx)==(q["data_relative_offset"],116,q["type_index"]),"original object descriptor")
    absolute=4096+start
    ck(absolute==q["absolute_offset"],"absolute offset")
    d=raw[absolute:absolute+size]
    ck(d.hex()==q["full_body_hex"],"exact original 116 source bytes")
    ck(hashlib.sha256(d).hexdigest()==q["sha256"],"object identity")
    fields=q["fields"];i=0
    def u32(name):
        nonlocal i
        value=struct.unpack_from("<i",d,i)[0];i+=4
        ck(value==fields[name],"field "+name)
    def f32(name):
        nonlocal i
        value=struct.unpack_from("<f",d,i)[0];i+=4
        ck(value==fields[name],"float field "+name)
    u32("m_CurrentQuality");u32("m_QualitySettings_count")
    n=struct.unpack_from("<I",d,i)[0];i+=4
    name=d[i:i+n].decode("utf-8");i=(i+n+3)&~3
    ck(name==fields["name"] and n==9,"single quality name")
    for name in ("pixelLightCount","shadows","shadowResolution","shadowProjection","shadowCascades"):
        u32(name)
    f32("shadowDistance");f32("shadowNearPlaneOffset")
    for hexval in [fields["shadowCascade2Split_bits"]]+fields["shadowCascade4Split_bits"]:
        ck(d[i:i+4].hex()==hexval,"original float bits");i+=4
    for name in ("blendWeights","textureQuality","anisotropicTextures","antiAliasing"):u32(name)
    for name in ("softParticles","softVegetation","realtimeReflectionProbes","billboardsFaceCameraPosition"):
        ck(d[i]==fields[name],"boolean "+name);i+=1
    u32("vSyncCount");f32("lodBias")
    for name in ("maximumLODLevel","particleRaycastBudget","asyncUploadTimeSlice","asyncUploadBufferSize","m_StrippedMaximumLODLevel"):
        u32(name)
    ck(i==len(d)==116,"exact end of original QualitySettings body")
    return {"fact":"FACT-0323","source_proof":"PASS","profile":name,"profiles":1,"antiAliasing":2,"runtime_eligible":False}

def main():
    a=argparse.ArgumentParser()
    a.add_argument("--globalgamemanagers",required=True)
    args=a.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"))
        ck(w["dataset_id"]=="UNITY_QUALITYSETTINGS_SINGLE_FANTASTIC_PROFILE_V1","witness id")
        print(json.dumps(verify(args.globalgamemanagers,w),sort_keys=True))
        print("PROVE_GLOBALGAMEMANAGERS_QUALITY_SETTINGS: PASS")
        return 0
    except Exception as exc:
        print("PROVE_GLOBALGAMEMANAGERS_QUALITY_SETTINGS: FAIL",exc)
        return 1
if __name__=="__main__":
    raise SystemExit(main())
