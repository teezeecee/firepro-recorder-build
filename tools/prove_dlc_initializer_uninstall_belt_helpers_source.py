#!/usr/bin/env python3
"""FACT-0320 original DLL validator for two retail helper bodies and EH sections."""
import argparse, hashlib, json, struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
W=Path(__file__).resolve().parents[1]/"canonical/witnesses/CAP-R6-001/dlc_initializer_uninstall_belt_helpers_source.summary.json"
def ck(condition,label):
    if not condition: raise AssertionError(label)
def verify(dll,w):
    pe=Path(dll).read_bytes()
    ck((len(pe),hashlib.sha256(pe).hexdigest())==(w["dll"]["size_bytes"],w["dll"]["sha256"]),"retail DLL identity")
    ss,q=p.secs(pe)
    streams,hs,rows,pos=p.mdstreams(pe,ss,q)
    s,b,ix,z,o=p.tables(pe,streams,hs,rows,pos)
    sb=streams["#Strings"][0];bb=streams["#Blob"][0]
    fm,owners=p.owner_maps(pe,rows,s,ix,z,o,sb)
    bodies=[]
    for m in w["methods"]:
        v=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(m["token"],16))
        il=v[9]
        ck((v[0],v[1],v[4],v[5],v[7],pe[p.off(ss,v[1]):v[8]].hex())==(m["row"],int(m["rva"],16),m["name"],m["signature"],(m["owner"],m["namespace"]),m["header"]),"MethodDef header "+m["token"])
        ck((len(il),il.hex(),hashlib.sha256(il).hexdigest())==(m["body_length"],m["body_hex"],m["body_sha256"]),"full original IL "+m["token"])
        ck(il[0]==int(m["first_opcode"],16) and il[1]==0x0a and m["raw_dlc_value"] in (2,5),"original first constant")
        ehstart=(v[8]+len(il)+3)&~3
        eh=pe[ehstart:ehstart+16]
        ck(eh.hex()==m["eh_section_hex"],"original exception section bytes "+m["token"])
        e=w["eh"]
        ck((eh[0],eh[1],struct.unpack_from("<H",eh,4)[0],struct.unpack_from("<H",eh,6)[0],eh[8],struct.unpack_from("<H",eh,9)[0],eh[11],struct.unpack_from("<I",eh,12)[0])==(e["kind"],e["size_bytes"],e["flags"],e["try_start"],e["try_length"],e["handler_start"],e["handler_length"],e["class_token_or_filter"]),"finally clause layout")
        for f in w["fields"]:
            ck(p.field(pe,s,b,z,o,sb,bb,fm,int(f["token"],16))==(f["row"],(f["owner"],f["namespace"]),f["name"],f["signature"]),"FieldDef metadata "+f["token"])
            for site in f["sites"]:
                ck(il[site:site+5]==bytes([int(f["opcode"],16)])+struct.pack("<I",int(f["token"],16)),"FieldDef site "+f["token"])
        for c in w["direct_callees"]:
            cv=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(c["token"],16))
            ck((cv[0],cv[1],cv[4],cv[5],cv[7],len(cv[9]),hashlib.sha256(cv[9]).hexdigest())==(c["row"],int(c["rva"],16),c["name"],c["signature"],(c["owner"],c["namespace"]),c["body_length"],c["body_sha256"]),"callee metadata and full body "+c["token"])
            for site in c["sites"]:
                ck(il[site:site+5]==bytes([int(c["opcode"],16)])+struct.pack("<I",int(c["token"],16)),"direct call site "+c["token"])
        for r in w["unresolved_numeric_references"]:
            j=r["site"]; op=int(r["opcode"],16); prefix=b"\xfe\x16" if op==0xfe16 else bytes([op])
            ck(il[j:j+len(prefix)+4]==prefix+struct.pack("<I",int(r["token"],16)),"numeric only external token "+r["token"])
        for bsite in w["branches"]:
            j=bsite["site"];delta=struct.unpack_from("<i",il,j+1)[0]
            ck((il[j],delta,j+5+delta)==(int(bsite["opcode"],16),bsite["delta"],bsite["target"]),"branch source target "+str(j))
        ck(il[117:119]==b"\xdc\x2a" and il[25:27]==b"\x12\x03" and il[68:71]==b"\x11\x04\x06","loop/handler source marks")
        bodies.append(il)
    ck(len(bodies)==2 and bodies[0][1:]==bodies[1][1:] and bodies[0][0]==0x18 and bodies[1][0]==0x1b,"119-byte twin method comparison")
    return {"fact":"FACT-0320","original_source":"PASS","source_methods":2,"method_body_length":119,"finally_sections":2,"runtime_eligible":False}
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);a=ap.parse_args()
    try:
        w=json.loads(W.read_text());ck(w["dataset_id"]=="DLL_DLC_INITIALIZER_UNINSTALL_BELT_HELPERS_SOURCE_V1" and w["source_ids"]==["DLL-001"],"witness identity")
        print(json.dumps(verify(a.dll,w),sort_keys=True));print("PROVE_DLC_INITIALIZER_UNINSTALL_BELT_HELPERS_SOURCE: PASS");return 0
    except Exception as e:
        print("PROVE_DLC_INITIALIZER_UNINSTALL_BELT_HELPERS_SOURCE: FAIL",str(e));return 1
if __name__=="__main__":raise SystemExit(main())
